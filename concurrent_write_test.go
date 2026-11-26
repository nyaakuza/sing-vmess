package vmess

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	concurrentWriters   = 8
	writesPerWriter     = 64
	concurrentRecordLen = 100
)

type recordingHandler struct {
	stream  chan []byte
	packets chan []byte
}

func (h *recordingHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	data, _ := io.ReadAll(io.LimitReader(conn, concurrentWriters*writesPerWriter*concurrentRecordLen))
	h.stream <- data
	conn.Close()
}

func (h *recordingHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	for i := 0; i < concurrentWriters*writesPerWriter; i++ {
		buffer := buf.New()
		_, err := conn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			break
		}
		h.packets <- append([]byte(nil), buffer.Bytes()...)
		buffer.Release()
	}
	close(h.packets)
	conn.Close()
}

func concurrentWriteServer(t *testing.T) (*recordingHandler, net.Conn) {
	t.Helper()
	const userId = "b831381d-6324-4d53-ad4f-8cda48b30811"
	handler := &recordingHandler{stream: make(chan []byte, 1), packets: make(chan []byte, concurrentWriters*writesPerWriter)}
	service := NewService[int](handler)
	if err := service.UpdateUsers([]int{0}, []string{userId}, []int{0}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		service.NewConnection(context.Background(), conn, M.Socksaddr{}, nil)
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return handler, conn
}

func concurrentRecord(writer, index int) []byte {
	record := bytes.Repeat([]byte{byte(writer)}, concurrentRecordLen)
	record[1] = byte(index)
	return record
}

func writeConcurrently(t *testing.T, write func(record []byte) error) {
	t.Helper()
	var group sync.WaitGroup
	for writer := 0; writer < concurrentWriters; writer++ {
		group.Add(1)
		go func(writer int) {
			defer group.Done()
			for index := 0; index < writesPerWriter; index++ {
				if err := write(concurrentRecord(writer, index)); err != nil {
					t.Error(err)
					return
				}
			}
		}(writer)
	}
	group.Wait()
}

func checkRecord(t *testing.T, record []byte) {
	t.Helper()
	if len(record) != concurrentRecordLen || !bytes.Equal(record, concurrentRecord(int(record[0]), int(record[1]))) {
		t.Fatalf("corrupted record %x", record)
	}
}

func newConcurrentTestClient(t *testing.T) *Client {
	t.Helper()
	client, err := NewClient("b831381d-6324-4d53-ad4f-8cda48b30811", "aes-128-gcm", 0, ClientWithGlobalPadding(), ClientWithAuthenticatedLength())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// Writers on separate goroutines share one connection's cipher, masking and padding state (a WireGuard
// detour sends from one goroutine per peer), so every write must stay one intact record.
func TestClientConnConcurrentWrites(t *testing.T) {
	handler, upstream := concurrentWriteServer(t)
	conn := newConcurrentTestClient(t).DialEarlyConn(upstream, M.ParseSocksaddr("example.com:80"))
	writeConcurrently(t, func(record []byte) error {
		_, err := conn.Write(record)
		return err
	})
	select {
	case data := <-handler.stream:
		if len(data) != concurrentWriters*writesPerWriter*concurrentRecordLen {
			t.Fatalf("received %d bytes", len(data))
		}
		for len(data) > 0 {
			checkRecord(t, data[:concurrentRecordLen])
			data = data[concurrentRecordLen:]
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stream not received")
	}
}

func receivePackets(t *testing.T, handler *recordingHandler) {
	t.Helper()
	received := 0
	timeout := time.After(10 * time.Second)
	for received < concurrentWriters*writesPerWriter {
		select {
		case packet, ok := <-handler.packets:
			if !ok {
				t.Fatalf("received %d packets", received)
			}
			checkRecord(t, packet)
			received++
		case <-timeout:
			t.Fatalf("received %d packets", received)
		}
	}
}

func TestClientPacketConnConcurrentWrites(t *testing.T) {
	handler, upstream := concurrentWriteServer(t)
	conn := newConcurrentTestClient(t).DialEarlyPacketConn(upstream, M.ParseSocksaddr("1.1.1.1:53"))
	destination := M.ParseSocksaddr("1.1.1.1:53")
	writeConcurrently(t, func(record []byte) error {
		buffer := buf.NewSize(256)
		buffer.Resize(64, 0)
		buffer.Write(record)
		return conn.WritePacket(buffer, destination)
	})
	receivePackets(t, handler)
}

func TestXUDPConnConcurrentWrites(t *testing.T) {
	handler, upstream := concurrentWriteServer(t)
	conn := newConcurrentTestClient(t).DialEarlyXUDPPacketConn(upstream, M.ParseSocksaddr("1.1.1.1:53"))
	writeConcurrently(t, func(record []byte) error {
		_, err := conn.(net.PacketConn).WriteTo(record, M.ParseSocksaddr("1.1.1.1:53").UDPAddr())
		return err
	})
	receivePackets(t, handler)
}

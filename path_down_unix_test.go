//go:build !windows

package quic

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/synctest"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/sys/unix"
)

var unreachable error = unix.ENETUNREACH

func TestSendQueuePathDownWithinGrace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		c := NewMockSendConn(mockCtrl)
		q := newSendQueue(c)

		c.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).Return(unreachable).Times(2)
		q.Send(getPacketWithContents([]byte("foobar")), 6, protocol.ECNNon)

		errChan := make(chan error, 1)
		go func() { errChan <- q.Run() }()

		synctest.Wait()

		select {
		case err := <-errChan:
			t.Fatalf("Run returned %v while the path was down for less than the grace", err)
		default:
		}

		time.Sleep(pathDownGrace)
		c.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).Return(unreachable).Times(2)
		q.Send(getPacketWithContents([]byte("foobar")), 6, protocol.ECNNon)

		synctest.Wait()

		select {
		case err := <-errChan:
			require.ErrorIs(t, err, unreachable)
		default:
			t.Fatal("Run should have returned once the grace ran out")
		}
	})
}

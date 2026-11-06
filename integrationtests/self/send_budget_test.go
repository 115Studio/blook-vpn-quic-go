package self_test

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"

	"github.com/stretchr/testify/require"
)

// A client with Chrome's fixed windows (6 MB per stream, 15 MB per connection) stops
// reading; the server must stop at its budget, not at the client's window, and the
// transfer must still complete once the client reads again.
func TestSendBudget(t *testing.T) {
	const (
		streamWindow = 6 << 20
		connWindow   = 15 << 20
		chunk        = 32 << 10
		total        = 48 << 20
	)

	run := func(t *testing.T, connBudget, streamBudget int64) (heldWhileStalled int64) {
		ln, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer ln.Close()

		ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(10*time.Second))
		defer cancel()
		client, err := quic.Dial(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(), getQuicConfig(&quic.Config{
			InitialStreamReceiveWindow:     streamWindow,
			MaxStreamReceiveWindow:         streamWindow,
			InitialConnectionReceiveWindow: connWindow,
			MaxConnectionReceiveWindow:     connWindow,
			WindowUpdateThreshold:          1.0 / 16,
		}))
		require.NoError(t, err)
		defer client.CloseWithError(0, "")

		var written atomic.Int64
		serverErr := make(chan error, 1)
		go func() {
			conn, err := ln.Accept(ctx)
			if err != nil {
				serverErr <- err
				return
			}
			str, err := conn.AcceptStream(ctx)
			if err != nil {
				serverErr <- err
				return
			}
			conn.SetSendBudget(connBudget, streamBudget)
			data := GeneratePRData(chunk)
			for written.Load() < total {
				n, err := str.Write(data)
				written.Add(int64(n))
				if err != nil {
					serverErr <- err
					return
				}
			}
			serverErr <- str.Close()
		}()

		str, err := client.OpenStream()
		require.NoError(t, err)
		_, err = str.Write([]byte{0})
		require.NoError(t, err)

		time.Sleep(scaleDuration(500 * time.Millisecond))
		heldWhileStalled = written.Load()

		n, err := io.Copy(io.Discard, str)
		require.NoError(t, err)
		require.EqualValues(t, total, n)
		require.NoError(t, <-serverErr)
		return heldWhileStalled
	}

	t.Run("budget", func(t *testing.T) {
		held := run(t, 6<<20, 3<<20)
		t.Logf("held at the stalled client: %d KB", held>>10)
		// The last Write may be in progress, still blocked, when the client is stalled.
		require.LessOrEqual(t, held, int64(3<<20+chunk))
		require.Greater(t, held, int64(2<<20))
	})

	t.Run("no budget", func(t *testing.T) {
		held := run(t, 0, 0)
		t.Logf("held at the stalled client: %d KB", held>>10)
		require.Greater(t, held, int64(5<<20), "without a budget the client's window binds")
	})
}

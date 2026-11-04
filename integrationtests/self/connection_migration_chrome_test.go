package self_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/apernet/quic-go"

	"github.com/stretchr/testify/require"
)

// A Chrome-parroting client sends no active_connection_id_limit, so the server
// assumes 2 and hands it a single spare connection ID, which the client moves onto
// right after the handshake. The server must replace the handshake ID the client then
// retires, or the client has nothing to probe a new path with. A phone flips between
// Wi-Fi and cellular several times, so the connection moves four times here.
func TestConnectionMigrationChromeParrot(t *testing.T) {
	serverConf, clientConf := chromeCompatibleTLSConfigs(t)
	ln, err := quic.Listen(newUDPConnLocalhost(t), serverConf, getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	newTransport := func() *quic.Transport {
		tr := &quic.Transport{
			Conn:                  newUDPConnLocalhost(t),
			ConnectionIDGenerator: quic.ZeroLengthConnectionIDGenerator{},
		}
		t.Cleanup(func() { tr.Close() })
		return tr
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := newTransport().Dial(ctx, ln.Addr(), clientConf, getQuicConfig(&quic.Config{ChromeParrot: true}))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	sconn, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer sconn.CloseWithError(0, "")

	echo := func(t *testing.T) {
		t.Helper()
		str, err := conn.OpenStream()
		require.NoError(t, err)
		_, err = str.Write(PRData)
		require.NoError(t, err)
		require.NoError(t, str.Close())

		sstr, err := sconn.AcceptStream(ctx)
		require.NoError(t, err)
		data, err := io.ReadAll(sstr)
		require.NoError(t, err)
		require.Equal(t, PRData, data)
	}
	echo(t)

	for i := range 4 {
		time.Sleep(20 * time.Millisecond) // let NEW_CONNECTION_ID arrive
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		path, err := conn.AddPath(newTransport())
		require.NoError(t, err)
		require.NoError(t, path.Probe(probeCtx), "move %d", i+1)
		cancel()
		require.NoError(t, path.Switch())
		echo(t)
	}
}

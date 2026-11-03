package self_test

import (
	"context"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

var initialDestConnID = protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})

func TestInitialDestinationConnectionIDOnTheWire(t *testing.T) {
	server := newUDPConnLocalhost(t)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go quic.DialEarly(ctx, newUDPConnLocalhost(t), server.LocalAddr(), getTLSClientConfig(), getQuicConfig(&quic.Config{
		InitialDestinationConnectionID: func() (quic.ConnectionID, error) { return initialDestConnID, nil },
	}))

	b := make([]byte, 2000)
	server.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := server.ReadFrom(b)
	require.NoError(t, err)
	_, dest, src, err := wire.ParseArbitraryLenConnectionIDs(b[:n])
	require.NoError(t, err)
	require.Equal(t, initialDestConnID.Bytes(), dest.Bytes())
	require.Zero(t, src.Len(), "DialEarly keeps a zero-length source connection ID")
}

func TestInitialDestinationConnectionIDHandshake(t *testing.T) {
	ln, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialEarly(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(), getQuicConfig(&quic.Config{
		InitialDestinationConnectionID: func() (quic.ConnectionID, error) { return initialDestConnID, nil },
	}))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	sconn, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer sconn.CloseWithError(0, "")
}

func TestInitialDestinationConnectionIDLength(t *testing.T) {
	for _, l := range []int{0, 7} {
		_, err := quic.DialEarly(context.Background(), newUDPConnLocalhost(t), newUDPConnLocalhost(t).LocalAddr(), getTLSClientConfig(), getQuicConfig(&quic.Config{
			InitialDestinationConnectionID: func() (quic.ConnectionID, error) {
				return protocol.ParseConnectionID(make([]byte, l)), nil
			},
		}))
		require.ErrorContains(t, err, "initial destination connection ID")
	}
}

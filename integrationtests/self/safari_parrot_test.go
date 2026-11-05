package self_test

import (
	"context"
	"crypto/tls"
	"io"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/internal/handshake"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/wire"
	"github.com/apernet/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestSafariParrotHandshake(t *testing.T) {
	serverConf, clientConf := chromeCompatibleTLSConfigs(t)

	server, err := quic.Listen(newUDPConnLocalhost(t), serverConf, getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientConn, err := quic.Dial(ctx, newUDPConnLocalhost(t), server.Addr(),
		clientConf, getQuicConfig(&quic.Config{Parrot: quic.ParrotSafari}))
	require.NoError(t, err)
	defer clientConn.CloseWithError(0, "")

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer serverConn.CloseWithError(0, "")

	state := clientConn.ConnectionState().TLS
	require.Equal(t, uint16(tls.VersionTLS13), state.Version)
	require.True(t, state.HandshakeComplete)

	// Safari takes no server-initiated bidi streams, so the server sends on a uni one,
	// more than the 2 MiB a stream starts at.
	const payloadLen = 3 << 20
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = PRDataLong[i%len(PRDataLong)]
	}
	go func() {
		str, err := serverConn.OpenUniStreamSync(ctx)
		if err != nil {
			return
		}
		defer str.Close()
		str.Write(payload)
	}()

	str, err := clientConn.AcceptUniStream(ctx)
	require.NoError(t, err)
	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, payload, data)
}

// Safari's first flight, as captured on iOS 26.6.2: two 1200-byte Initials, an 8-byte
// destination id, an empty source id, packet numbers 0 and 1, and in each one CRYPTO
// frame of at most 999 bytes followed by padding.
func TestSafariParrotFirstFlight(t *testing.T) {
	server := newUDPConnLocalhost(t)

	_, clientConf := chromeCompatibleTLSConfigs(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go quic.DialEarly(ctx, newUDPConnLocalhost(t), server.LocalAddr(), clientConf,
		getQuicConfig(&quic.Config{Parrot: quic.ParrotSafari}))

	var offset protocol.ByteCount
	for pn := range 2 {
		b := make([]byte, 2000)
		server.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := server.ReadFrom(b)
		require.NoError(t, err)
		require.Equal(t, 1200, n, "datagram %d", pn)

		hdr, _, _, err := wire.ParsePacket(b[:n])
		require.NoError(t, err)
		require.Equal(t, protocol.PacketTypeInitial, hdr.Type)
		require.Equal(t, 8, hdr.DestConnectionID.Len())
		require.Zero(t, hdr.SrcConnectionID.Len())

		_, opener := handshake.NewInitialAEAD(hdr.DestConnectionID, protocol.PerspectiveServer, protocol.Version1)
		ehdr, frames := openInitial(t, opener, b[:n], hdr)
		require.EqualValues(t, pn, ehdr.PacketNumber)
		require.Equal(t, protocol.PacketNumberLen1, ehdr.PacketNumberLen)

		cryptoOffset, cryptoData, rest := parseCryptoFrame(t, frames)
		require.Equal(t, offset, cryptoOffset)
		require.LessOrEqual(t, len(cryptoData), 999)
		if pn == 0 {
			require.Len(t, cryptoData, 999)
		}
		offset += protocol.ByteCount(len(cryptoData))
		require.Equal(t, make([]byte, len(rest)), rest, "only padding follows the CRYPTO frame")
	}
}

// openInitial removes header protection from and decrypts a client Initial,
// returning its header and plaintext payload.
func openInitial(t *testing.T, opener handshake.LongHeaderOpener, data []byte, hdr *wire.Header) (*wire.ExtendedHeader, []byte) {
	t.Helper()
	hdrLen := hdr.ParsedLen()
	sample := data[hdrLen+4 : hdrLen+4+16]
	var orig [4]byte
	copy(orig[:], data[hdrLen:hdrLen+4])
	opener.DecryptHeader(sample, &data[0], data[hdrLen:hdrLen+4])

	ehdr, err := hdr.ParseExtended(data)
	require.NoError(t, err)
	extHdrLen := ehdr.ParsedLen()
	// The mask covers four bytes; past the packet number they are payload.
	copy(data[extHdrLen:hdrLen+4], orig[ehdr.PacketNumberLen:])
	payload, err := opener.Open(nil, data[extHdrLen:hdrLen+protocol.ByteCount(hdr.Length)], ehdr.PacketNumber, data[:extHdrLen])
	require.NoError(t, err)
	return ehdr, payload
}

// parseCryptoFrame requires payload to start with a CRYPTO frame and returns its
// offset, its data and what follows it.
func parseCryptoFrame(t *testing.T, payload []byte) (protocol.ByteCount, []byte, []byte) {
	t.Helper()
	typ, n, err := quicvarint.Parse(payload)
	require.NoError(t, err)
	require.EqualValues(t, 0x06, typ, "the first frame is CRYPTO")
	payload = payload[n:]
	off, n, err := quicvarint.Parse(payload)
	require.NoError(t, err)
	payload = payload[n:]
	l, n, err := quicvarint.Parse(payload)
	require.NoError(t, err)
	payload = payload[n:]
	return protocol.ByteCount(off), payload[:l], payload[l:]
}

// Safari advertises an active_connection_id_limit of 64; the client stores what the
// server issues against it, and moves to new paths as a phone flips networks.
func TestConnectionMigrationSafariParrot(t *testing.T) {
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

	conn, err := newTransport().Dial(ctx, ln.Addr(), clientConf, getQuicConfig(&quic.Config{Parrot: quic.ParrotSafari}))
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

package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/apernet/quic-go/internal/protocol"
)

// make it possible to mock connection ID for initial generation in the tests
var generateConnectionIDForInitial = protocol.GenerateConnectionIDForInitial

// initialDestConnID is the destination connection ID of a client's first Initial: the
// application's when Config.InitialDestinationConnectionID is set, else a random one —
// a fixed 8 bytes under a parrot (Chrome and Safari both send 8), quic-go's random
// 8..20 otherwise.
func initialDestConnID(conf *Config) (protocol.ConnectionID, error) {
	if conf.InitialDestinationConnectionID == nil {
		if conf.Parrot != ParrotNone {
			return protocol.GenerateChromeConnectionIDForInitial()
		}
		return generateConnectionIDForInitial()
	}
	id, err := conf.InitialDestinationConnectionID()
	if err != nil {
		return protocol.ConnectionID{}, err
	}
	if id.Len() < protocol.MinConnectionIDLenInitial || id.Len() > protocol.MaxConnIDLen {
		return protocol.ConnectionID{}, fmt.Errorf("quic: initial destination connection ID is %d bytes, want %d..%d", id.Len(), protocol.MinConnectionIDLenInitial, protocol.MaxConnIDLen)
	}
	return id, nil
}

// DialAddr establishes a new QUIC connection to a server.
// It resolves the address, and then creates a new UDP connection to dial the QUIC server.
// When the QUIC connection is closed, this UDP connection is closed.
// See [Dial] for more details.
func DialAddr(ctx context.Context, addr string, tlsConf *tls.Config, conf *Config) (*Conn, error) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	tr, err := setupTransport(udpConn, tlsConf, true)
	if err != nil {
		return nil, err
	}
	conn, err := tr.dial(ctx, udpAddr, addr, tlsConf, conf, false)
	if err != nil {
		tr.Close()
		return nil, err
	}
	return conn, nil
}

// DialAddrEarly establishes a new 0-RTT QUIC connection to a server.
// See [DialAddr] for more details.
func DialAddrEarly(ctx context.Context, addr string, tlsConf *tls.Config, conf *Config) (*Conn, error) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	tr, err := setupTransport(udpConn, tlsConf, true)
	if err != nil {
		return nil, err
	}
	conn, err := tr.dial(ctx, udpAddr, addr, tlsConf, conf, true)
	if err != nil {
		tr.Close()
		return nil, err
	}
	return conn, nil
}

// DialEarly establishes a new 0-RTT QUIC connection to a server using a net.PacketConn.
// See [Dial] for more details.
func DialEarly(ctx context.Context, c net.PacketConn, addr net.Addr, tlsConf *tls.Config, conf *Config) (*Conn, error) {
	dl, err := setupTransport(c, tlsConf, false)
	if err != nil {
		return nil, err
	}
	conn, err := dl.DialEarly(ctx, addr, tlsConf, conf)
	if err != nil {
		dl.Close()
		return nil, err
	}
	return conn, nil
}

// Dial establishes a new QUIC connection to a server using a net.PacketConn.
// If the PacketConn satisfies the [OOBCapablePacketConn] interface (as a [net.UDPConn] does),
// ECN and packet info support will be enabled. In this case, ReadMsgUDP and WriteMsgUDP
// will be used instead of ReadFrom and WriteTo to read/write packets.
// The [tls.Config] must define an application protocol (using tls.Config.NextProtos).
//
// This is a convenience function. More advanced use cases should instantiate a [Transport],
// which offers configuration options for a more fine-grained control of the connection establishment,
// including reusing the underlying UDP socket for multiple QUIC connections.
func Dial(ctx context.Context, c net.PacketConn, addr net.Addr, tlsConf *tls.Config, conf *Config) (*Conn, error) {
	dl, err := setupTransport(c, tlsConf, false)
	if err != nil {
		return nil, err
	}
	conn, err := dl.Dial(ctx, addr, tlsConf, conf)
	if err != nil {
		dl.Close()
		return nil, err
	}
	return conn, nil
}

func setupTransport(c net.PacketConn, tlsConf *tls.Config, createdPacketConn bool) (*Transport, error) {
	if tlsConf == nil {
		return nil, errors.New("quic: tls.Config not set")
	}
	return &Transport{
		Conn:        c,
		createdConn: createdPacketConn,
		isSingleUse: true,
	}, nil
}

package quic

import (
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/wire"
)

// Values a Safari-parroting client pins, as Safari on iOS 26.6.2 sends them. Apple's
// QUIC stack advertises no max_idle_timeout, max_udp_payload_size,
// initial_max_streams_bidi or max_datagram_frame_size, so the local idle timeout is
// the caller's and the client takes no server-initiated bidirectional streams.
const (
	safariInitialMaxStreamData  = 2 << 20  // 2 MiB
	safariInitialMaxData        = 16 << 20 // 16 MiB
	safariMaxIncomingUniStreams = 8
	safariActiveConnIDLimit     = 64
	// UDP payload size of the Initial datagrams.
	safariInitialPacketSize = 1200
	// The CRYPTO data an Initial carries: Safari cuts its ClientHello at 999 bytes,
	// one CRYPTO frame per Initial, the rest of the datagram PADDING.
	safariInitialCryptoLen = 999
)

// safariParrotTransportParameters adjusts the transport parameters advertised by a
// Safari-parroting client. The omitted ones are reset to their protocol defaults, so
// what we imply by omission matches how we actually behave.
func safariParrotTransportParameters(params *wire.TransportParameters) {
	params.MaxUDPPayloadSize = protocol.MaxPacketBufferSize
	params.MaxDatagramFrameSize = protocol.InvalidByteCount
	params.MaxAckDelay = protocol.DefaultMaxAckDelay
	params.AckDelayExponent = protocol.DefaultAckDelayExponent
	params.DisableActiveMigration = false
	params.MaxBidiStreamNum = 0
	params.ActiveConnectionIDLimit = safariActiveConnIDLimit
	params.SafariFingerprint = true
}

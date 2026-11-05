package wire

import (
	"github.com/apernet/quic-go/quicvarint"
)

// safariParameterOrder is the set Safari on iOS 26.6.2 sends, in ascending order. It
// sends no max_idle_timeout, max_udp_payload_size, initial_max_streams_bidi, GREASE or
// version_information.
var safariParameterOrder = [...]transportParameterID{
	initialMaxDataParameterID,
	initialMaxStreamDataBidiLocalParameterID,
	initialMaxStreamDataBidiRemoteParameterID,
	initialMaxStreamDataUniParameterID,
	initialMaxStreamsUniParameterID,
	activeConnectionIDLimitParameterID,
	initialSourceConnectionIDParameterID,
}

// safariRotationWeights is how often Safari starts the rotated list at each
// safariParameterOrder position: counts out of 42 ClientHellos captured from Safari on
// iOS 26.6.2. The skew is Apple's (Safari 27.2 on macOS shows the same lean towards
// 0x0e and 0x04), so a uniform start would itself be a tell.
var safariRotationWeights = [len(safariParameterOrder)]uint64{14, 1, 5, 4, 3, 14, 1}

// marshalSafari encodes the client's transport parameters the way Apple's QUIC stack
// does: the set above in ascending order, rotated to a start drawn from
// safariRotationWeights. Values come from p; pinning them is Config.Parrot's job.
func (p *TransportParameters) marshalSafari() []byte {
	start := safariRotationStart(randUint64n)
	out := make([]byte, 0, 64)
	for i := range safariParameterOrder {
		out = p.appendSafariParameter(out, safariParameterOrder[(start+i)%len(safariParameterOrder)])
	}
	return out
}

func safariRotationStart(rand func(uint64) uint64) int {
	var total uint64
	for _, w := range safariRotationWeights {
		total += w
	}
	r := rand(total)
	for i, w := range safariRotationWeights {
		if r < w {
			return i
		}
		r -= w
	}
	return 0
}

func (p *TransportParameters) appendSafariParameter(b []byte, id transportParameterID) []byte {
	switch id {
	case initialMaxDataParameterID:
		return p.marshalVarintParam(b, id, uint64(p.InitialMaxData))
	case initialMaxStreamDataBidiLocalParameterID:
		return p.marshalVarintParam(b, id, uint64(p.InitialMaxStreamDataBidiLocal))
	case initialMaxStreamDataBidiRemoteParameterID:
		return p.marshalVarintParam(b, id, uint64(p.InitialMaxStreamDataBidiRemote))
	case initialMaxStreamDataUniParameterID:
		return p.marshalVarintParam(b, id, uint64(p.InitialMaxStreamDataUni))
	case initialMaxStreamsUniParameterID:
		return p.marshalVarintParam(b, id, uint64(p.MaxUniStreamNum))
	case activeConnectionIDLimitParameterID:
		return p.marshalVarintParam(b, id, p.ActiveConnectionIDLimit)
	default: // initial_source_connection_id, empty for a Safari client
		b = quicvarint.Append(b, uint64(id))
		b = quicvarint.Append(b, uint64(p.InitialSourceConnectionID.Len()))
		return append(b, p.InitialSourceConnectionID.Bytes()...)
	}
}

package quic

import "github.com/apernet/quic-go/internal/protocol"

// SetSendBudget caps the data this side lets sit at the peer received but not yet
// read: at most connection bytes across the connection and stream bytes on any one
// stream (0 lifts a cap). The peer keeps the windows it advertised, so nothing about
// it changes on the wire; this side just stops short of the credit.
//
// The cap holds exactly for a peer that keeps its windows at the ones in its
// transport parameters (no auto-tuning) and loosens by however much a peer grew
// them. The sender learns about reads only through the peer's window updates, so a
// budget close to the update granularity (a quarter window by default, see
// Config.WindowUpdateThreshold) costs throughput; one below a quarter window is
// raised to it, since the peer would never advertise more.
//
// It may be called at any time after the handshake, from any goroutine.
func (c *Conn) SetSendBudget(connection, stream int64) {
	if c.peerParams == nil {
		return
	}

	c.connFlowController.SetSendBudget(
		protocol.ByteCount(connection),
		protocol.ByteCount(stream),
		c.peerParams.InitialMaxData,
	)

	// A budget that was raised or lifted frees streams it blocked.
	c.scheduleSending()
}

package ackhandler

// The tests in this package describe the upstream ACK cadence (every second ack-eliciting
// packet); the fork acks every 20 to spare the peer a wake and a recvmmsg per pair of packets.
func init() { packetsBeforeAck = 2 }

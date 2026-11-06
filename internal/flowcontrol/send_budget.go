package flowcontrol

import "github.com/apernet/quic-go/internal/protocol"

// sendHold is how much of a peer's credit a sender leaves unused so that at most
// budget bytes sit at the peer received but unread.
//
// A peer that keeps its receive window at peerWindow (the one in its transport
// parameters, never auto-tuned) advertises limit = read + peerWindow, so every
// MAX_DATA / MAX_STREAM_DATA tells the sender exactly how much the peer had read:
// limit - peerWindow. Stopping at that plus budget is stopping at
// limit - (peerWindow - budget). A peer that grew its window has read less than
// this assumes, so the bound loosens by the growth; it never stalls.
//
// The peer reveals its reads only once per threshold of its window (a quarter in
// quic-go), and it advertises nothing while less than that is read. A budget under
// a quarter window would leave the sender waiting for an update the peer never
// sends, so the budget never goes below it.
func sendHold(peerWindow, budget protocol.ByteCount) protocol.ByteCount {
	if budget <= 0 {
		return 0
	}
	budget = max(budget, peerWindow/4)
	return max(peerWindow-budget, 0)
}

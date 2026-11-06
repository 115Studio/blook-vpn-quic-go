package flowcontrol

import (
	"math/rand/v2"
	"testing"

	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

func TestSendHold(t *testing.T) {
	require.Zero(t, sendHold(6000, 0), "no budget")
	require.Zero(t, sendHold(6000, 6000), "budget as large as the window")
	require.Zero(t, sendHold(6000, 9000), "budget above the window")
	require.EqualValues(t, 3000, sendHold(6000, 3000))
	// The peer only advertises after a quarter window is read.
	require.EqualValues(t, 4500, sendHold(6000, 100))
	require.Zero(t, sendHold(0, 100), "unknown peer window")
}

func TestSendBudgetConnection(t *testing.T) {
	fc := NewConnectionFlowController(0, 0, nil, utils.NewRTTStats(), utils.DefaultLogger)
	fc.UpdateSendWindow(15000)
	fc.SetSendBudget(6000, 0, 15000)
	require.EqualValues(t, 6000, fc.SendWindowSize())

	fc.AddBytesSent(6000)
	require.Zero(t, fc.SendWindowSize())
	// Out of budget is not out of credit: no DATA_BLOCKED for an offset the peer allows.
	blocked, _ := fc.IsNewlyBlocked()
	require.False(t, blocked)

	// The peer read 4000 and advertised read + window.
	fc.UpdateSendWindow(4000 + 15000)
	require.EqualValues(t, 4000, fc.SendWindowSize())

	fc.SetSendBudget(0, 0, 15000)
	require.EqualValues(t, 13000, fc.SendWindowSize())
}

func TestSendBudgetStream(t *testing.T) {
	cfc := NewConnectionFlowController(0, 0, nil, utils.NewRTTStats(), utils.DefaultLogger)
	cfc.UpdateSendWindow(15000)
	fc := NewStreamFlowController(4, cfc, 100, 100, 6000, utils.NewRTTStats(), utils.DefaultLogger)
	require.EqualValues(t, 6000, fc.SendWindowSize())

	cfc.SetSendBudget(6000, 3000, 15000)
	require.EqualValues(t, 3000, fc.SendWindowSize())
	fc.AddBytesSent(3000)
	require.Zero(t, fc.SendWindowSize())
	require.False(t, fc.IsNewlyBlocked())

	// The connection budget binds when it is the tighter one.
	other := NewStreamFlowController(8, cfc, 100, 100, 6000, utils.NewRTTStats(), utils.DefaultLogger)
	require.EqualValues(t, 3000, other.SendWindowSize())
	other.AddBytesSent(3000)
	require.Zero(t, other.SendWindowSize())
}

func TestWindowUpdateThreshold(t *testing.T) {
	newConn := func(threshold float64) *connectionFlowController {
		fc := NewConnectionFlowController(1600, 1600, nil, utils.NewRTTStats(), utils.DefaultLogger)
		fc.SetWindowUpdateThreshold(threshold)
		return fc
	}

	fc := newConn(0)
	require.NoError(t, fc.IncrementHighestReceived(1600, monotime.Now()))
	require.False(t, fc.AddBytesRead(100), "a quarter window by default")

	fc = newConn(1.0 / 16)
	require.NoError(t, fc.IncrementHighestReceived(1600, monotime.Now()))
	require.True(t, fc.AddBytesRead(100))
	require.EqualValues(t, 1700, fc.GetWindowUpdate(monotime.Now()))

	// Streams advertise at their connection's cadence.
	str := NewStreamFlowController(4, fc, 1600, 1600, 0, utils.NewRTTStats(), utils.DefaultLogger)
	require.NoError(t, str.UpdateHighestReceived(100, false, monotime.Now()))
	hasStreamUpdate, _ := str.AddBytesRead(100)
	require.True(t, hasStreamUpdate)
}

// budgetLink drives a sender's flow controllers against a receiver's real ones over
// a link that delays data and window updates, with readers that lag behind. Chrome's
// windows scaled down: 6000 per stream, 15000 per connection, both fixed.
type budgetLink struct {
	t *testing.T

	connBudget, streamBudget protocol.ByteCount

	sendConn *connectionFlowController
	recvConn *connectionFlowController
	send     []StreamFlowController
	recv     []StreamFlowController

	sent, received, read []protocol.ByteCount
	inFlight             []budgetPacket
}

// budgetPacket is STREAM data (stream >= 0) or a window update for the sender.
type budgetPacket struct {
	at     int
	stream int
	offset protocol.ByteCount
	isMax  bool
	conn   bool
}

const (
	budgetStreamWindow = 6000
	budgetConnWindow   = 15000
	budgetDelay        = 5 // ticks one way
)

func newBudgetLink(t *testing.T, streams int, threshold float64, connBudget, streamBudget protocol.ByteCount) *budgetLink {
	l := &budgetLink{
		t:            t,
		connBudget:   connBudget,
		streamBudget: streamBudget,
		sendConn:     NewConnectionFlowController(0, 0, nil, utils.NewRTTStats(), utils.DefaultLogger),
		recvConn:     NewConnectionFlowController(budgetConnWindow, budgetConnWindow, nil, utils.NewRTTStats(), utils.DefaultLogger),
		sent:         make([]protocol.ByteCount, streams),
		received:     make([]protocol.ByteCount, streams),
		read:         make([]protocol.ByteCount, streams),
	}
	l.recvConn.SetWindowUpdateThreshold(threshold)
	l.sendConn.UpdateSendWindow(budgetConnWindow)
	l.sendConn.SetSendBudget(connBudget, streamBudget, budgetConnWindow)

	for i := range streams {
		id := protocol.StreamID(4 * i)
		l.send = append(l.send, NewStreamFlowController(id, l.sendConn, 0, 0, budgetStreamWindow, utils.NewRTTStats(), utils.DefaultLogger))
		l.recv = append(l.recv, NewStreamFlowController(id, l.recvConn, budgetStreamWindow, budgetStreamWindow, 0, utils.NewRTTStats(), utils.DefaultLogger))
	}
	return l
}

func (l *budgetLink) sendData(tick int) {
	for i, fc := range l.send {
		n := min(fc.SendWindowSize(), 300)
		if n == 0 {
			continue
		}
		fc.AddBytesSent(n)
		l.sent[i] += n
		l.inFlight = append(l.inFlight, budgetPacket{at: tick + budgetDelay, stream: i, offset: l.sent[i]})
	}
}

func (l *budgetLink) deliver(tick int) {
	var later []budgetPacket
	for _, p := range l.inFlight {
		if p.at > tick {
			later = append(later, p)
			continue
		}
		switch {
		case p.conn:
			l.sendConn.UpdateSendWindow(p.offset)
		case p.isMax:
			l.send[p.stream].UpdateSendWindow(p.offset)
		default:
			require.NoError(l.t, l.recv[p.stream].UpdateHighestReceived(p.offset, false, monotime.Now()))
			l.received[p.stream] = max(l.received[p.stream], p.offset)
		}
	}
	l.inFlight = later
}

func (l *budgetLink) readStream(tick, i int, n protocol.ByteCount) {
	n = min(n, l.received[i]-l.read[i])
	if n <= 0 {
		return
	}
	l.read[i] += n
	hasStreamUpdate, hasConnUpdate := l.recv[i].AddBytesRead(n)
	if hasStreamUpdate {
		if offset := l.recv[i].GetWindowUpdate(monotime.Now()); offset > 0 {
			l.inFlight = append(l.inFlight, budgetPacket{at: tick + budgetDelay, stream: i, offset: offset, isMax: true})
		}
	}
	if hasConnUpdate {
		if offset := l.recvConn.GetWindowUpdate(monotime.Now()); offset > 0 {
			l.inFlight = append(l.inFlight, budgetPacket{at: tick + budgetDelay, offset: offset, conn: true})
		}
	}
}

// checkUnread asserts what the receiver holds unread stays inside the budgets.
func (l *budgetLink) checkUnread() {
	var total protocol.ByteCount
	for i := range l.recv {
		unread := l.received[i] - l.read[i]
		require.LessOrEqual(l.t, unread, l.streamBudget, "stream %d", i)
		total += unread
	}
	require.LessOrEqual(l.t, total, l.connBudget)
}

func TestSendBudgetBoundsUnreadAndKeepsFlowing(t *testing.T) {
	for _, threshold := range []float64{0, 1.0 / 16} {
		l := newBudgetLink(t, 3, threshold, 6000, 3000)
		rng := rand.New(rand.NewPCG(1, 2))
		const target = 200_000

		for tick := 0; l.read[0]+l.read[1]+l.read[2] < 3*target; tick++ {
			require.Less(t, tick, 100_000, "transfer stalled (threshold %v)", threshold)
			l.sendData(tick)
			l.deliver(tick)
			for i := range l.recv {
				// Readers fall behind in bursts, the way a tun hand-off does.
				if rng.IntN(4) != 0 {
					l.readStream(tick, i, protocol.ByteCount(rng.IntN(500)))
				}
			}
			l.checkUnread()
		}
	}
}

func TestSendBudgetSurvivesAStalledStream(t *testing.T) {
	// One stream's reader stops (a paused player). With update granularity under
	// connection budget minus stream budget, the others keep flowing; a quarter
	// window (3750) would not fit in 6000 - 3000.
	l := newBudgetLink(t, 2, 1.0/16, 6000, 3000)

	for tick := range 2000 {
		l.sendData(tick)
		l.deliver(tick)
		l.readStream(tick, 1, 400)
		l.checkUnread()
	}

	require.EqualValues(t, 3000, l.received[0]-l.read[0], "the stalled stream is held at its budget")
	require.Greater(t, l.read[1], protocol.ByteCount(100_000), "the other stream kept flowing")
}

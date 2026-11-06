package flowcontrol

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/qerr"
	"github.com/apernet/quic-go/internal/utils"
)

type connectionFlowController struct {
	baseFlowController

	// Set by the application while the connection runs, so they are atomic.
	sendHold         atomic.Int64
	streamSendBudget atomic.Int64
}

var _ ConnectionFlowController = &connectionFlowController{}

// NewConnectionFlowController gets a new flow controller for the connection
// It is created before we receive the peer's transport parameters, thus it starts with a sendWindow of 0.
func NewConnectionFlowController(
	receiveWindow protocol.ByteCount,
	maxReceiveWindow protocol.ByteCount,
	allowWindowIncrease func(size protocol.ByteCount) bool,
	rttStats *utils.RTTStats,
	logger utils.Logger,
) *connectionFlowController {
	return &connectionFlowController{
		baseFlowController: baseFlowController{
			rttStats:             rttStats,
			receiveWindow:        receiveWindow,
			receiveWindowSize:    receiveWindow,
			maxReceiveWindowSize: maxReceiveWindow,
			updateThreshold:      protocol.WindowUpdateThreshold,
			allowWindowIncrease:  allowWindowIncrease,
			logger:               logger,
		},
	}
}

// SetWindowUpdateThreshold sets the fraction of a receive window read before a higher
// limit is advertised, for the connection and the streams opened after it. It must be
// called before the connection receives data.
func (c *connectionFlowController) SetWindowUpdateThreshold(threshold float64) {
	if threshold > 0 && threshold < 1 {
		c.updateThreshold = threshold
	}
}

func (c *connectionFlowController) windowUpdateThreshold() float64 {
	return c.updateThreshold
}

// SetSendBudget caps what this side sends at what the peer read plus budget, on the
// connection and on each stream (streamBudget; 0 lifts a cap). peerWindow is the
// connection receive window in the peer's transport parameters.
func (c *connectionFlowController) SetSendBudget(budget, streamBudget, peerWindow protocol.ByteCount) {
	c.sendHold.Store(int64(sendHold(peerWindow, budget)))
	c.streamSendBudget.Store(int64(max(streamBudget, 0)))
}

func (c *connectionFlowController) SendWindowSize() protocol.ByteCount {
	return c.sendWindowSizeUnder(protocol.ByteCount(c.sendHold.Load()))
}

func (c *connectionFlowController) streamBudget() protocol.ByteCount {
	return protocol.ByteCount(c.streamSendBudget.Load())
}

// IncrementHighestReceived adds an increment to the highestReceived value
func (c *connectionFlowController) IncrementHighestReceived(increment protocol.ByteCount, now monotime.Time) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// If this is the first frame received on this connection, start flow-control auto-tuning.
	if c.highestReceived == 0 {
		c.startNewAutoTuningEpoch(now)
	}
	c.highestReceived += increment

	if c.checkFlowControlViolation() {
		return &qerr.TransportError{
			ErrorCode:    qerr.FlowControlError,
			ErrorMessage: fmt.Sprintf("received %d bytes for the connection, allowed %d bytes", c.highestReceived, c.receiveWindow),
		}
	}
	return nil
}

func (c *connectionFlowController) AddBytesRead(n protocol.ByteCount) (hasWindowUpdate bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.addBytesRead(n)
	return c.hasWindowUpdate()
}

func (c *connectionFlowController) GetWindowUpdate(now monotime.Time) protocol.ByteCount {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	oldWindowSize := c.receiveWindowSize
	offset := c.getWindowUpdate(now)
	if c.logger.Debug() && oldWindowSize < c.receiveWindowSize {
		c.logger.Debugf("Increasing receive flow control window for the connection to %d kB", c.receiveWindowSize/(1<<10))
	}
	return offset
}

// EnsureMinimumWindowSize sets a minimum window size
// it should make sure that the connection-level window is increased when a stream-level window grows
func (c *connectionFlowController) EnsureMinimumWindowSize(inc protocol.ByteCount, now monotime.Time) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if inc <= c.receiveWindowSize {
		return
	}
	newSize := min(inc, c.maxReceiveWindowSize)
	if delta := newSize - c.receiveWindowSize; delta > 0 && c.allowWindowIncrease(delta) {
		c.receiveWindowSize = newSize
		if c.logger.Debug() {
			c.logger.Debugf("Increasing receive flow control window for the connection to %d, in response to stream flow control window increase", newSize)
		}
	}
	c.startNewAutoTuningEpoch(now)
}

// Reset rests the flow controller. This happens when 0-RTT is rejected.
// All stream data is invalidated, it's as if we had never opened a stream and never sent any data.
// At that point, we only have sent stream data, but we didn't have the keys to open 1-RTT keys yet.
func (c *connectionFlowController) Reset() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.bytesRead > 0 || c.highestReceived > 0 || !c.epochStartTime.IsZero() {
		return errors.New("flow controller reset after reading data")
	}
	c.bytesSent = 0
	c.lastBlockedAt = 0
	c.sendWindow = 0
	return nil
}

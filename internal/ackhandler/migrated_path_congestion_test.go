package ackhandler

import (
	"testing"

	congestionExt "github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

type fakeCongestionControl struct{ congestionExt.CongestionControl }

func (fakeCongestionControl) SetRTTStatsProvider(congestionExt.RTTStatsProvider) {}

func newMigrationTestHandler() *sentPacketHandler {
	return NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	).(*sentPacketHandler)
}

func TestMigratedPathKeepsInstalledCongestionControl(t *testing.T) {
	sph := newMigrationTestHandler()
	sph.SetCongestionControl(fakeCongestionControl{})

	sph.MigratedPath(monotime.Now(), 1200)

	_, kept := sph.getCongestionControl().(*ccAdapter)
	require.True(t, kept, "a migration replaced the installed congestion controller")
}

func TestMigratedPathResetsDefaultCongestionControl(t *testing.T) {
	sph := newMigrationTestHandler()
	before := sph.getCongestionControl()

	sph.MigratedPath(monotime.Now(), 1200)

	require.NotSame(t, before, sph.getCongestionControl())
}

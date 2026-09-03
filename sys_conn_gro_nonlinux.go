//go:build !linux

package quic

import "syscall"

const msgTypeUDPGRO = -1

func enableGRO(syscall.RawConn) bool { return false }

func parseUDPGROSize([]byte) (int, bool) { return 0, false }

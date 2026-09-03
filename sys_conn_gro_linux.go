//go:build linux

package quic

import (
	"encoding/binary"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

const msgTypeUDPGRO = unix.UDP_GRO

// enableGRO asks the kernel to hand coalesced same-size datagrams of a flow over
// as one buffer plus a UDP_GRO cmsg carrying the segment size. Coalescing only
// happens when the NIC path runs UDP GRO for this socket (or, for NAT'd flows,
// rx-udp-gro-forwarding), so failing here just means per-packet reads.
func enableGRO(conn syscall.RawConn) bool {
	if kernelVersionMajor < 5 {
		return false
	}
	if disabled, err := strconv.ParseBool(os.Getenv("QUIC_GO_DISABLE_GRO")); err == nil && disabled {
		return false
	}
	var serr error
	if err := conn.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
	}); err != nil {
		return false
	}
	return serr == nil
}

// parseUDPGROSize reads the int the kernel puts in the UDP_GRO cmsg.
func parseUDPGROSize(body []byte) (int, bool) {
	if len(body) != 4 {
		return 0, false
	}
	return int(binary.NativeEndian.Uint32(body)), true
}

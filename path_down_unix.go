//go:build !windows

package quic

import (
	"errors"

	"golang.org/x/sys/unix"
)

func isPathDownErr(err error) bool {
	return errors.Is(err, unix.ENETUNREACH) ||
		errors.Is(err, unix.EHOSTUNREACH) ||
		errors.Is(err, unix.ENETDOWN) ||
		errors.Is(err, unix.EHOSTDOWN) ||
		errors.Is(err, unix.EADDRNOTAVAIL)
}

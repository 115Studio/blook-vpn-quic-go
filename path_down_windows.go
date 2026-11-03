//go:build windows

package quic

import (
	"errors"

	"golang.org/x/sys/windows"
)

func isPathDownErr(err error) bool {
	return errors.Is(err, windows.WSAENETUNREACH) ||
		errors.Is(err, windows.WSAEHOSTUNREACH) ||
		errors.Is(err, windows.WSAENETDOWN) ||
		errors.Is(err, windows.WSAEHOSTDOWN) ||
		errors.Is(err, windows.WSAEADDRNOTAVAIL)
}

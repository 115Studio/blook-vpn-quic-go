package quic

import "time"

// A network that has just gone away under a connection (Wi-Fi dropped, cellular handing
// over) fails every send with "network unreachable" or a sibling until the OS settles. A
// client that follows network changes moves the connection to a socket on the new network
// within this window (Conn.AddPath), so the failed sends count as lost packets rather than
// as the end of the connection. Past the window the error ends the connection as before,
// which is what a client that never moves gets: the same failure, this much later.
const pathDownGrace = 10 * time.Second

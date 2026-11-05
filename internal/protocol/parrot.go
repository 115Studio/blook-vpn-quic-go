package protocol

// Parrot is the client whose QUIC handshake a client imitates on the wire.
type Parrot uint8

const (
	// ParrotNone sends quic-go's own handshake.
	ParrotNone Parrot = iota
	// ParrotChrome imitates Google Chrome.
	ParrotChrome
	// ParrotSafari imitates Apple's QUIC stack (Safari and every other app on iOS
	// 26, which share it), as captured from Safari on iOS 26.6.2.
	ParrotSafari
)

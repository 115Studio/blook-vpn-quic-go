package handshake

import (
	utls "github.com/refraction-networking/utls"
)

// safariQUICClientHelloSpec returns the TLS ClientHello Apple's QUIC stack sends, as
// captured from Safari on iOS 26.6.2 (every app on iOS shares the stack, so App Store
// and iCloud hellos are the same). Unlike Chrome's, the extension order is fixed.
//
// As with Chrome, this is not uTLS's HelloSafari preset: that one is the TLS-over-TCP
// hello, which carries TLS 1.2 suites, more extensions and no QUIC parameters.
//
// alpn comes from the caller's tls.Config; Safari sends "h3".
func safariQUICClientHelloSpec(alpn []string) *utls.ClientHelloSpec {
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}
	grease := utls.CurveID(utls.GREASE_PLACEHOLDER)
	return &utls.ClientHelloSpec{
		// AES-256 first, unlike Chrome.
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_128_GCM_SHA256,
		},
		CompressionMethods: []byte{0x00},
		Extensions: []utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				grease,
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
			}},
			&utls.ALPNExtension{AlpnProtocols: alpn},
			&utls.StatusRequestExtension{},
			// rsa_pss_rsae_sha384 (0x0805) really is listed twice.
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
				utls.PKCS1WithSHA1,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: grease, Data: []byte{0}},
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
			}},
			// Populated from quic-go's own marshalled parameters; see
			// utlsQUICConn.SetTransportParameters.
			&utls.QUICTransportParametersExtension{},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionZlib,
			}},
			// The second GREASE extension; uTLS gives it the one-byte body Safari's has.
			&utls.UtlsGREASEExtension{},
		},
	}
}

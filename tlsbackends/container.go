package tlsbackends

import "crypto/tls"

type tlsCertificate struct {
	N string
	Crt  *tls.Certificate
}

func (tC *tlsCertificate) Name() string {
	return tC.N
}

func (tC *tlsCertificate) Certificate() *tls.Certificate {
	return tC.Crt
}

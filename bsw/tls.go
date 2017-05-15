package bsw

import (
	"crypto/tls"
	"net"
	"time"
)

// TLS attempts connection to an IP using TLS on port 443, and if successfull, will parse the server
// certificate for CommonName and SubjectAlt names.
func TLS(ip string, timeout int64) *Tsk {
	t := newTsk("TLS Certificate")
	tconn, err := net.DialTimeout("tcp", ip+":443", time.Duration(timeout)*time.Millisecond)
	if err != nil {
		t.SetErr(err)
		return t
	}
	if err := tconn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond)); err != nil {
		t.SetErr(err)
		return t
	}
	conn := tls.Client(tconn, &tls.Config{InsecureSkipVerify: true})
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		t.SetErr(err)
		return t
	}
	state := conn.ConnectionState()
	cert := state.PeerCertificates[0]
	t.AddResult(ip, cert.Subject.CommonName)
	for _, name := range cert.DNSNames {
		t.AddResult(ip, name)
	}
	return t
}

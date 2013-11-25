package bsw

import (
	"crypto/tls"
	"net"
	"time"
)

func TLS(ip string) ([]Result, error) {
	results := make([]Result, 0)
	tconn, err := net.DialTimeout("tcp", ip+":443", 600*time.Millisecond)
	if err != nil {
		return results, err
	}
	config := tls.Config{InsecureSkipVerify: true}
	conn := tls.Client(tconn, &config)
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		return results, err
	}
	state := conn.ConnectionState()
	for _, cert := range state.PeerCertificates {
		// TODO: Regex to detect if Subject name is a hostname
		results = append(results, Result{Source: "TLS Certificate", IP: ip, Hostname: cert.Subject.CommonName})
		for _, name := range cert.DNSNames {
			results = append(results, Result{Source: "TLS Certificate", IP: ip, Hostname: name})
		}
	}
	return results, nil
}

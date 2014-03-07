package bsw

import (
	"errors"
	"github.com/miekg/dns"
	"strings"
)

// LookupIP returns hostname from PTR record or error.
func LookupIP(ip, serverAddr string) (string, error) {
	fqdn, err := dns.ReverseAddr(ip)
	if err != nil {
		return "", err
	}
	m := &dns.Msg{}
	m.SetQuestion(fqdn, dns.TypePTR)
	in, err := dns.Exchange(m, serverAddr+":53")
	if err != nil {
		return "", err
	}
	if len(in.Answer) < 1 {
		return "", errors.New("no Answer")
	}
	if a, ok := in.Answer[0].(*dns.PTR); ok {
		return strings.TrimRight(a.Ptr, "."), nil
	}
	return "", errors.New("no PTR record returned")

}

// LookupName returns IPv4 address from A record or error.
func LookupName(fqdn, serverAddr string) (string, error) {
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	in, err := dns.Exchange(m, serverAddr+":53")
	if err != nil {
		return "", err
	}
	if len(in.Answer) < 1 {
		return "", errors.New("no Answer")
	}
	if a, ok := in.Answer[0].(*dns.A); ok {
		ip := a.A.String()
		return ip, nil
	}
	return "", errors.New("no A record returned")
}

// LookupCname returns an IPv4 address from CNAME record or error.
func LookupCname(fqdn, serverAddr string) (string, error) {
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeCNAME)
	in, err := dns.Exchange(m, serverAddr+":53")
	if err != nil {
		return "", err
	}
	if len(in.Answer) < 1 {
		return "", errors.New("no Answer")
	}
	if a, ok := in.Answer[0].(*dns.CNAME); ok {
		name := a.Target
		return strings.TrimRight(name, "."), nil
	}
	return "", errors.New("no CNAME record returned")
}

// LookupName6 returns a IPv6 address from AAAA record or error.
func LookupName6(fqdn, serverAddr string) (string, error) {
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeAAAA)
	in, err := dns.Exchange(m, serverAddr+":53")
	if err != nil {
		return "", err
	}
	if len(in.Answer) < 1 {
		return "", errors.New("no Answer")
	}
	if a, ok := in.Answer[0].(*dns.AAAA); ok {
		ip := a.AAAA.String()
		return ip, nil
	}
	return "", errors.New("no AAAA record returned")
}

// LookupSRV returns a hostname from SRV record or error.
func LookupSRV(fqdn, dnsServer string) (string, error) {
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeSRV)
	in, err := dns.Exchange(m, dnsServer+":53")
	if err != nil {
		return "", err
	}
	if len(in.Answer) < 1 {
		return "", errors.New("no Answer")
	}
	if a, ok := in.Answer[0].(*dns.SRV); ok {
		return strings.TrimRight(a.Target, "."), nil
	}
	return "", errors.New("no SRV record returned")
}

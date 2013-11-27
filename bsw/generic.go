package bsw

import (
	"errors"
	"github.com/miekg/dns"
	"strings"
)

func LookupIP(ip, serverAddr string) (string, error) {
	fqdn, err := dns.ReverseAddr(ip)
	if err != nil {
		return "", err
	}
	m := new(dns.Msg)
	m.SetQuestion(fqdn, dns.TypePTR)
	in, err := dns.Exchange(m, serverAddr+":53")
	if err != nil {
		return "", err
	}
	if len(in.Answer) < 1 {
		return "", errors.New("No Answer")
	}
	if a, ok := in.Answer[0].(*dns.PTR); ok {
		return strings.TrimRight(a.Ptr, "."), nil
	} else {
		return "", errors.New("No PTR record returned")
	}
}

func LookupName(fqdn, serverAddr string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	in, err := dns.Exchange(m, serverAddr+":53")
	if err != nil {
		return "", err
	}
	if len(in.Answer) < 1 {
		return "", errors.New("No Answer")
	}
	if a, ok := in.Answer[0].(*dns.A); ok {
		ip := a.A.String()
		return ip, nil
	} else {
		return "", errors.New("No A record returned")
	}
}

func LookupCname(fqdn, serverAddr string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeCNAME)
	in, err := dns.Exchange(m, serverAddr+":53")
	if err != nil {
		return "", err
	}
	if len(in.Answer) < 1 {
		return "", errors.New("No Answer")
	}
	if a, ok := in.Answer[0].(*dns.CNAME); ok {
		name := a.Target
		return strings.TrimRight(name, "."), nil
	} else {
		return "", errors.New("No CNAME record returned")
	}
}

func LookupName6(fqdn, serverAddr string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeAAAA)
	in, err := dns.Exchange(m, serverAddr+":53")
	if err != nil {
		return "", err
	}
	if len(in.Answer) < 1 {
		return "", errors.New("No Answer")
	}
	if a, ok := in.Answer[0].(*dns.AAAA); ok {
		ip := a.AAAA.String()
		return ip, nil
	} else {
		return "", errors.New("No AAAA record returned")
	}
}

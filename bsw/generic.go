package bsw

import (
	"errors"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// LookupMX returns all the mx servers for a domain.
func LookupMX(domain, serverAddr string) ([]string, error) {
	servers := []string{}
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	in, err := dns.Exchange(m, serverAddr+":53")
	if err != nil {
		return servers, err
	}
	if len(in.Answer) < 1 {
		return servers, errors.New("no Answer")
	}
	for _, a := range in.Answer {
		if mx, ok := a.(*dns.MX); ok {
			parts := strings.Split(mx.Mx, " ")
			if len(parts) < 1 {
				continue
			}
			servers = append(servers, parts[len(parts)-1])
		}
	}
	return servers, nil
}

// LookupNS returns the names servers for a domain.
func LookupNS(domain, serverAddr string) ([]string, error) {
	servers := []string{}
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	in, err := dns.Exchange(m, serverAddr+":53")
	if err != nil {
		return servers, err
	}
	if len(in.Answer) < 1 {
		return servers, errors.New("no Answer")
	}
	for _, a := range in.Answer {
		if ns, ok := a.(*dns.NS); ok {
			servers = append(servers, ns.Ns)
		}
	}
	return servers, nil
}

// LookupIP returns hostname from PTR record or error.
func LookupIP(ip, serverAddr string) ([]string, error) {
	names := []string{}
	m := &dns.Msg{}
	ipArpa, err := dns.ReverseAddr(ip)
	if err != nil {
		return names, err
	}
	m.SetQuestion(ipArpa, dns.TypePTR)
	in, err := dns.Exchange(m, serverAddr+":53")
	if err != nil {
		return names, err
	}
	if len(in.Answer) < 1 {
		return names, errors.New("no Answer")
	}

	for _, a := range in.Answer {
		if ptr, ok := a.(*dns.PTR); ok {
			if strings.Contains(ptr.Ptr, strings.Join(strings.Split(ip, "."), "-")) {
				continue
			}
			names = append(names, strings.TrimRight(ptr.Ptr, "."))
		}
	}

	if len(names) < 1 {
		return names, errors.New("no PTR")
	}

	return names, nil
}

// LookupName returns IPv4 addresses from A records or error.
func LookupName(fqdn, serverAddr string) ([]string, error) {
	ips := []string{}
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	in, err := dns.Exchange(m, serverAddr+":53")
	if err != nil {
		return ips, err
	}
	if len(in.Answer) < 1 {
		return ips, errors.New("no Answer")
	}
	for _, answer := range in.Answer {
		if a, ok := answer.(*dns.A); ok {
			ip := a.A.String()
			ips = append(ips, ip)
		}
	}

	if len(ips) == 0 {
		err = errors.New("no A record returned")
	}
	sort.Sort(sort.StringSlice(ips))
	return ips, err
}

// LookupCname returns a fqdn address from CNAME record or error.
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

// LookupName6 returns IPv6 addresses from AAAA records or error.
func LookupName6(fqdn, serverAddr string) ([]string, error) {
	ips := []string{}
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeAAAA)
	in, err := dns.Exchange(m, serverAddr+":53")
	if err != nil {
		return ips, err
	}
	if len(in.Answer) < 1 {
		return ips, errors.New("no Answer")
	}
	for _, answer := range in.Answer {
		if a, ok := answer.(*dns.AAAA); ok {
			ip := a.AAAA.String()
			ips = append(ips, ip)
		}
	}

	if len(ips) == 0 {
		err = errors.New("no A record returned")
	}
	return ips, err
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

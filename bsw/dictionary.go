package bsw

import (
	"errors"
	"github.com/miekg/dns"
)

// Search for a possible wild card host by attempting to 
// get an A record youmustconstructmoreplylons.[domain].
func GetWildCard(domain, serverAddr string) string {
	var fqdn = "youmustconstructmorepylons." + domain
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	in, err := dns.Exchange(m, serverAddr+":53")
	if err != nil {
		return ""
	}
	if len(in.Answer) < 1 {
		return ""
	}
	if a, ok := in.Answer[0].(*dns.A); ok {
		return a.A.String()
	} else {
		return ""
	}
}

// Search for a possible wild card host by attempting to 
// get an AAAA record youmustconstructmoreplylons.[domain].
func GetWildCard6(domain, serverAddr string) string {
	var fqdn = "youmustconstructmorepylons." + domain
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeAAAA)
	in, err := dns.Exchange(m, serverAddr+":53")
	if err != nil {
		return ""
	}
	if len(in.Answer) < 1 {
		return ""
	}
	if a, ok := in.Answer[0].(*dns.AAAA); ok {
		return a.AAAA.String()
	} else {
		return ""
	}
}

// Attempt to get an A and CNAME record for a sub domain of domain.
func Dictionary(domain, subname, blacklist, serverAddr string) (Results, error) {
	results := Results{}
	var fqdn = subname + "." + domain
	ip, err := LookupName(fqdn, serverAddr)
	if err != nil {
		cfqdn, err := LookupCname(fqdn, serverAddr)
		if err != nil {
			return results, err
		}
		ip, err = LookupName(cfqdn, serverAddr)
		if err != nil {
			return results, err
		}
		if ip == blacklist {
			return results, errors.New("Returned IP in blackslist")
		}
		results = append(results, Result{Source: "Dictionary-CNAME", IP: ip, Hostname: fqdn}, Result{Source: "Dictionary-CNAME", IP: ip, Hostname: cfqdn})
		return results, nil
	}
	if ip == blacklist {
		return results, errors.New("Returned IP in blacklist")
	}
	results = append(results, Result{Source: "Dictionary", IP: ip, Hostname: fqdn})
	return results, nil
}

// Attempt to get an AAAA record for a sub domain of a domain.
func Dictionary6(domain, subname, blacklist, serverAddr string) (Results, error) {
	results := Results{}
	var fqdn = subname + "." + domain
	ip, err := LookupName6(fqdn, serverAddr)
	if err != nil {
		return results, err
	}
	if ip == blacklist {
		return results, errors.New("Returned IP in blacklist")
	}
	results = append(results, Result{Source: "Dictionary IPv6", IP: ip, Hostname: fqdn})
	return results, nil
}

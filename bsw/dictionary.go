package bsw

import "fmt"
import "reflect"

const wildcardsub = "youmustcontstuctmoreplyons."

// GetWildCard searches for a possible wild card host by attempting to
// get A records for wildcardsub + domain.
func GetWildCards(domain, serverAddr string) []string {
	fqdn := wildcardsub + domain
	ips, _ := LookupName(fqdn, serverAddr)
	return ips
}

// GetWildCard6 searches for a possible wild card host by attempting to
// get AAAA records wildcardsub + domain.
func GetWildCards6(domain, serverAddr string) []string {
	fqdn := wildcardsub + domain
	ips, _ := LookupName6(fqdn, serverAddr)
	return ips
}

// Dictionary attempts to get an A and CNAME record for a sub domain of domain.
func Dictionary(domain string, subname string, blacklist []string, serverAddr string) *Tsk {
	t := newTsk("Dictionary IPv4")
	fqdn := subname + "." + domain
	ips, err := LookupName(fqdn, serverAddr)
	if err == nil {
		if reflect.DeepEqual(ips, blacklist) {
			t.SetErr(fmt.Errorf("%v: returned IPs in blackslist", ips))
			return t
		}
		for _, ip := range ips {
			t.AddResult(ip, fqdn)
		}
		return t
	}

	ecount := 0
	cfqdn := ""
	tfqdn := fqdn
	cfqdns := []string{}

	for {
		cfqdn, err = LookupCname(tfqdn, serverAddr)
		if err != nil {
			t.SetErr(err)
			return t
		}
		cfqdns = append(cfqdns, cfqdn)
		ips, err = LookupName(cfqdn, serverAddr)
		if err != nil {
			ecount++
			if ecount > 10 {
				t.SetErr(err)
				return t
			}
			tfqdn = cfqdn
			continue
		}
		break
	}

	if reflect.DeepEqual(ips, blacklist) {
		t.SetErr(fmt.Errorf("%v: returned IPs in blackslist", ips))
		return t
	}
	t.SetTask("Dictionary-CNAME")
	for _, ip := range ips {
		t.AddResult(ip, fqdn)
		for _, c := range cfqdns {
			t.AddResult(ip, c)
		}
	}
	return t
}

// Dictionary6 attempts to get an AAAA record for a sub domain of a domain.
func Dictionary6(domain string, subname string, blacklist []string, serverAddr string) *Tsk {
	t := newTsk("Dictionary IPv6")
	fqdn := subname + "." + domain
	ips, err := LookupName6(fqdn, serverAddr)
	if err != nil {
		t.SetErr(err)
		return t
	}
	if reflect.DeepEqual(ips, blacklist) {
		t.SetErr(fmt.Errorf("%v: returned IPs in blacklist", ips))
		return t
	}
	for _, ip := range ips {
		t.AddResult(ip, fqdn)
	}
	return t
}

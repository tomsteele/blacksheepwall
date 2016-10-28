package bsw

import "fmt"

const wildcardsub = "youmustcontstuctmoreplyons."

// GetWildCard searches for a possible wild card host by attempting to
// get an A record for wildcardsub + domain.
func GetWildCard(domain, serverAddr string) string {
	fqdn := wildcardsub + domain
	ip, _ := LookupName(fqdn, serverAddr)
	return ip
}

// GetWildCard6 searches for a possible wild card host by attempting to
// get an AAAA record wildcardsub + domain.
func GetWildCard6(domain, serverAddr string) string {
	fqdn := wildcardsub + domain
	ip, _ := LookupName6(fqdn, serverAddr)
	return ip
}

// Dictionary attempts to get an A and CNAME record for a sub domain of domain.
func Dictionary(domain, subname, blacklist, serverAddr string) *Tsk {
	t := newTsk("Dictionary IPv4")
	fqdn := subname + "." + domain
	ip, err := LookupName(fqdn, serverAddr)
	if err == nil {
		if ip == blacklist {
			t.SetErr(fmt.Errorf("%v: returned IP in blackslist", ip))
			return t
		}
		t.AddResult(ip, fqdn)
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
		ip, err = LookupName(cfqdn, serverAddr)
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

	if ip == blacklist {
		t.SetErr(fmt.Errorf("%v: returned IP in blackslist", ip))
		return t
	}
	t.SetTask("Dictionary-CNAME")
	t.AddResult(ip, fqdn)
	for _, c := range cfqdns {
		t.AddResult(ip, c)
	}
	return t
}

// Dictionary6 attempts to get an AAAA record for a sub domain of a domain.
func Dictionary6(domain, subname, blacklist, serverAddr string) *Tsk {
	t := newTsk("Dictionary IPv6")
	fqdn := subname + "." + domain
	ip, err := LookupName6(fqdn, serverAddr)
	if err != nil {
		t.SetErr(err)
		return t
	}
	if ip == blacklist {
		t.SetErr(fmt.Errorf("%v: returned IP in blacklist", ip))
		return t
	}
	t.AddResult(ip, fqdn)
	return t
}

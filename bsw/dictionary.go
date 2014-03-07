package bsw

import (
	"errors"
)

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
func Dictionary(domain, subname, blacklist, serverAddr string) (Results, error) {
	results := Results{}
	fqdn := subname + "." + domain
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
			return results, errors.New("returned IP in blackslist")
		}
		results = append(results, Result{Source: "Dictionary-CNAME", IP: ip, Hostname: fqdn}, Result{Source: "Dictionary-CNAME", IP: ip, Hostname: cfqdn})
		return results, nil
	}
	if ip == blacklist {
		return results, errors.New("returned IP in blacklist")
	}
	results = append(results, Result{Source: "Dictionary", IP: ip, Hostname: fqdn})
	return results, nil
}

// Dictionary6 attempts to get an AAAA record for a sub domain of a domain.
func Dictionary6(domain, subname, blacklist, serverAddr string) (Results, error) {
	results := Results{}
	fqdn := subname + "." + domain
	ip, err := LookupName6(fqdn, serverAddr)
	if err != nil {
		return results, err
	}
	if ip == blacklist {
		return results, errors.New("returned IP in blacklist")
	}
	results = append(results, Result{Source: "Dictionary IPv6", IP: ip, Hostname: fqdn})
	return results, nil
}

package bsw

import (
	"fmt"
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
func Dictionary(domain, subname, blacklist, serverAddr string) (string, Results, error) {
	task := "Dictionary IPv4"
	results := Results{}
	fqdn := subname + "." + domain
	ip, err := LookupName(fqdn, serverAddr)
	if err != nil {
		cfqdn, err := LookupCname(fqdn, serverAddr)
		if err != nil {
			return task, results, err
		}
		ip, err = LookupName(cfqdn, serverAddr)
		if err != nil {
			return task, results, err
		}
		if ip == blacklist {
			return task, results, fmt.Errorf("%v: returned IP in blackslist", ip)
		}
		results = append(results, Result{Source: "Dictionary-CNAME", IP: ip, Hostname: fqdn}, Result{Source: "Dictionary-CNAME", IP: ip, Hostname: cfqdn})
		return task, results, nil
	}
	if ip == blacklist {
		return task, results, fmt.Errorf("%v: returned IP in blacklist", ip)
	}
	results = append(results, Result{Source: task, IP: ip, Hostname: fqdn})
	return task, results, nil
}

// Dictionary6 attempts to get an AAAA record for a sub domain of a domain.
func Dictionary6(domain, subname, blacklist, serverAddr string) (string, Results, error) {
	task := "Dictionary IPv6"
	results := Results{}
	fqdn := subname + "." + domain
	ip, err := LookupName6(fqdn, serverAddr)
	if err != nil {
		return task, results, err
	}
	if ip == blacklist {
		return task, results, fmt.Errorf("%v: returned IP in blacklist", ip)
	}
	results = append(results, Result{Source: task, IP: ip, Hostname: fqdn})
	return task, results, nil
}

package bsw

import (
	"strings"
)

// NS returns the A record for any NS records for a domain.
func NS(domain, serverAddr string) (string, Results, error) {
	task := "ns"
	results := Results{}
	servers, err := LookupNS(domain, serverAddr)
	if err != nil {
		return task, results, err
	}
	for _, s := range servers {
		ip, err := LookupName(s, serverAddr)
		if err != nil || ip == "" {
			continue
		}
		results = append(results, Result{
			Source:   task,
			IP:       ip,
			Hostname: strings.TrimRight(s, "."),
		})
	}
	return task, results, nil
}

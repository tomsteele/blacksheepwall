package bsw

import "strings"

// MX returns the A record for an MX record for a domain.
func MX(domain, serverAddr string) (string, Results, error) {
	task := "mx"
	results := Results{}
	servers, err := LookupMX(domain, serverAddr)
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

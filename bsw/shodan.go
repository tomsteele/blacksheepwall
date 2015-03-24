package bsw

import (
	"github.com/tomsteele/go-shodan"
)

// ShodanAPI uses Shodan's reverse dns route to return hostnames for a list
// of ips.
func ShodanAPI(ips []string, key string) (string, Results, error) {
	task := "shodan API"
	results := Results{}
	c := shodan.New(key)
	d, err := c.DNSReverse(ips)
	if err != nil {
		return task, results, err
	}
	for _, i := range d {
		for _, h := range i.Hostnames {
			results = append(results, Result{
				Source:   task,
				IP:       i.IP,
				Hostname: h,
			})
		}
	}
	return task, results, nil
}

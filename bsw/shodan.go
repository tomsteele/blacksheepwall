package bsw

import (
	"net/url"
	"strconv"

	"github.com/tomsteele/go-shodan"
)

// ShodanAPIReverse uses Shodan's '/dns/reverse' REST API to get hostnames for
// a list of ips.
func ShodanAPIReverse(ips []string, key string) (string, Results, error) {
	task := "shodan API reverse"
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

// ShodanAPIHostSearch uses Shodan's '/shodan/host/search' REST API endpoint
// to find hostnames and ip addresses for a domain.
func ShodanAPIHostSearch(domain string, key string) (string, Results, error) {
	task := "shodan API host search"
	results := Results{}
	if domain[0] != 46 {
		domain = "." + domain
	}
	c := shodan.New(key)
	count, err := c.HostCount("hostname:"+domain, []string{})
	if err != nil {
		return task, results, err
	}
	pages := count.Total / 100
	if pages < 1 {
		pages = 1
	}
	for i := 1; i <= pages; i++ {
		opts := url.Values{}
		opts.Set("page", strconv.Itoa(i))
		hs, err := c.HostSearch("hostname:"+domain, []string{}, opts)
		if err != nil {
			return task, results, err
		}
		for _, m := range hs.Matches {
			for _, h := range m.Hostnames {
				if v, ok := h.(string); ok {
					results = append(results, Result{
						Source:   task,
						IP:       m.IPStr,
						Hostname: v,
					})
				}
			}
		}
	}
	return task, results, nil
}

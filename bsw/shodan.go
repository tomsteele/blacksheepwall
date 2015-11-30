package bsw

import (
	"net/url"
	"strconv"

	"github.com/tomsteele/go-shodan"
)

// ShodanAPIReverse uses Shodan's '/dns/reverse' REST API to get hostnames for
// a list of ips.
func ShodanAPIReverse(ips []string, key string) *Tsk {
	t := newTsk("shodan API reverse")
	c := shodan.New(key)
	d, err := c.DNSReverse(ips)
	if err != nil {
		t.SetErr(err)
		return t
	}
	for _, i := range d {
		for _, h := range i.Hostnames {
			t.AddResult(i.IP, h)
		}
	}
	return t
}

// ShodanAPIHostSearch uses Shodan's '/shodan/host/search' REST API endpoint
// to find hostnames and ip addresses for a domain.
func ShodanAPIHostSearch(domain string, key string) *Tsk {
	t := newTsk("shodan API host search")
	if domain[0] != 46 {
		domain = "." + domain
	}
	c := shodan.New(key)
	count, err := c.HostCount("hostname:"+domain, []string{})
	if err != nil {
		t.SetErr(err)
		return t
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
			t.SetErr(err)
			return t
		}
		for _, m := range hs.Matches {
			for _, h := range m.Hostnames {
				if v, ok := h.(string); ok {
					t.AddResult(m.IPStr, v)
				}
			}
		}
	}
	return t
}

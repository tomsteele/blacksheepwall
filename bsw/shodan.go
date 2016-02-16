package bsw

import (
	"net/url"
	"strconv"

	"github.com/tomsteele/go-shodan"
)

// Append Shodan results to BSW Task
func appendlist(ips []string, t *Tsk, c *shodan.Client) error {
	d, err := c.DNSReverse(ips)
	if err != nil {
		return err
	}
	for _, i := range d {
		for _, h := range i.Hostnames {
			t.AddResult(i.IP, h)
		}
	}
	return nil
}

// ShodanAPIReverse uses Shodan's '/dns/reverse' REST API to get hostnames for
// a list of ips.
func ShodanAPIReverse(ips []string, key string) *Tsk {
	t := newTsk("shodan API reverse")
	c := shodan.New(key)
	for i := 0; i <= len(ips)/100; i++ {
		start := i * 100
		end := start + 100
		if end >= len(ips) {
			err := appendlist(ips[start:], t, c)
			if err != nil {
				t.SetErr(err)
				return t
			}
		} else {
			err := appendlist(ips[start:end], t, c)
			if err != nil {
				t.SetErr(err)
				return t
			}
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

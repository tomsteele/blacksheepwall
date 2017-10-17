package bsw

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/PuerkitoBio/goquery"
)

// ExfiltratedHostname uses exfiltrated.com's hostname search to identify
// possible hostnames for a domain. Each returned hostname is then resolved to the current IP.
func ExfiltratedHostname(domain, server string) *Tsk {
	t := newTsk("exfiltrated.com")
	resp, err := http.Get(fmt.Sprintf("http://exfiltrated.com/queryhostname.php?hostname=%s", domain))
	if err != nil {
		t.SetErr(err)
		return t
	}
	doc, err := goquery.NewDocumentFromResponse(resp)
	if err != nil {
		t.SetErr(err)
		return t
	}

	wg := sync.WaitGroup{}
	mutex := sync.Mutex{}

	doc.Selection.Find("td:nth-child(1)").Each(func(_ int, s *goquery.Selection) {
		wg.Add(1)
		go func(hostname string) {
			defer wg.Done()
			ips, err := LookupName(hostname, server)
			if err != nil || len(ips) == 0 {
				cfqdn, err := LookupCname(hostname, server)
				if err != nil || cfqdn == "" {
					return
				}
				ips, err = LookupName(cfqdn, server)
				if err != nil || len(ips) == 0 {
					return
				}
			}
			mutex.Lock()
			for _, ip := range ips {
				t.AddResult(ip, hostname)
			}
			mutex.Unlock()
		}(s.Text())
	})
	wg.Wait()
	return t
}

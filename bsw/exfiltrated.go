package bsw

import (
	"net/http"
	"sync"

	"github.com/PuerkitoBio/goquery"
)

// ExfiltratedHostname uses exfiltrated.com's hostname search to identify possible hostnames for a domain. Each returned hostname is then resolved to the current IP.
func ExfiltratedHostname(domain, server string) (string, Results, error) {
	task := "exfiltrated.com"
	results := Results{}
	resp, err := http.Get("http://exfiltrated.com/queryhostname.php?hostname=" + domain)
	if err != nil {
		return task, results, err
	}
	doc, err := goquery.NewDocumentFromResponse(resp)
	if err != nil {
		return task, results, err
	}

	wg := sync.WaitGroup{}
	mutex := sync.Mutex{}

	doc.Selection.Find("td:nth-child(1)").Each(func(_ int, s *goquery.Selection) {
		wg.Add(1)
		go func(hostname string) {
			defer wg.Done()
			ip, err := LookupName(hostname, server)
			if err != nil || ip == "" {
				cfqdn, err := LookupCname(hostname, server)
				if err != nil || cfqdn == "" {
					return
				}
				ip, err = LookupName(cfqdn, server)
				if err != nil || ip == "" {
					return
				}
			}
			mutex.Lock()
			results = append(results, Result{Source: task, IP: ip, Hostname: hostname})
			mutex.Unlock()
		}(s.Text())
	})
	wg.Wait()
	return task, results, err
}

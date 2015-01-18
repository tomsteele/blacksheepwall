package bsw

import (
	"net/http"

	"github.com/PuerkitoBio/goquery"
)

// Very long selector...
const viewDNSSelector = "#null > tbody:nth-child(1) > tr:nth-child(3) > td:nth-child(1) > font:nth-child(1) > i:nth-child(7) > table:nth-child(4) > tbody:nth-child(1) > tr:nth-child(n+1) > td:nth-child(1)"

// ViewDNSInfo Lookup an IP using viewdns.info's reverseip functionality, parsing
// the HTML table for hostnames.
func ViewDNSInfo(ip string) (string, Results, error) {
	task := "viewdns.info"
	results := Results{}
	url := "http://viewdns.info/reverseip/?host=" + ip + "&t=1"
	resp, err := http.Get(url)
	if err != nil {
		return task, results, err
	}
	defer resp.Body.Close()
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return task, results, err
	}
	doc.Selection.Find(viewDNSSelector).Each(func(_ int, s *goquery.Selection) {
		results = append(results, Result{Source: task, IP: ip, Hostname: s.Text()})
	})
	return task, results, nil
}

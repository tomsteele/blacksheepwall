package bsw

import (
	"github.com/PuerkitoBio/goquery"
	"net/http"
)

// Very long selector...
const viewDnsSelector = "#null > tbody:nth-child(1) > tr:nth-child(3) > td:nth-child(1) > font:nth-child(1) > i:nth-child(7) > table:nth-child(4) > tbody:nth-child(1) > tr:nth-child(n+1) > td:nth-child(1)"

// Lookup an IP using viewdns.info's reverseip functionality, parsing
// the HTML table for hostnames.
func ViewDnsInfo(ip string) (Results, error) {
	results := Results{}
	var url = "http://viewdns.info/reverseip/?host=" + ip + "&t=1"
	resp, err := http.Get(url)
	if err != nil {
		return results, err
	}
	defer resp.Body.Close()
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return results, err
	}
	doc.Selection.Find(viewDnsSelector).Each(func(_ int, s *goquery.Selection) {
		results = append(results, Result{Source: "viewdns.info", IP: ip, Hostname: s.Text()})
	})
	return results, nil
}

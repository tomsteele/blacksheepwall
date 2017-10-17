package bsw

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// YandexAPI uses Yandex XML API and the 'rhost' search operator to find
// subdomains of a given domain.
func YandexAPI(domain, apiURL, serverAddr string) *Tsk {
	t := newTsk("yandex API")
	xmlTemplate := "<?xml version='1.0' encoding='UTF-8'?><request><query>%s</query><sortby>rlv</sortby><maxpassages>1</maxpassages><page>0</page><groupings><groupby attr=\" \" mode=\"flat\" groups-on-page=\"100\" docs-in-group=\"1\" /></groupings></request>"

	// Split the domain and reverse the order, then rejoin it for the query.
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		t.SetErr(errors.New("Invalid domain"))
		return t
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	query := "rhost:" + strings.Join(parts, ".") + ".*"

	postBody := fmt.Sprintf(xmlTemplate, query)
	resp, err := http.Post(apiURL, "text/xml", strings.NewReader(postBody))
	if err != nil {
		t.SetErr(err)
		return t
	}
	defer resp.Body.Close()
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.SetErr(err)
		return t
	}
	domainSet := make(map[string]bool)
	doc.Find("domain").Each(func(_ int, s *goquery.Selection) {
		domain := s.Text()
		if domainSet[domain] {
			return
		}
		ips, err := LookupName(domain, serverAddr)
		if err != nil || len(ips) == 0 {
			cfqdn, err := LookupCname(domain, serverAddr)
			if err != nil || cfqdn == "" {
				return
			}
			ips, err = LookupName(cfqdn, serverAddr)
			if err != nil || len(ips) == 0 {
				return
			}
		}
		for _, ip := range ips {
			t.AddResult(ip, domain)
		}
	})
	return t
}

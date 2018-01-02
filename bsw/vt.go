package bsw

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

const virusTotalURL = "https://www.virustotal.com"

// VirusTotal searches VirusTotal for sudbomains related to a domain.
func VirusTotal(domain, serverAddr string) *Tsk {
	t := newTsk("VirusTotal")

	resp, err := http.Get(fmt.Sprintf("%s/en/domain/%s/information/", virusTotalURL, domain))
	if err != nil {
		t.SetErr(err)
		return t
	}
	doc, err := goquery.NewDocumentFromResponse(resp)
	if err != nil {
		t.SetErr(err)
		return t
	}

	doc.Selection.Find("#observed-subdomains a").Each(func(_ int, s *goquery.Selection) {
		name := strings.TrimSpace(s.Text())

		ips, err := LookupName(name, serverAddr)
		if err == nil {
			for _, ip := range ips {
				t.AddResult(ip, name)
			}
			return
		}

		ecount := 0
		cfqdn := ""
		tfqdn := name
		cfqdns := []string{}

		for {
			cfqdn, err = LookupCname(tfqdn, serverAddr)
			if err != nil {
				break
			}
			cfqdns = append(cfqdns, cfqdn)
			ips, err = LookupName(cfqdn, serverAddr)
			if err != nil {
				ecount++
				if ecount > 10 {
					break
				}
				tfqdn = cfqdn
				continue
			}
			break
		}

		for _, ip := range ips {
			t.AddResult(ip, name)
			for _, c := range cfqdns {
				t.AddResult(ip, c)
			}
		}

	})
	return t
}

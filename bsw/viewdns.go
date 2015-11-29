package bsw

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/PuerkitoBio/goquery"
)

// Very long selector...
const viewDNSSelector = "#null > tbody:nth-child(1) > tr:nth-child(3) > td:nth-child(1) > font:nth-child(1) > i:nth-child(7) > table:nth-child(4) > tbody:nth-child(1) > tr:nth-child(n+1) > td:nth-child(1)"

// ViewDNSInfo uses viewdns.info's reverseip functionality, parsing
// the HTML table for hostnames.
func ViewDNSInfo(ip string) *Tsk {
	t := newTsk("viewdns.info")
	resp, err := http.Get(fmt.Sprintf("http://viewdns.info/reverseip/?host=%s&t=1", ip))
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
	doc.Selection.Find(viewDNSSelector).Each(func(_ int, s *goquery.Selection) {
		t.AddResult(ip, s.Text())
	})
	return t
}

type viewDNSInfoMessage struct {
	Query struct {
		Tool string `json:"tool"`
		Host string `json:"host"`
	} `json:"query"`
	Response struct {
		DomainCount string `json:"domain_count"`
		Domains     []struct {
			Name         string `json:"name"`
			LastResovled string `json:"last_resolved"`
		} `json:"domains"`
	} `json:"response"`
}

// ViewDNSInfoAPI uses viewdns.iinfo's API and reverseip function to find hostnames for an ip.
func ViewDNSInfoAPI(ip, key string) *Tsk {
	t := newTsk("viewdns.info API")
	resp, err := http.Get(fmt.Sprintf("http://pro.viewdns.info/reverseip/?host=%s&apikey=%s&output=json", ip, key))
	if err != nil {
		t.SetErr(err)
		return t
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.SetErr(err)
		return t
	}
	m := &viewDNSInfoMessage{}
	if err := json.Unmarshal(body, &m); err != nil {
		t.SetErr(err)
		return t
	}

	for _, domain := range m.Response.Domains {
		t.AddResult(ip, domain.Name)
	}
	return t
}

package bsw

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/PuerkitoBio/goquery"
)

// Very long selector...
const viewDNSSelector = "#null > tbody:nth-child(1) > tr:nth-child(3) > td:nth-child(1) > font:nth-child(1) > i:nth-child(7) > table:nth-child(4) > tbody:nth-child(1) > tr:nth-child(n+1) > td:nth-child(1)"

// ViewDNSInfo uses viewdns.info's reverseip functionality, parsing
// the HTML table for hostnames.
func ViewDNSInfo(ip string) (string, Results, error) {
	task := "viewdns.info"
	results := Results{}
	resp, err := http.Get("http://viewdns.info/reverseip/?host=" + ip + "&t=1")
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
func ViewDNSInfoAPI(ip, key string) (string, Results, error) {
	task := "viewdns.info API"
	results := Results{}
	resp, err := http.Get("http://pro.viewdns.info/reverseip/?host=" + ip + "&apikey=" + key + "&output=json")
	if err != nil {
		return task, results, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return task, results, err
	}
	m := &viewDNSInfoMessage{}
	if err := json.Unmarshal(body, &m); err != nil {
		return task, results, err
	}

	for _, domain := range m.Response.Domains {
		results = append(results, Result{
			Source:   task,
			IP:       ip,
			Hostname: domain.Name,
		})
	}
	return task, results, nil
}

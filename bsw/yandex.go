package bsw

import (
	"fmt"
	"github.com/moovweb/gokogiri"
	"io/ioutil"
	"net/http"
	"strings"
)

// Uses Yandex XML API and the 'rhost' search operator to find subdomains of a
// given domain.
func YandexAPI(domain, apiUrl, serverAddr string) (Results, error) {
	results := Results{}
	var xmlTemplate = "<?xml version='1.0' encoding='UTF-8'?><request><query>%s</query><sortby>rlv</sortby><maxpassages>1</maxpassages><page>0</page><groupings><groupby attr=\" \" mode=\"flat\" groups-on-page=\"100\" docs-in-group=\"1\" /></groupings></request>"
	parts := strings.Split(domain, ".")
	var query = "rhost:" + parts[1] + "." + parts[0] + ".*"
	postBody := fmt.Sprintf(xmlTemplate, query)
	resp, err := http.Post(apiUrl, "text/xml", strings.NewReader(postBody))
	if err != nil {
		return results, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return results, err
	}
	doc, err := gokogiri.ParseXml(body)
	defer doc.Free()
	if err != nil {
		return results, nil
	}
	nodes, err := doc.Search("//domain")
	if err != nil {
		return results, nil
	}
	if len(nodes) > 0 {
		domainSet := make(map[string]bool)
		for _, node := range nodes {
			domain := node.InnerHtml()
			if domainSet[domain] {
				continue
			}
			domainSet[domain] = true
			ip, err := LookupName(domain, serverAddr)
			if err == nil {
				results = append(results, Result{Source: "Yandex API", IP: ip, Hostname: domain})
			}
		}
	}
	return results, nil
}

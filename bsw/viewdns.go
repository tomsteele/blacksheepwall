package bsw

import (
	"github.com/moovweb/gokogiri"
	"io/ioutil"
	"net/http"
)

func ViewDnsInfo(ip string) ([]Result, error) {
	results := make([]Result, 0)
	var url = "http://viewdns.info/reverseip/?host=" + ip + "&t=1"
	resp, err := http.Get(url)
	if err != nil {
		return results, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return results, err
	}
	doc, err := gokogiri.ParseHtml(body)
	defer doc.Free()
	if err != nil {
		return results, err
	}
	nodes, err := doc.Search("//table[@border=1]/tr[position() > 1]/td[1]")
	if err != nil {
		return results, err
	}
	for _, node := range nodes {
		results = append(results, Result{Source: "viewdns.info", IP: ip, Hostname: node.InnerHtml()})
	}
	return results, nil
}

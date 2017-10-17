package bsw

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/PuerkitoBio/goquery"
)

type bingMessage struct {
	D bingResults `json:"D"`
}

type bingResults struct {
	Results []bingResult `json:"Results"`
}

type bingResult struct {
	Metadata    bingMetadata `json:"__Metadata"`
	ID          string       `json:"id"`
	Title       string       `json:"Title"`
	Description string       `json:"Description"`
	DisplayURL  string       `json:"DisplayUrl"`
	URL         string       `json:"Url"`
}

type bingMetadata struct {
	URI  string `json:"Uri"`
	Type string `json:"Type"`
}

const azureURL = "https://api.datamarket.azure.com"

// FindBingSearchPath attempts an authenticated search request to two different Bing API paths. If and when a
// search is successfull, that path will be returned. If no path is valid this function
// returns an error.
func FindBingSearchPath(key string) (string, error) {
	paths := []string{"/Data.ashx/Bing/Search/v1/Web", "/Data.ashx/Bing/SearchWeb/v1/Web"}
	query := "?Query=%27I<3BSW%27"
	for _, path := range paths {
		fullURL := azureURL + path + query
		client := &http.Client{}
		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			return "", err
		}
		req.SetBasicAuth(key, key)
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		if resp.StatusCode == 200 {
			return path, nil
		}
	}
	return "", errors.New("invalid Bing API key")
}

// BingAPIIP uses the bing search API and 'ip' search operator to find alternate hostnames for
// a single IP.
func BingAPIIP(ip, key, path string) *Tsk {
	t := newTsk("bing API")
	client := &http.Client{}
	req, err := http.NewRequest("GET", azureURL+path+"?Query=%27ip:"+ip+"%27&$top=50&Adult=%27off%27&$format=json", nil)
	if err != nil {
		t.SetErr(err)
		return t
	}
	req.SetBasicAuth(key, key)
	resp, err := client.Do(req)
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
	m := &bingMessage{}
	if err = json.Unmarshal(body, &m); err != nil {
		t.SetErr(err)
		return t
	}
	for _, res := range m.D.Results {
		if u, err := url.Parse(res.URL); err == nil && u.Host != "" {
			t.AddResult(ip, u.Host)
		}
	}
	return t
}

// BingAPIDomain uses the bing search API and 'domain' search operator to find hostnames for
// a single domain.
func BingAPIDomain(domain, key, path, server string) *Tsk {
	t := newTsk("bing API")
	client := &http.Client{}
	req, err := http.NewRequest("GET", azureURL+path+"?Query=%27domain:"+domain+"%27&$top=50&Adult=%27off%27&$format=json", nil)
	if err != nil {
		t.SetErr(err)
		return t
	}
	req.SetBasicAuth(key, key)
	resp, err := client.Do(req)
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
	m := &bingMessage{}
	if err = json.Unmarshal(body, &m); err != nil {
		t.SetErr(err)
		return t
	}
	for _, res := range m.D.Results {
		u, err := url.Parse(res.URL)
		if err != nil || u.Host == "" {
			continue
		}
		ips, err := LookupName(u.Host, server)
		if err != nil || len(ips) == 0 {
			cfqdn, err := LookupCname(u.Host, server)
			if err != nil || cfqdn == "" {
				continue
			}
			ips, err = LookupName(cfqdn, server)
			if err != nil || len(ips) == 0 {
				continue
			}
		}
		for _, ip := range ips {
			t.AddResult(ip, u.Host)
		}
	}
	return t
}

// BingIP uses bing's 'ip:' search operator and scrapes the HTML to find hostnames for an ip.
func BingIP(ip string) *Tsk {
	t := newTsk("bing ip")
	resp, err := http.Get("http://www.bing.com/search?q=ip:" + ip)
	if err != nil {
		t.SetErr(err)
		return t
	}
	doc, err := goquery.NewDocumentFromResponse(resp)
	if err != nil {
		t.SetErr(err)
		return t
	}
	doc.Selection.Find("cite").Each(func(_ int, s *goquery.Selection) {
		u, err := url.Parse(s.Text())
		if err != nil || u.Host == "" {
			return
		}
		t.AddResult(ip, u.Host)
	})
	return t
}

// BingDomain uses bing's 'domain:' search operator and scrapes the HTML to find ips and hostnames for a domain.
func BingDomain(domain, server string) *Tsk {
	t := newTsk("bing domain")
	resp, err := http.Get("http://www.bing.com/search?q=domain:" + domain)
	if err != nil {
		t.SetErr(err)
		return t
	}
	doc, err := goquery.NewDocumentFromResponse(resp)
	if err != nil {
		t.SetErr(err)
		return t
	}
	doc.Selection.Find("cite").Each(func(_ int, s *goquery.Selection) {
		u, err := url.Parse(s.Text())
		if err != nil || u.Host == "" {
			return
		}
		ips, err := LookupName(u.Host, server)
		if err != nil || len(ips) == 0 {
			cfqdn, err := LookupCname(u.Host, server)
			if err != nil || cfqdn == "" {
				return
			}
			ips, err = LookupName(cfqdn, server)
			if err != nil || len(ips) == 0 {
				return
			}

		}
		for _, ip := range ips {
			t.AddResult(ip, u.Host)
		}
	})
	return t
}

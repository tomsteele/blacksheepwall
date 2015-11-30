package bsw

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

const censysURL = "https://www.censys.io/api/v1"

type censysSearchResponse struct {
	Status  string `json:"status"`
	Results []struct {
		IP string `json:"ip"`
	} `json:"results"`
	Metadata struct {
		Pages int `json:"pages"`
	} `json:"metadata"`
}

type censysViewResponse struct {
	Num443 struct {
		HTTPS struct {
			TLS struct {
				Certificate struct {
					Parsed struct {
						Extensions struct {
							SubjectAltName struct {
								DNSNames []string `json:"dns_names"`
							} `json:"subject_alt_name"`
						} `json:"extensions"`
						Subject struct {
							CommonName []string `json:"common_name"`
						} `json:"subject"`
					} `json:"parsed"`
				} `json:"certificate"`
			} `json:"tls"`
		} `json:"https"`
	} `json:"443"`
}

// CensysDomain search censys.io for a particular domain.
// After a list of IP addresses are found to be matching the domain,
// each ip in the list is looked up using the 'view' search.
// This TLS certificates for each IP, hostnames are gathers from these
// TLS certificates.
func CensysDomain(domain, auth string) *Tsk {
	t := newTsk("censys.io Domain")
	p := 1
	ips, pages, err := censysSearch(domain, auth, p)
	if err != nil {
		t.SetErr(err)
		return t
	}
	p++
	for p <= pages {
		i, _, err := censysSearch(domain, auth, p)
		if err != nil {
			t.SetErr(err)
			return t
		}
		p++
		ips = append(ips, i...)
	}
	for _, ip := range ips {
		names, err := censysView(ip, auth)
		if err != nil {
			t.SetErr(err)
			return t
		}
		for _, n := range removeDuplicates(names) {
			if ok, err := regexp.Match(DomainRegex, []byte(n)); !ok || err != nil {
				continue
			}
			if strings.Contains(n, domain) && n != domain {
				t.AddResult(ip, n)
			}
		}
	}
	return t
}

// CensysIP search an ip using censys.io's ipv4 view.
// Hostnames are extracted from previously gathered TLS certificates.
func CensysIP(ip, auth string) *Tsk {
	t := newTsk("censys.io IP search")
	names, err := censysView(ip, auth)
	if err != nil {
		t.SetErr(err)
		return t
	}
	for _, n := range removeDuplicates(names) {
		if ok, err := regexp.Match(DomainRegex, []byte(n)); ok && err == nil {
			t.AddResult(ip, n)
		}
	}
	return t
}

func censysSearch(domain, auth string, page int) ([]string, int, error) {
	buf := bytes.NewBuffer([]byte(fmt.Sprintf("{\"query\": \"%s\", \"page\": %d}", domain, page)))
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/search/ipv4", censysURL), buf)
	ips := []string{}
	if err != nil {
		return ips, 0, err
	}
	parts := strings.Split(auth, ":")
	if len(parts) != 2 {
		return ips, 0, errors.New("Invalid auth string for censys.io")
	}
	req.SetBasicAuth(parts[0], parts[1])
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return ips, 0, err
	}
	if resp.StatusCode != 200 {
		return ips, 0, errors.New("Request returned non 200 status code")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ips, 0, err
	}
	m := &censysSearchResponse{}
	if err = json.Unmarshal(body, &m); err != nil {
		return ips, 0, err
	}
	for _, r := range m.Results {
		ips = append(ips, r.IP)
	}
	return ips, m.Metadata.Pages, nil
}

func censysView(ip, auth string) ([]string, error) {
	names := []string{}
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/view/ipv4/%s", censysURL, ip), nil)
	if err != nil {
		return names, err
	}
	parts := strings.Split(auth, ":")
	if len(parts) != 2 {
		return names, errors.New("Invalid auth string for censys.io")
	}
	req.SetBasicAuth(parts[0], parts[1])
	resp, err := client.Do(req)
	if err != nil {
		return names, err
	}
	if resp.StatusCode != 200 {
		return names, errors.New("Request returned non 200 status code")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return names, err
	}
	m := &censysViewResponse{}
	if err = json.Unmarshal(body, &m); err != nil {
		return names, err
	}
	names = append(names, m.Num443.HTTPS.TLS.Certificate.Parsed.Extensions.SubjectAltName.DNSNames...)
	names = append(names, m.Num443.HTTPS.TLS.Certificate.Parsed.Subject.CommonName...)
	return names, nil
}

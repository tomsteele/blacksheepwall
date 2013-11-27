package bsw

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"regexp"
)

func Headers(ip string) ([]Result, error) {
	results := make([]Result, 0, 2)
	host, _ := hostnameFromHttpLocationHeader(ip, "http")
	if host != "" {
		results = append(results, Result{Source: "Headers", IP: ip, Hostname: host})
	}
	host, _ = hostnameFromHttpLocationHeader(ip, "https")
	if host != "" {
		results = append(results, Result{Source: "Headers", IP: ip, Hostname: host})
	}
	return results, nil
}

func hostnameFromHttpLocationHeader(ip string, protocol string) (string, error) {
	req, err := http.NewRequest("GET", protocol+"://"+ip, nil)
	if err != nil {
		return "", err
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	res, err := tr.RoundTrip(req)
	if err != nil {
		return "", err
	}
	location := res.Header["Location"]
	if location != nil {
		u, err := url.Parse(location[0])
		if err != nil {
			return "", err
		}
		host := u.Host
		if m, _ := regexp.Match("[a-zA-Z]+", []byte(host)); m == true {
			return host, nil
		}
		return "", nil
	}
	return "", nil
}

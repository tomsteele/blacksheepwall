package bsw

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"regexp"
)

func Headers(ip string) ([]Result, error) {
	results := []Result{}
	for _, proto := range []string{"http", "https"} {
		if host := hostnameFromHttpLocationHeader(ip, proto); host != "" {
			results = append(results, Result{Source: "Headers", IP: ip, Hostname: host})
		}
	}
	return results, nil
}

func hostnameFromHttpLocationHeader(ip string, protocol string) string {
	req, err := http.NewRequest("GET", protocol+"://"+ip, nil)
	if err != nil {
		return ""
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	res, err := tr.RoundTrip(req)
	if err != nil {
		return ""
	}
	location := res.Header["Location"]
	if location != nil {
		u, err := url.Parse(location[0])
		if err != nil {
			return ""
		}
		host := u.Host
		if m, _ := regexp.Match("[a-zA-Z]+", []byte(host)); m == true {
			return host
		}
		return ""
	}
	return ""
}

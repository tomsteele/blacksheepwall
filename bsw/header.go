package bsw

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

// Using http(s), attempt to connect to an IP. If connection is successfull return any hostnames from the possible
// 'Location' headers.
func Headers(ip string) (Results, error) {
	results := []Result{}
	for _, proto := range []string{"http", "https"} {
		if host := hostnameFromHttpLocationHeader(ip, proto); host != "" {
			results = append(results, Result{Source: "Headers", IP: ip, Hostname: host})
		}
	}
	return results, nil
}

// Performs http(s) request and parses possible 'Location' headers.
func hostnameFromHttpLocationHeader(ip, protocol string) string {
	req, err := http.NewRequest("GET", protocol+"://"+ip, nil)
	if err != nil {
		return ""
	}
	tr := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, time.Duration(1*time.Second))
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
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

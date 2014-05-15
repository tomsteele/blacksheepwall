package bsw

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"time"
	"fmt"
)

// Headers uses attempts to connect to IP over http(s). If connection is successfull return any hostnames from the possible
// 'Location' headers.
func Headers(ip string, timeout int64) (string, Results, error) {
	task := "Headers"
	results := []Result{}
	for _, proto := range []string{"http", "https"} {
		host, err := hostnameFromHTTPLocationHeader(ip, proto, timeout)
		if err != nil {
			return task, results, err
		} else if host != "" {
			results = append(results, Result{Source: task, IP: ip, Hostname: host})
		}
	}
	return task, results, nil
}

// Performs http(s) request and parses possible 'Location' headers.
func hostnameFromHTTPLocationHeader(ip, protocol string, timeout int64) (string, error) {
	req, err := http.NewRequest("GET", protocol+"://"+ip, nil)
	if err != nil {
		return "", err
	}
	tr := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, time.Duration(timeout)*time.Millisecond)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
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
		return "", fmt.Errorf("%v: unsuccessful header match", ip)
	}
	return "", fmt.Errorf("%v: unsuccessful header match", ip)
}

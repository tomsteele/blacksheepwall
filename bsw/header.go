package bsw

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

// Headers uses attempts to connect to IP over http(s).
// If connection is successfull return any hostnames from the possible 'Location' headers.
func Headers(ip string, timeout int64) *Tsk {
	t := newTsk("Headers")
	for _, proto := range []string{"http", "https"} {
		host, err := hostnameFromHTTPLocationHeader(ip, proto, timeout)
		if err != nil {
			t.SetErr(err)
		} else if host != "" {
			t.AddResult(ip, host)
		}
	}
	return t
}

// Performs http(s) request and parses possible 'Location' headers.
func hostnameFromHTTPLocationHeader(ip, protocol string, timeout int64) (string, error) {
	req, err := http.NewRequest("GET", protocol+"://"+ip, nil)
	if err != nil {
		return "", err
	}
	tr := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			conn, err := net.DialTimeout(network, addr, time.Duration(timeout)*time.Millisecond)
			if err != nil {
				return nil, err
			}
			conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))
			return conn, nil
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

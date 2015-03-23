package bsw

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// Robtex looks up a host at robtex.com.
func Robtex(ip string) (string, Results, error) {
	task := "robtex.com"
	results := Results{}
	resp, err := http.Get("http://www.robtex.com/ip/" + ip + ".html")
	if err != nil {
		return task, results, err
	}
	defer resp.Body.Close()
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return task, results, err
	}
	doc.Selection.Find("#x_summary td:nth-child(1)").Each(func(_ int, s *goquery.Selection) {
		hostname := s.Text()
		if strings.Contains(hostname, "*") {
			return
		}
		if hostname == "." {
			return
		}
		if _, err := strconv.Atoi(hostname); err == nil {
			return
		}
		results = append(results, Result{Source: task, IP: ip, Hostname: s.Text()})
	})
	return task, results, nil
}

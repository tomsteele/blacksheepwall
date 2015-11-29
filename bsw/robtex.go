package bsw

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// Robtex looks up a host at robtex.com.
func Robtex(ip string) *Tsk {
	t := newTsk("robtex.com")
	resp, err := http.Get(fmt.Sprintf("http://www.robtex.com/ip/%s.html", ip))
	if err != nil {
		t.SetErr(err)
		return t
	}
	defer resp.Body.Close()
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.SetErr(err)
		return t
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
		t.AddResult(ip, s.Text())
	})
	return t
}

package bsw

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/PuerkitoBio/goquery"
)

// GoogleCT searches https://transparencyreport.google.com
// for a list of certificates.
func GoogleCT(domain string) *Tsk {
	t := newTsk("Google CT")
	t.SetErr(errors.New("not implemented"))
	return t
}

const crtshURL = "https://crt.sh"

// CRTSHCT searches https://crt.sh for a list of
// certificates
func CRTSHCT(domain, serverAddr string) *Tsk {
	t := newTsk("CRT.SH CT")
	resp, err := http.Get(fmt.Sprintf("%s/?q=%s", crtshURL, domain))
	if err != nil {
		t.SetErr(err)
		return t
	}
	doc, err := goquery.NewDocumentFromResponse(resp)
	if err != nil {
		t.SetErr(err)
		return t
	}
	doc.Selection.Find("td:nth-child(1) a").Each(func(_ int, s *goquery.Selection) {
		id := s.Text()
		certresp, err := http.Get(fmt.Sprintf("%s/?d=%s", crtshURL, id))
		if err != nil {
			return
		}
		data, err := ioutil.ReadAll(certresp.Body)
		if err != nil {
			return
		}
		certresp.Body.Close()
		block, _ := pem.Decode(data)
		if block == nil {
			return
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return
		}

		names := append(cert.DNSNames, cert.Subject.CommonName)

		var wg sync.WaitGroup
		var mutex sync.Mutex

		for _, n := range names {
			wg.Add(1)

			go func(name string) {
				defer wg.Done()
				ips, err := LookupName(name, serverAddr)
				if err == nil {
					mutex.Lock()
					for _, ip := range ips {
						t.AddResult(ip, name)
					}
					mutex.Unlock()
					return
				}

				ecount := 0
				cfqdn := ""
				tfqdn := name
				cfqdns := []string{}

				for {
					cfqdn, err = LookupCname(tfqdn, serverAddr)
					if err != nil {
						break
					}
					cfqdns = append(cfqdns, cfqdn)
					ips, err = LookupName(cfqdn, serverAddr)
					if err != nil {
						ecount++
						if ecount > 10 {
							break
						}
						tfqdn = cfqdn
						continue
					}
					break
				}

				mutex.Lock()
				for _, ip := range ips {
					t.AddResult(ip, name)
					for _, c := range cfqdns {
						t.AddResult(ip, c)
					}
				}
				mutex.Unlock()
			}(n)
		}
		wg.Wait()
	})
	return t
}

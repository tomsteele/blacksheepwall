package bsw

import (
	"strings"

	"github.com/miekg/dns"
)

// AXFR attempts a zone transfer for the domain.
func AXFR(domain, serverAddr string) (string, Results, error) {
	task := "axfr"
	results := Results{}

	servers, err := LookupNS(domain, serverAddr)
	if err != nil {
		return task, results, err
	}

	for _, s := range servers {
		tr := dns.Transfer{}
		m := &dns.Msg{}
		m.SetAxfr(dns.Fqdn(domain))
		in, err := tr.In(m, s+":53")
		if err != nil {
			return task, results, err
		}
		for ex := range in {
			for _, a := range ex.RR {
				var ip, hostname string
				switch v := a.(type) {
				case *dns.A:
					ip = v.A.String()
					hostname = v.Hdr.Name
				case *dns.AAAA:
					ip = v.AAAA.String()
					hostname = v.Hdr.Name
				case *dns.PTR:
					ip = v.Hdr.Name
					hostname = v.Ptr
				case *dns.NS:
					cip, err := LookupName(v.Ns, serverAddr)
					if err != nil || cip == "" {
						continue
					}
					ip = cip
					hostname = v.Ns
				case *dns.CNAME:
					cip, err := LookupName(v.Target, serverAddr)
					if err != nil || cip == "" {
						continue
					}
					hostname = v.Hdr.Name
					ip = cip
				case *dns.SRV:
					cip, err := LookupName(v.Target, serverAddr)
					if err != nil || ip == "" {
						continue
					}
					ip = cip
					hostname = v.Target
				default:
					continue
				}
				results = append(results, Result{
					Source:   task,
					IP:       ip,
					Hostname: strings.TrimRight(hostname, "."),
				})
			}
		}
	}
	return task, results, nil
}

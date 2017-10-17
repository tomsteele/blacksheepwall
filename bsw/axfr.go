package bsw

import (
	"strings"

	"github.com/miekg/dns"
)

// AXFR attempts a zone transfer for the domain.
func AXFR(domain, serverAddr string) *Tsk {
	t := newTsk("axfr")
	servers, err := LookupNS(domain, serverAddr)
	if err != nil {
		t.SetErr(err)
		return t
	}

	for _, s := range servers {
		tr := dns.Transfer{}
		m := &dns.Msg{}
		m.SetAxfr(dns.Fqdn(domain))
		in, err := tr.In(m, s+":53")
		if err != nil {
			t.SetErr(err)
			return t
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
					if err != nil || len(cip) == 0 {
						continue
					}
					ip = cip[0]
					hostname = v.Ns
				case *dns.CNAME:
					cip, err := LookupName(v.Target, serverAddr)
					if err != nil || len(cip) == 0 {
						continue
					}
					hostname = v.Hdr.Name
					ip = cip[0]
				case *dns.SRV:
					cip, err := LookupName(v.Target, serverAddr)
					if err != nil || len(cip) == 0 {
						continue
					}
					ip = cip[0]
					hostname = v.Target
				default:
					continue
				}
				t.AddResult(ip, strings.TrimRight(hostname, "."))
			}
		}
	}
	return t
}

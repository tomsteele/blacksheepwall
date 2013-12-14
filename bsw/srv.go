package bsw

import (
	"errors"
	"github.com/miekg/dns"
)

func LookupSRV(domain, dnsServer string) (Results, error) {
	results := []Result{}
	srvrcdarr := [...]string{"_gc._tcp.", "_kerberos._tcp.", "_kerberos._udp.", "_ldap._tcp.",
		"_test._tcp.", "_sips._tcp.", "_sip._udp.", "_sip._tcp.", "_aix._tcp.",
		"_aix._tcp.", "_finger._tcp.", "_ftp._tcp.", "_http._tcp.", "_nntp._tcp.",
		"_telnet._tcp.", "_whois._tcp.", "_h323cs._tcp.", "_h323cs._udp.",
		"_h323be._tcp.", "_h323be._udp.", "_h323ls._tcp.", "_https._tcp.",
		"_h323ls._udp.", "_sipinternal._tcp.", "_sipinternaltls._tcp.",
		"_sip._tls.", "_sipfederationtls._tcp.", "_jabber._tcp.",
		"_xmpp-server._tcp.", "_xmpp-client._tcp.", "_imap.tcp.",
		"_certificates._tcp.", "_crls._tcp.", "_pgpkeys._tcp.",
		"_pgprevokations._tcp.", "_cmp._tcp.", "_svcp._tcp.", "_crl._tcp.",
		"_ocsp._tcp.", "_PKIXREP._tcp.", "_smtp._tcp.", "_hkp._tcp.",
		"_hkps._tcp.", "_jabber._udp.", "_xmpp-server._udp.", "_xmpp-client._udp.",
		"_jabber-client._tcp.", "_jabber-client._udp.", "_kpasswd._tcp.", "_kpasswd._udp.",
		"_imap._tcp."}

	for _, value := range srvrcdarr {
		fqdn := value + domain
		srvTarget, _ := MakeSRVRequest(fqdn, dnsServer)
		if len(srvTarget) > 0 {
			ip, _ := LookupFQDN(srvTarget, dnsServer)
			results = append(results, Result{Source: "SRV", IP: ip, Hostname: srvTarget})
		}

	}
	return results, nil
}

func MakeSRVRequest(fqdn, dnsServer string) (string, error) {
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeSRV)
	in, err := dns.Exchange(m, dnsServer+":53")
	if err != nil {
		return "", err
	}
	if len(in.Answer) < 1 {
		return "", errors.New("No Answer")
	}
	if a, ok := in.Answer[0].(*dns.SRV); ok {
		return a.Target, nil
	} else {
		return "", errors.New("No SRV record returned")
	}
}

func LookupFQDN(fqdn, dnsServer string) (string, error) {
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	in, err := dns.Exchange(m, dnsServer+":53")
	if err != nil {
		return "", err
	}
	if len(in.Answer) < 1 {
		return "", errors.New("No Answer")
	}
	if a, ok := in.Answer[0].(*dns.A); ok {
		ip := a.A.String()
		return ip, nil
	} else {
		return "", errors.New("No A record returned")
	}
}

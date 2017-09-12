package bsw

// SRV iterates over a list of common SRV records, returning hostname and IP results for each.
func SRV(domain, dnsServer string) *Tsk {
	t := newTsk("SRV")
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
		srvTarget, err := LookupSRV(fqdn, dnsServer)
		if err != nil {
			continue
		}
		ips, err := LookupName(srvTarget, dnsServer)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			t.AddResult(ip, srvTarget)
		}
	}
	return t
}

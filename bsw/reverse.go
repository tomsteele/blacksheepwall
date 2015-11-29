package bsw

// Reverse uses LookupIP to get PTR record for an IP.
func Reverse(ip, serverAddr string) *Tsk {
	t := newTsk("Reverse")
	hostname, err := LookupIP(ip, serverAddr)
	if err != nil {
		t.SetErr(err)
		return t
	}
	for _, host := range hostname {
		t.AddResult(ip, host)
	}
	return t
}

package bsw

// Reverse uses LookupIP to get PTR record for an IP.
func Reverse(ip, serverAddr string) (Results, error) {
	results := Results{}
	hostname, err := LookupIP(ip, serverAddr)
	if err != nil {
		return results, err
	}
    for _, host := range hostname {
	   results = append(results, Result{Source: "Reverse", IP: ip, Hostname: host})
    }
	return results, nil
}

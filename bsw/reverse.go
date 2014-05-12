package bsw

// Reverse uses LookupIP to get PTR record for an IP.
func Reverse(ip, serverAddr string) (Results, error) {
    errtask := []Result{Result{Source: "Reverse"}}
	results := Results{}
	hostname, err := LookupIP(ip, serverAddr)
	if err != nil {
		return errtask, err
	}
    for _, host := range hostname {
	   results = append(results, Result{Source: "Reverse", IP: ip, Hostname: host})
    }
	return results, nil
}

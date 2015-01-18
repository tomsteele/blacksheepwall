package bsw

// Reverse uses LookupIP to get PTR record for an IP.
func Reverse(ip, serverAddr string) (string, Results, error) {
	task := "Reverse"
	results := Results{}
	hostname, err := LookupIP(ip, serverAddr)
	if err != nil {
		return task, results, err
	}
	for _, host := range hostname {
		results = append(results, Result{Source: task, IP: ip, Hostname: host})
	}
	return task, results, nil
}

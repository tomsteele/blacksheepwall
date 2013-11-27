package bsw

func Reverse(ip, serverAddr string) ([]Result, error) {
	results := make([]Result, 1)
	hostname, err := LookupIP(ip, serverAddr)
	if err != nil {
		return results, err
	}
	results[0] = Result{Source: "Reverse", IP: ip, Hostname: hostname}
	return results, nil
}

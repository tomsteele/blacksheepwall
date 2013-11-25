package bsw

func Reverse(ip string, serverAddr string) ([]Result, error) {
	results := make([]Result, 1)
	hostname, err := LookupIP(ip, serverAddr)
	if err != nil {
		return results, err
	}
	results[0] = Result{Source: "Reverse", IPAddress: ip, Hostname: hostname}
	return results, nil
}

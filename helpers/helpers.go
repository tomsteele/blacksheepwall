package helpers

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// LinesToIPList processes a list of IP addresses or networks in CIDR format.
// Returning a list of all possible IP addresses.
func LinesToIPList(lines []string) ([]string, error) {
	ipList := []string{}
	for _, line := range lines {
		if net.ParseIP(line) != nil {
			ipList = append(ipList, line)
		} else if ip, network, err := net.ParseCIDR(line); err == nil {
			for ip := ip.Mask(network.Mask); network.Contains(ip); increaseIP(ip) {
				ipList = append(ipList, ip.String())
			}
		} else if strings.Contains(line, "-") {
			splitIP := strings.SplitN(line, "-", 2)
			ip := net.ParseIP(splitIP[0])
			endIP := net.ParseIP(splitIP[1])
			if endIP != nil {
				if !isStartingIPLower(ip, endIP) {
					return ipList, fmt.Errorf("%s is greater than %s", ip.String(), endIP.String())
				}
				ipList = append(ipList, ip.String())
				for !ip.Equal(endIP) {
					increaseIP(ip)
					ipList = append(ipList, ip.String())
				}
			} else {
				ipOct := strings.SplitN(ip.String(), ".", 4)
				endIP := net.ParseIP(ipOct[0] + "." + ipOct[1] + "." + ipOct[2] + "." + splitIP[1])
				if endIP != nil {
					if !isStartingIPLower(ip, endIP) {
						return ipList, fmt.Errorf("%s is greater than %s", ip.String(), endIP.String())
					}
					ipList = append(ipList, ip.String())
					for !ip.Equal(endIP) {
						increaseIP(ip)
						ipList = append(ipList, ip.String())
					}
				} else {
					return ipList, fmt.Errorf("%s is not an IP Address or CIDR Network", line)
				}
			}
		} else {
			return ipList, fmt.Errorf("%s is not an IP Address or CIDR Network", line)
		}
	}
	return ipList, nil
}

// increases an IP by a single address.
func increaseIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isStartingIPLower(start, end net.IP) bool {
	if len(start) != len(end) {
		return false
	}
	for i := range start {
		if start[i] > end[i] {
			return false
		}
	}
	return true
}

// ReadFileLines returns all the lines in a file.
func ReadFileLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	lines := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if scanner.Text() == "" {
			continue
		}
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/tomsteele/blacksheepwall/bsw"
	"log"
	"net"
	"os"
	"runtime"
)

var usage = `
  Usage: blacksheepwall [options] <ip address or CIDR>

  Options:
  -h, --help            Show Usage and exit.
  -version              Show version and exit.
  -debug                Enable debugging and show errors returned from tasks.
  -concurrency <int>    Max amount of concurrent tasks.    [default: 100]
  -cpus <int>           Max amount of cpus  for the go runtime.    [default: runtime.NumCPU()]
  -server <string>      DNS server address.    [default: "8.8.8.8"]
  -input <string>       Line separated file of networks (CIDR) or 
                        IP Addresses.
  -ipv6	                Look for additional AAAA records where applicable.
  -domain <string>      Target domain to use for certain tasks.
  -dictionary <string>  Attempt to retrieve the CNAME and A record for
                        each subdomain in the line separated file.
  -yandex <string>      Provided a Yandex search XML API url. Use the Yandex 
                        search 'rhost:' operator to find subdomains of a 
                        provided domain..
  -bing	<string>        Provided a base64 encoded API key. Use the Bing search
                        API's 'ip:' operator to lookup hostnames for each host.
  -headers              Perform HTTP(s) requests to each host and look for 
                        hostnames in a possible Location header.
  -reverse              Retrieve the PTR for each host.
  -tls                  Attempt to retrieve names from TLS certificates 
                        (CommonName and Subject Alternative Name).
  -viewdns              Lookup each host using viewdns.info's Reverse IP
                        Lookup function.
  -fcrdns               Verify results by attempting to retrieve the A or AAAA record for
                        each result previously identified hostname.
  -clean                Print results as unique hostnames for each host.
  -csv                  Print results in csv format.
  -json                 Print results as JSON.

`

func linesToIpList(lines []string) ([]string, error) {
	ipList := make([]string, 0)
	for _, line := range lines {
		if net.ParseIP(line) != nil {
			ipList = append(ipList, line)
		} else if ip, network, err := net.ParseCIDR(line); err == nil {
			for ip := ip.Mask(network.Mask); network.Contains(ip); increaseIp(ip) {
				ipList = append(ipList, ip.String())
			}
		} else {
			return ipList, errors.New("\"" + line + "\" is not an IP Address or CIDR Network")
		}
	}
	return ipList, nil
}

func increaseIp(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func readFileLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	lines := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func setMaxProcs(cpus int) {
	if cpus < 1 {
		log.Fatal("-cpus must be atleast 1")
	}
	if cpus > runtime.NumCPU() {
		log.Fatal("-cpus count too high")
	}
	runtime.GOMAXPROCS(cpus)
}

type task func() ([]bsw.Result, error)
type empty struct{}

func main() {
	var flVersion = flag.Bool("version", false, "Show version and exit.")
	var flConcurrency = flag.Int("concurrency", 100, "Max amount of concurrent tasks.")
	var flCpus = flag.Int("cpus", runtime.NumCPU(), "Max amount of cpus  for the go runtime.")
	var flDebug = flag.Bool("debug", false, "Enable debugging and show errors returned from tasks.")
	var flipv6 = flag.Bool("ipv6", false, "Look for AAAA records where applicable.")
	var flServerAddr = flag.String("server", "8.8.8.8", "DNS server address.")
	var flIpFile = flag.String("input", "", "Line separated file of networks (CIDR) or IP Addresses.")
	var flReverse = flag.Bool("reverse", false, "Retrieve the PTR for each host.")
	var flHeader = flag.Bool("headers", false, "Perform HTTP(s) requests to each host and look for hostnames in a possible Location header.")
	var flTLS = flag.Bool("tls", false, "Attempt to retrieve names from TLS certificates (CommonName and Subject Alternative Name).")
	var flViewDnsInfo = flag.Bool("viewdns", false, "Lookup each host using viewdns.info's Reverse IP Lookup function.")
	var flBing = flag.String("bing", "", "Provided a base64 encoded API key. Use the Bing search API's 'ip:' operator to lookup hostnames for each host.")
	var flYandex = flag.String("yandex", "", "Provided a Yandex search XML API url. Use the Yandex search 'rhost:' operator to find subdomains of a provided domain..")
	var flDomain = flag.String("domain", "", "Target domain to use for certain tasks.")
	var flDictFile = flag.String("dictionary", "", "Attempt to retrieve the CNAME and A record for each subdomain in the line separated file.")
	var flFcrdns = flag.Bool("fcrdns", false, "Verify results by attempting to retrieve the A or AAAA record for each result previously identified hostname.")
	var flClean = flag.Bool("clean", false, "Print results as unique hostnames for each host.")
	var flCsv = flag.Bool("csv", false, "Print results in csv format.")
	var flJson = flag.Bool("json", false, "Print results as JSON.")
	flag.Usage = func() { fmt.Print(usage) }
	flag.Parse()

	if *flVersion {
		fmt.Println("blacksheepwall version ", bsw.VERSION)
		os.Exit(0)
	}

	setMaxProcs(*flCpus)

	ipAddrList := make([]string, 0)
	var flNetwork = ""
	if *flIpFile == "" && *flDomain == "" && len(flag.Args()) < 1 {
		log.Fatal("You didn't provide any work for me to do")
	}
	if *flYandex != "" && *flDomain == "" {
		log.Fatal("Yandex API requires domain set with -domain")
	}
	if *flDictFile != "" && *flDomain == "" {
		log.Fatal("Dictionary lookup requires domain set with -domain")
	}
	if *flDomain != "" && *flYandex == "" && *flDictFile == "" {
		log.Fatal("-domain provided but no methods provided that use it")
	}
	if len(flag.Args()) > 0 {
		flNetwork = flag.Arg(0)
		list, err := linesToIpList([]string{flNetwork})
		if err != nil {
			log.Fatal(err.Error())
		}
		ipAddrList = append(ipAddrList, list...)
	}
	if *flIpFile != "" {
		lines, err := readFileLines(*flIpFile)
		if err != nil {
			log.Fatal("Error reading " + *flIpFile + " " + err.Error())
		}
		list, err := linesToIpList(lines)
		if err != nil {
			log.Fatal(err.Error())
		}
		ipAddrList = append(ipAddrList, list...)
	}
	tracker := make(chan empty)
	res := make(chan []bsw.Result)
	tasks := make(chan task)
	log.Printf("Spreading tasks across %d goroutines", *flConcurrency)
	for i := 0; i < *flConcurrency; i++ {
		go func() {
			var c = 0
			for def := range tasks {
				result, err := def()
				if m := c % 2; m == 0 {
					c = 3
					os.Stderr.WriteString("\rWorking \\")
				} else {
					c = 2
					os.Stderr.WriteString("\rWorking /")
				}
				if err != nil && *flDebug {
					log.Println(err.Error())
				}
				if err == nil {
					res <- result
				}
			}
			e := empty{}
			tracker <- e
		}()
	}

	results := make([]bsw.Result, 0)
	go func() {
		for result := range res {
			if len(result) < 1 {
				continue
			}
			if *flFcrdns {
				for _, r := range result {
					ip, err := bsw.LookupName(r.Hostname, *flServerAddr)
					if err == nil && len(ip) > 0 {
						results = append(results, bsw.Result{Source: "fcrdns", IP: ip, Hostname: r.Hostname})
					}
					ip, err = bsw.LookupName6(r.Hostname, *flServerAddr)
					if err == nil && len(ip) > 0 {
						results = append(results, bsw.Result{Source: "fcrdns", IP: ip, Hostname: r.Hostname})
					}
				}
			} else {
				results = append(results, result...)
			}
		}
		e := empty{}
		tracker <- e
	}()

	var bingPath string
	if *flBing != "" {
		p, err := bsw.FindBingSearchPath(*flBing)
		if err != nil {
			log.Fatal(err.Error())
		}
		bingPath = p
	}

	for _, h := range ipAddrList {
		host := h
		if *flReverse {
			tasks <- func() ([]bsw.Result, error) {
				return bsw.Reverse(host, *flServerAddr)
			}
		}
		if *flTLS {
			tasks <- func() ([]bsw.Result, error) {
				return bsw.TLS(host)
			}
		}
		if *flViewDnsInfo {
			tasks <- func() ([]bsw.Result, error) {
				return bsw.ViewDnsInfo(host)
			}
		}
		if *flBing != "" && bingPath != "" {
			tasks <- func() ([]bsw.Result, error) {
				return bsw.BingAPI(host, *flBing, bingPath)
			}
		}
		if *flHeader {
			tasks <- func() ([]bsw.Result, error) {
				return bsw.Headers(host)
			}
		}

	}

	if *flDictFile != "" && *flDomain != "" {
		nameList, err := readFileLines(*flDictFile)
		if err != nil {
			log.Fatal("Error reading " + *flDictFile + " " + err.Error())
		}
		blacklist := bsw.GetWildCard(*flDomain, *flServerAddr)
		var blacklist6 = ""
		if *flipv6 {
			blacklist6 = bsw.GetWildCard6(*flDomain, *flServerAddr)
		}
		for _, n := range nameList {
			sub := n
			tasks <- func() ([]bsw.Result, error) {
				return bsw.Dictionary(*flDomain, sub, blacklist, *flServerAddr)
			}
			if *flipv6 {
				tasks <- func() ([]bsw.Result, error) {
					return bsw.Dictionary6(*flDomain, sub, blacklist6, *flServerAddr)
				}
			}
		}
	}

	if *flYandex != "" && *flDomain != "" {
		tasks <- func() ([]bsw.Result, error) {
			return bsw.YandexAPI(*flDomain, *flYandex, *flServerAddr)
		}
	}

	close(tasks)
	for i := 0; i < *flConcurrency; i++ {
		<-tracker
	}
	close(res)
	<-tracker

	os.Stderr.WriteString("\r")
	log.Println("All tasks completed")
	fmt.Println()

	if *flJson {
		j, _ := json.MarshalIndent(results, "", "    ")
		fmt.Println(string(j))
	} else if *flCsv {
		for _, r := range results {
			fmt.Printf("%s,%s,%s\n", r.Hostname, r.IP, r.Source)
		}
	} else if *flClean {
		cleanSet := make(map[string][]string)
		for _, r := range results {
			cleanSet[r.Hostname] = append(cleanSet[r.Hostname], r.IP)
		}
		for k, v := range cleanSet {
			fmt.Printf("%s:\n", k)
			for _, ip := range v {
				fmt.Printf("\t%s\n", ip)
			}
		}
	} else {
		for _, r := range results {
			fmt.Printf("Hostname: %s IP: %s Source: %s\n", r.Hostname, r.IP, r.Source)
		}
	}
}

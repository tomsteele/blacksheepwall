/*blacksheepwall is a hostname reconnaissance tool, it is similar to other
tools, but has a focus on speed.*/

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/tomsteele/blacksheepwall/bsw"
	"github.com/tomsteele/blacksheepwall/helpers"
)

const usage = `
 Usage: blacksheepwall [options] <ip address or CIDR>

 Options:
  -h, --help            Show Usage and exit.

  -version              Show version and exit.

  -debug                Enable debugging and show errors returned from tasks.

  -config               Location of a YAML file containing any of the options below.
                        Hypens should be replaced with underscores (e.g. bing-html, bing_html).
                        Options that do not take an argument are booleans and should be represented
                        using true/false (e.g. bing_html: true).

  -timeout              Maximum timeout in seconds for SOCKET connections.  [default .5 seconds]

  -concurrency <int>    Max amount of concurrent tasks.  [default: 100]

  -server <string>      DNS server address.  [default: "8.8.8.8"]

  -input <string>       Line separated file of networks (CIDR) or IP Addresses.

  -ipv6                 Look for additional AAAA records where applicable.

  -domain <string>      Target domain to use for certain tasks, can be a single
                        domain or a file of line separated domains.

  -fcrdns               Verify results by attempting to retrieve the A or AAAA record for
                        each result previously identified hostname.

  -parse <string>       Generate output by parsing JSON from a file from a previous scan.

  -validate             Validate hostnames using a RFC compliant regex.

 Passive:
  -dictionary <string>  Attempt to retrieve the CNAME and A record for
                        each subdomain in the line separated file.

  -ns                   Lookup the ip and hostname of any nameservers for the domain.

  -mx                   Lookup the ip and hostmame of any mx records for the domain.

  -yandex <string>      Provided a Yandex search XML API url. Use the Yandex
                        search 'rhost:' operator to find subdomains of a
                        provided domain.

  -bing <string>        Provided a base64 encoded API key. Use the Bing search
                        API's 'ip:' operator to lookup hostnames for each ip, and the
                        'domain:' operator to find ips/hostnames for a domain.

  -bing-html            Use Bing search 'ip:' operator to lookup hostname for each ip, and the
                        'domain:' operator to find ips/hostnames for a domain. Only
                        the first page is scraped. This does not use the API.

  -shodan <string>      Provided a Shodan API key. Use Shodan's API '/dns/reverse' to lookup hostnames for
                        each ip, and '/shodan/host/search' to lookup ips/hostnames for a domain.
                        A single call is made for all ips.

  -reverse              Retrieve the PTR for each host.

  -viewdns-html         Lookup each host using viewdns.info's Reverse IP
                        Lookup function. Use sparingly as they will block you.

  -viewdns <string>     Lookup each host using viewdns.info's API and Reverse IP Lookup function.

  -logontube            Lookup each host and/or domain using logontube.com's API. As of this release
                        the site is down.

  -exfiltrated          Lookup hostnames returned from exfiltrated.com's hostname search.

  -censys <string>      Searches censys.io for a domain. Names are gathered from TLS certificates for each host
                        returned from this search. The provided string should be your API ID and Secret separated
						by a colon.

  -crtsh                Searches crt.sh for certificates related to the provided domain.
  
  -vt                   Searches VirusTotal for subdomains for the provided domain.

  -srv                  Find DNS SRV record and retrieve associated hostname/IP info.

  -cmn-crawl <string>   Search commoncrawl.org for subdomains of a domain. The provided argument should be the index
                        to be used. For example: "CC-MAIN-2017-04-index"

 Active:
  -axfr                 Attempt a zone transfer on the domain.

  -headers              Perform HTTP(s) requests to each host and look for
                        hostnames in a possible Location header.

  -tls                  Attempt to retrieve names from TLS certificates
                        (CommonName and Subject Alternative Name).

 Output Options:
  -clean                Print results as unique hostnames for each host.
  -csv                  Print results in csv format.
  -json                 Print results as JSON.

`

func readDataAndOutput(path string, ojson, ocsv, oclean bool) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal("Error reading file provided to -parse")
	}
	r := bsw.Results{}
	if err := json.Unmarshal(data, &r); err != nil {
		log.Fatal("Error parsing JSON from file provided to -parse")
	}
	output(r, ojson, ocsv, oclean)
}

func output(results bsw.Results, ojson, ocsv, oclean bool) {
	switch {
	case ojson:
		j, _ := json.MarshalIndent(results, "", "    ")
		fmt.Println(string(j))
	case ocsv:
		for _, r := range results {
			fmt.Printf("%s,%s,%s\n", r.Hostname, r.IP, r.Source)
		}
	case oclean:
		cleanSet := make(map[string][]string)
		for _, r := range results {
			cleanSet[r.IP] = append(cleanSet[r.IP], r.Hostname)
		}
		for k, v := range cleanSet {
			fmt.Printf("%s:\n", k)
			for _, h := range v {
				fmt.Printf("\t%s\n", h)
			}
		}
	default:
		w := tabwriter.NewWriter(os.Stdout, 0, 8, 4, ' ', 0)
		fmt.Fprintln(w, "IP\tHostname\tSource")
		for _, r := range results {
			fmt.Fprintf(w, "%s\t%s\t%s\n", r.IP, r.Hostname, r.Source)
		}
		w.Flush()
	}
}

type task func() *bsw.Tsk
type empty struct{}

func main() {
	// Command line options. For usage information see the
	// usage variable above.
	var (
		flVersion        = flag.Bool("version", false, "")
		flTimeout        = flag.Int64("timeout", 600, "")
		flConcurrency    = flag.Int("concurrency", 100, "")
		flDebug          = flag.Bool("debug", false, "")
		flValidate       = flag.Bool("validate", false, "")
		flConfig         = flag.String("config", "", "")
		flipv6           = flag.Bool("ipv6", false, "")
		flServerAddr     = flag.String("server", "8.8.8.8", "")
		flIPFile         = flag.String("input", "", "")
		flParse          = flag.String("parse", "", "")
		flReverse        = flag.Bool("reverse", false, "")
		flHeader         = flag.Bool("headers", false, "")
		flTLS            = flag.Bool("tls", false, "")
		flAXFR           = flag.Bool("axfr", false, "")
		flMX             = flag.Bool("mx", false, "")
		flNS             = flag.Bool("ns", false, "")
		flViewDNSInfo    = flag.Bool("viewdns-html", false, "")
		flViewDNSInfoAPI = flag.String("viewdns", "", "")
		flLogonTube      = flag.Bool("logontube", false, "")
		flCommonCrawl    = flag.String("cmn-crawl", "", "")
		flSRV            = flag.Bool("srv", false, "")
		flCRTSH          = flag.Bool("crtsh", false, "")
		flVT             = flag.Bool("vt", false, "")
		flBing           = flag.String("bing", "", "")
		flShodan         = flag.String("shodan", "", "")
		flCensys         = flag.String("censys", "", "")
		flBingHTML       = flag.Bool("bing-html", false, "")
		flYandex         = flag.String("yandex", "", "")
		flExfil          = flag.Bool("exfiltrated", false, "")
		flDomain         = flag.String("domain", "", "")
		flDictFile       = flag.String("dictionary", "", "")
		flFcrdns         = flag.Bool("fcrdns", false, "")
		flClean          = flag.Bool("clean", false, "")
		flCsv            = flag.Bool("csv", false, "")
		flJSON           = flag.Bool("json", false, "")
	)
	flag.Usage = func() { fmt.Print(usage) }
	flag.Parse()

	if *flVersion {
		fmt.Println("blacksheepwall version ", bsw.VERSION)
		os.Exit(0)
	}

	if *flParse != "" {
		readDataAndOutput(*flParse, *flJSON, *flCsv, *flClean)
		os.Exit(0)
	}

	config := &bsw.C{}
	if *flConfig != "" {
		var err error
		config, err = bsw.ReadConfig(*flConfig)
		if err != nil {
			log.Fatalf("Error reading config file. Error: %s", err.Error())
		}
	}

	// Modify timeout to Milliseconds for function calls.
	// Adjust some options for the config file.
	if config.Timeout != 0 && *flTimeout == 600 {
		*flTimeout = config.Timeout * 1000
	}
	if *flTimeout != 600 {
		*flTimeout = *flTimeout * 1000
	}
	if config.Concurrency != 0 && *flConcurrency == 100 {
		*flConcurrency = config.Concurrency
	}
	if config.Server != "" && *flServerAddr == "8.8.8.8" {
		*flServerAddr = config.Server
	}

	// Ingest options from config.
	if !*flValidate {
		*flValidate = config.Validate
	}
	if !*flipv6 {
		*flipv6 = config.IPv6
	}
	if !*flReverse {
		*flReverse = config.Reverse
	}
	if !*flHeader {
		*flHeader = config.Headers
	}
	if !*flTLS {
		*flTLS = config.TLS
	}
	if !*flAXFR {
		*flAXFR = config.AXFR
	}
	if !*flMX {
		*flMX = config.MX
	}
	if !*flNS {
		*flNS = config.NS
	}
	if !*flCRTSH {
		*flCRTSH = config.CRTSH
	}
	if !*flVT {
		*flVT = config.VT
	}
	if !*flViewDNSInfo {
		*flViewDNSInfo = config.ViewDNSInfo
	}
	if *flViewDNSInfoAPI == "" {
		*flViewDNSInfoAPI = config.ViewDNSInfoAPI
	}
	if !*flLogonTube {
		*flLogonTube = config.LogonTube
	}
	if !*flSRV {
		*flSRV = config.SRV
	}
	if *flBing == "" {
		*flBing = config.Bing
	}
	if *flCommonCrawl == "" {
		*flCommonCrawl = config.CommonCrawl
	}
	if *flShodan == "" {
		*flShodan = config.Shodan
	}
	if *flCensys == "" {
		*flCensys = config.Censys
	}
	if !*flBingHTML {
		*flBingHTML = config.BingHTML
	}
	if *flYandex == "" {
		*flYandex = config.Yandex
	}
	if !*flExfil {
		*flExfil = config.Exfil
	}
	if *flDictFile == "" {
		*flDictFile = config.DictFile
	}
	if !*flFcrdns {
		*flFcrdns = config.FCRDNS
	}

	// Holds all IP addresses for testing.
	ipAddrList := []string{}

	stat, err := os.Stdin.Stat()
	var isStdIn bool
	if err == nil {
		isStdIn = (stat.Mode() & os.ModeCharDevice) == 0
	}
	// Verify that some sort of work load was given in commands.
	if !isStdIn && *flIPFile == "" && *flDomain == "" && len(flag.Args()) < 1 {
		log.Fatal("You didn't provide any work for me to do")
	}
	if *flYandex != "" && *flDomain == "" {
		log.Fatal("Yandex API requires domain set with -domain")
	}
	if *flDictFile != "" && *flDomain == "" {
		log.Fatal("Dictionary lookup requires domain set with -domain")
	}
	if *flDomain == "" && *flSRV == true {
		log.Fatal("SRV lookup requires domain set with -domain")
	}
	if *flExfil && *flDomain == "" {
		log.Fatal("Exfiltrated requires domain set with -domain")
	}
	if *flNS && *flDomain == "" {
		log.Fatal("NS lookup requires domain set with -domain")
	}
	if *flMX && *flDomain == "" {
		log.Fatal("MX lookup requires domain set with -domain")
	}
	if *flCRTSH && *flDomain == "" {
		log.Fatal("CRTSH requires a domain set with -domain")
	}
	if *flVT && *flDomain == "" {
		log.Fatal("VirusTotal requires a domain set with -domain")
	}
	if *flAXFR && *flDomain == "" {
		log.Fatal("Zone transfer requires domain set with -domain")
	}
	if *flCommonCrawl != "" && *flDomain == "" {
		log.Fatal("Common Crawl requires domain set with -domain")
	}
	if *flDomain != "" && *flYandex == "" && *flDictFile == "" && !*flSRV && !*flLogonTube && *flShodan == "" && *flBing == "" && !*flBingHTML && !*flAXFR && !*flNS && !*flMX && !*flVT && !*flCRTSH && !*flExfil && *flCensys == "" && *flCommonCrawl == "" {
		log.Fatal("-domain provided but no methods provided that use it")
	}

	// Build list of domains.
	domains := []string{}
	if *flDomain != "" {
		if _, err := os.Stat(*flDomain); os.IsNotExist(err) {
			domains = append(domains, *flDomain)
		} else {
			lines, err := helpers.ReadFileLines(*flDomain)
			if err != nil {
				log.Fatal("Error reading " + *flDomain + " " + err.Error())
			}
			domains = append(domains, lines...)
		}
	}

	// Get first argument that is not an option and turn it into a list of IPs.
	if len(flag.Args()) > 0 {
		flNetwork := flag.Arg(0)
		list, err := helpers.LinesToIPList([]string{flNetwork})
		if err != nil {
			log.Fatal(err.Error())
		}
		ipAddrList = append(ipAddrList, list...)
	}

	// If file given as -input, read lines and turn each possible IP or network into
	// a list of IPs. Appends list to ipAddrList. Will fail fatally if line in file
	// is not a valid IP or CIDR range.
	if *flIPFile != "" {
		lines, err := helpers.ReadFileLines(*flIPFile)
		if err != nil {
			log.Fatal("Error reading " + *flIPFile + " " + err.Error())
		}
		list, err := helpers.LinesToIPList(lines)
		if err != nil {
			log.Fatal(err.Error())
		}
		ipAddrList = append(ipAddrList, list...)
	}

	// Use a map that acts like a set to store only unique results.
	resMap := make(map[bsw.Result]bool)

	if isStdIn {
		stdin, err := ioutil.ReadAll(os.Stdin)
		if err == nil {
			pipedResults := bsw.Results{}
			if err := json.Unmarshal(stdin, &pipedResults); err != nil {
				log.Fatal("Error parsing JSON from stdin")
			}
			for _, r := range pipedResults {
				ipAddrList = append(ipAddrList, r.IP)
				resMap[r] = true
			}
		}
	}

	// tracker: Chanel uses an empty struct to track when all goroutines in the pool
	//          have completed as well as a single call from the gatherer.
	//
	// tasks:   Chanel used in the goroutine pool to manage incoming work. A task is
	//          a function wrapper that returns a slice of results and a possible error.
	//
	// res:     When each task is called in the pool, it will send valid results to
	//          the res channel.
	tracker := make(chan empty)
	tasks := make(chan task, *flConcurrency)
	res := make(chan *bsw.Tsk, *flConcurrency)

	// Start up *flConcurrency amount of goroutines.
	log.Printf("Spreading tasks across %d goroutines", *flConcurrency)
	for i := 0; i < *flConcurrency; i++ {
		go func() {
			for def := range tasks {
				res <- def()
			}
			tracker <- empty{}
		}()
	}

	// Ingest incoming results.
	go func() {
		c := 0
		for t := range res {
			if !*flDebug {
				if m := c % 2; m == 0 {
					c = 3
					os.Stderr.WriteString("\rWorking \\")
				} else {
					c = 2
					os.Stderr.WriteString("\rWorking /")
				}
			}
			if err := t.Err(); err != nil && *flDebug {
				log.Printf("%v: %v", t.Task(), err)
				continue
			}
			if t.Err() != nil {
				continue
			}
			if !t.HasResults() {
				continue
			}
			result := t.Results()
			if *flDebug {
				log.Printf("%v: %v %v: task completed successfully\n", t.Task(), result[0].Hostname, result[0].IP)
			}
			if *flFcrdns {
				for _, r := range result {
					r.Hostname = strings.ToLower(r.Hostname)
					ips, err := bsw.LookupName(r.Hostname, *flServerAddr)
					if err == nil {
						for _, ip := range ips {
							resMap[bsw.Result{Source: "fcrdns", IP: ip, Hostname: r.Hostname}] = true
						}
						continue
					}
					var (
						ecount    int
						cfqdn     string
						cfqdns    []string
						isErrored bool
					)
					tfqdn := r.Hostname
					for {
						cfqdn, err = bsw.LookupCname(tfqdn, *flServerAddr)
						if err != nil {
							isErrored = true
							break
						}
						cfqdns = append(cfqdns, cfqdn)
						ips, err = bsw.LookupName(cfqdn, *flServerAddr)
						if err != nil {
							ecount++
							if ecount > 10 {
								isErrored = true
								break
							}
							tfqdn = cfqdn
							continue
						}
						break
					}
					if !isErrored {
						for _, ip := range ips {
							resMap[bsw.Result{Source: "fcrdns", IP: ip, Hostname: r.Hostname}] = true
							for _, c := range cfqdns {
								resMap[bsw.Result{Source: "fcrdns", IP: ip, Hostname: c}] = true
							}
						}
					} else {
						ips, err = bsw.LookupName6(r.Hostname, *flServerAddr)
						if err == nil {
							for _, ip := range ips {
								resMap[bsw.Result{Source: "fcrdns", IP: ip, Hostname: r.Hostname}] = true
							}
						}
					}
				}
			} else {
				for _, r := range result {
					r.Hostname = strings.ToLower(r.Hostname)
					if *flValidate {
						if ok, err := regexp.Match(bsw.DomainRegex, []byte(r.Hostname)); err != nil || !ok {
							continue
						}
					}
					resMap[r] = true
				}
			}
		}
		tracker <- empty{}
	}()

	// Bing has two possible search paths. We need to find which one is valid.
	var bingPath string
	if *flBing != "" {
		p, err := bsw.FindBingSearchPath(*flBing)
		if err != nil {
			log.Fatal(err.Error())
		}
		bingPath = p
	}

	if *flShodan != "" && len(ipAddrList) > 0 {
		tasks <- func() *bsw.Tsk { return bsw.ShodanAPIReverse(ipAddrList, *flShodan) }
	}

	// IP based functionality should be added to the pool here.
	for _, h := range ipAddrList {
		host := h
		if *flReverse {
			tasks <- func() *bsw.Tsk { return bsw.Reverse(host, *flServerAddr) }
		}
		if *flTLS {
			tasks <- func() *bsw.Tsk { return bsw.TLS(host, *flTimeout) }
		}
		if *flViewDNSInfo {
			tasks <- func() *bsw.Tsk { return bsw.ViewDNSInfo(host) }
		}
		if *flViewDNSInfoAPI != "" {
			tasks <- func() *bsw.Tsk { return bsw.ViewDNSInfoAPI(host, *flViewDNSInfoAPI) }
		}
		if *flLogonTube {
			tasks <- func() *bsw.Tsk { return bsw.LogonTubeAPI(host) }
		}
		if *flBingHTML {
			tasks <- func() *bsw.Tsk { return bsw.BingIP(host) }
		}
		if *flBing != "" && bingPath != "" {
			tasks <- func() *bsw.Tsk { return bsw.BingAPIIP(host, *flBing, bingPath) }
		}
		if *flHeader {
			tasks <- func() *bsw.Tsk { return bsw.Headers(host, *flTimeout) }
		}
	}

	// Domain based functions will likely require separate blocks and should be added below.

	// Subdomain dictionary guessing.
	for _, d := range domains {
		domain := d
		if *flDictFile != "" {
			nameList, err := helpers.ReadFileLines(*flDictFile)
			if err != nil {
				log.Fatal("Error reading " + *flDictFile + " " + err.Error())
			}
			// Get an IP for a possible wildcard domain and use it as a blacklist.
			blacklist := bsw.GetWildCards(domain, *flServerAddr)
			for _, wildcardIp := range blacklist {
				ip := wildcardIp
				tasks <- func() *bsw.Tsk {
					t := &bsw.Tsk{}
					t.SetTask("Wildcard IPv4")
					t.AddResult(ip, "*."+domain)
					return t
				}
			}
			var blacklist6 []string
			if *flipv6 {
				blacklist6 = bsw.GetWildCards6(domain, *flServerAddr)
				for _, wildcardIp := range blacklist6 {
					ip := wildcardIp
					tasks <- func() *bsw.Tsk {
						t := &bsw.Tsk{}
						t.SetTask("Wildcard IPv6")
						t.AddResult(ip, "*."+domain)
						return t
					}
				}
			}
			for _, n := range nameList {
				sub := n
				tasks <- func() *bsw.Tsk { return bsw.Dictionary(domain, sub, blacklist, *flServerAddr) }
				if *flipv6 {
					tasks <- func() *bsw.Tsk { return bsw.Dictionary6(domain, sub, blacklist6, *flServerAddr) }
				}
			}
		}

		if *flExfil {
			tasks <- func() *bsw.Tsk { return bsw.ExfiltratedHostname(domain, *flServerAddr) }
		}
		if *flSRV {
			tasks <- func() *bsw.Tsk { return bsw.SRV(domain, *flServerAddr) }
		}
		if *flYandex != "" {
			tasks <- func() *bsw.Tsk { return bsw.YandexAPI(domain, *flYandex, *flServerAddr) }
		}
		if *flLogonTube {
			tasks <- func() *bsw.Tsk { return bsw.LogonTubeAPI(domain) }
		}
		if *flShodan != "" {
			tasks <- func() *bsw.Tsk { return bsw.ShodanAPIHostSearch(domain, *flShodan) }
		}
		if *flBing != "" && bingPath != "" {
			tasks <- func() *bsw.Tsk { return bsw.BingAPIDomain(domain, *flBing, bingPath, *flServerAddr) }
		}
		if *flBingHTML {
			tasks <- func() *bsw.Tsk { return bsw.BingDomain(domain, *flServerAddr) }
		}
		if *flAXFR {
			tasks <- func() *bsw.Tsk { return bsw.AXFR(domain, *flServerAddr) }
		}
		if *flNS {
			tasks <- func() *bsw.Tsk { return bsw.NS(domain, *flServerAddr) }
		}
		if *flMX {
			tasks <- func() *bsw.Tsk { return bsw.MX(domain, *flServerAddr) }
		}
		if *flCensys != "" {
			tasks <- func() *bsw.Tsk { return bsw.CensysDomain(domain, *flCensys) }
		}
		if *flCommonCrawl != "" {
			tasks <- func() *bsw.Tsk { return bsw.CommonCrawl(domain, *flCommonCrawl, *flServerAddr) }
		}
		if *flCRTSH {
			tasks <- func() *bsw.Tsk { return bsw.CRTSHCT(domain, *flServerAddr) }
		}
		if *flVT {
			tasks <- func() *bsw.Tsk { return bsw.VirusTotal(domain, *flServerAddr) }
		}
	}

	// Close the tasks channel after all jobs have completed and for each
	// goroutine in the pool receive an empty message from  tracker.
	close(tasks)
	for i := 0; i < *flConcurrency; i++ {
		<-tracker
	}
	close(res)
	// Receive and empty message from the result gatherer.
	<-tracker
	os.Stderr.WriteString("\r")
	log.Println("All tasks completed")

	// Create a results slice from the unique set in resMap. Allows for sorting.
	results := bsw.Results{}
	for k := range resMap {
		results = append(results, k)
	}
	sort.Sort(results)
	output(results, *flJSON, *flCsv, *flClean)
}

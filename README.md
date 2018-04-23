blacksheepwall
===

[![](https://godoc.org/github.com/tomsteele/blacksheepwall/bsw?status.svg)](http://godoc.org/github.com/tomsteele/blacksheepwall/bsw)

blacksheepwall is a hostname reconnaissance tool written in Go. It can also be used as a stand-alone package in your tools.

## Download

Binary packages for every supported operating system are available [here](https://github.com/tomsteele/blacksheepwall/releases/latest).

## Install

You can download a compiled binary and just run it. Alternatively, if you have Go installed and configured with a workspace, you can run:
```
$ go get github.com/tomsteele/blacksheepwall
```

## Usage

```
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
```

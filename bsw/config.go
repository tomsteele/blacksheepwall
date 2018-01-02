package bsw

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

// C is used to parse a YAML config file.
type C struct {
	Timeout        int64  `yaml:"timeout"`
	Concurrency    int    `yaml:"concurrency"`
	Validate       bool   `yaml:"validate"`
	IPv6           bool   `yaml:"ipv6"`
	Server         string `yaml:"server"`
	Reverse        bool   `yaml:"reverse"`
	Headers        bool   `yaml:"headers"`
	TLS            bool   `yaml:"tls"`
	AXFR           bool   `yaml:"axfr"`
	MX             bool   `yaml:"mx"`
	NS             bool   `yaml:"ns"`
	ViewDNSInfo    bool   `yaml:"viewdns_html"`
	ViewDNSInfoAPI string `yaml:"viewdns"`
	Robtex         bool   `yaml:"robtex"`
	LogonTube      bool   `yaml:"logontube"`
	SRV            bool   `yaml:"srv"`
	Bing           string `yaml:"bing"`
	BingHTML       bool   `yaml:"bing_html"`
	Shodan         string `yaml:"shodan"`
	Censys         string `yaml:"censys"`
	Yandex         string `yaml:"yandex"`
	Exfil          bool   `yaml:"exfiltrated"`
	DictFile       string `yaml:"dictionary"`
	FCRDNS         bool   `yaml:"fcrdns"`
	CommonCrawl    string `yaml:"cmn_crawl"`
	CRTSH          bool   `yaml:"crtsh"`
	VT             bool   `yaml:"vt"`
}

// ReadConfig parses a yaml file and returns a pointer to a new config.
func ReadConfig(location string) (*C, error) {
	c := &C{}
	data, err := ioutil.ReadFile(location)
	if err != nil {
		return c, err
	}
	err = yaml.Unmarshal(data, c)
	return c, err
}

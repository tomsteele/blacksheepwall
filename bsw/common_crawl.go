package bsw

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type commonCrawlMessage struct {
	URL string `json:"url"`
}

// CommonCrawl search commoncrawl.org for subdomains of the provided domain.
func CommonCrawl(domain, path, serverAddr string) *Tsk {
	t := newTsk("commoncrawl.org")
	client := &http.Client{}
	u := fmt.Sprintf("http://index.commoncrawl.org/%s?url=*.%s&output=json", path, domain)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		t.SetErr(err)
		return t
	}
	resp, err := client.Do(req)
	if err != nil {
		t.SetErr(err)
		return t
	}
	subSet := map[string]bool{}
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		var msg commonCrawlMessage
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			continue
		}
		xurl, err := url.Parse(msg.URL)
		if err != nil {
			continue
		}
		subdomain := strings.SplitN(xurl.Host, domain, 2)[0]
		subdomain = strings.TrimRight(subdomain, ".")
		subSet[subdomain] = true
	}
	var wg sync.WaitGroup
	var mutex sync.Mutex

	for k := range subSet {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			xtsk := Dictionary(domain, sub, nil, serverAddr)
			if len(xtsk.Err()) > 0 {
				return
			}
			for _, r := range xtsk.Results() {
				mutex.Lock()
				t.AddResult(r.IP, r.Hostname)
				mutex.Unlock()
			}
		}(k)
	}
	wg.Wait()
	return t
}

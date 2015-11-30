package bsw

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type logontubeMessage struct {
	Hostip   string `json:"hostip"`
	Hostname string `json:"hostname"`
	Response struct {
		DomainCount string   `json:"domain_count"`
		Domains     []string `json:"domains"`
	} `json:"response"`
}

// LogonTubeAPI sends either a domain or IP to logontube.com's API.
func LogonTubeAPI(search string) *Tsk {
	t := newTsk("logontube.com API")
	resp, err := http.Get(fmt.Sprintf("http://reverseip.logontube.com/?url=%s&output=json", search))
	if err != nil {
		t.SetErr(err)
		return t
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.SetErr(err)
		return t
	}
	m := &logontubeMessage{}
	if err := json.Unmarshal(body, &m); err != nil {
		t.SetErr(err)
		return t
	}
	for _, r := range m.Response.Domains {
		t.AddResult(m.Hostip, r)
	}
	return t
}

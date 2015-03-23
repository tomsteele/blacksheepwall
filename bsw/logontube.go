package bsw

import (
	"encoding/json"
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
func LogonTubeAPI(search string) (string, Results, error) {
	task := "logontube.com API"
	results := Results{}
	url := "http://reverseip.logontube.com/?url=" + search + "&output=json"
	resp, err := http.Get(url)
	if err != nil {
		return task, results, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return task, results, err
	}
	m := &logontubeMessage{}
	if err := json.Unmarshal(body, &m); err != nil {
		return task, results, err
	}
	for _, r := range m.Response.Domains {
		results = append(results, Result{
			Source:   task,
			IP:       m.Hostip,
			Hostname: r,
		})
	}
	return task, results, nil
}

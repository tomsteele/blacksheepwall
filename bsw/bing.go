package bsw

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
)

type bingMessage struct {
	D bingResults
}

type bingResults struct {
	Results []bingResult
}

type bingResult struct {
	__metadata  bingMetadata
	ID          string
	Title       string
	Description string
	DisplayUrl  string
	Url         string
}

type bingMetadata struct {
	Uri  string
	Type string
}

const host = "https://api.datamarket.azure.com"

// Attempts an authenticated search request to two different Bing API paths. If and when a
// search is successfull, that path will be returned. If no path is valid this function
// returns an error.
func FindBingSearchPath(key string) (string, error) {
	var paths = []string{"/Data.ashx/Bing/Search/v1/Web", "/Data.ashx/Bing/SearchWeb/v1/Web"}
	var query = "?Query=%27I<3BSW%27"
	for _, path := range paths {
		var fullUrl = host + path + query
		client := &http.Client{}
		req, err := http.NewRequest("GET", fullUrl, nil)
		if err != nil {
			return "", err
		}
		req.SetBasicAuth(key, key)
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		if resp.StatusCode == 200 {
			return path, nil
		}
	}
	return "", errors.New("Invalid Bing API key")
}

// Uses the Bing search API and 'ip' search operator to find alternate hostnames for
// a single IP.
func BingAPI(ip, key, path string) (Results, error) {
	results := Results{}
	var query = "?Query=%27ip:" + ip + "%27&$top=50&Adult=%27off%27&$format=json"
	var fullUrl = host + path + query
	client := &http.Client{}
	req, err := http.NewRequest("GET", fullUrl, nil)
	if err != nil {
		return results, err
	}
	req.SetBasicAuth(key, key)
	resp, err := client.Do(req)
	if err != nil {
		return results, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return results, err
	}
	var m bingMessage
	err = json.Unmarshal(body, &m)
	if err != nil {
		return results, err
	}
	for _, res := range m.D.Results {
		u, err := url.Parse(res.Url)
		if err == nil {
			results = append(results, Result{Source: "Bing API", IP: ip, Hostname: u.Host})
		}
	}
	return results, nil
}

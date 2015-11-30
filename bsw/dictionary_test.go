package bsw

import (
	"testing"
)

func TestWildCard(t *testing.T) {
	ip := GetWildCard("stacktitan.com", "8.8.8.8")
	if ip == "" {
		t.Error("Failed to get A record for wildcard")
	}
}

func TestDictionary(t *testing.T) {
	tsk := Dictionary("stacktitan.com", "foo", "", "8.8.8.8")
	if !tsk.HasResults() {
		t.Fatal("Dictionary did not return any results")
	}
	results := tsk.Results()
	if results[0].IP != "104.131.56.170" {
		t.Error("Dictionary returned incorrect or non-existent IP Address")
	}
	if results[0].Hostname != "foo.stacktitan.com" {
		t.Error("Dictionary returned incorrect hostname")
	}
	if results[0].Source != "Dictionary IPv4" {
		t.Error("Dictionary returned incorrect source")
	}

	tsk = Dictionary("stacktitan.com", "autodiscover", "", "8.8.8.8")
	if !tsk.HasResults() {
		t.Fatal("Dictionary did not return any results")
	}
	results = tsk.Results()
	if results[0].IP != "184.106.31.93" {
		t.Error("Dictionary returned incorrect or non-existent IP Address")
	}
	if results[0].Hostname != "autodiscover.stacktitan.com" {
		t.Error("Dictionary returned incorrect hostname")
	}
	if results[0].Source != "Dictionary-CNAME" {
		t.Error("Dictionary returned incorrect source")
	}
}

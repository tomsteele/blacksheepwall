package bsw

import (
	"testing"
)

func TestWildCard(t *testing.T) {
	ip := GetWildCard("huptwo34.com", "208.67.222.222")
	if ip == "" {
		t.Error("Failed to get A record for wildcard")
	}
}

func testDictionary(t *testing.T) {
	results, _ := Dictionary("huptwo34.com", "www", "", "8.8.8.8")
	if results[0].IPAddress != "209.147.121.178" {
		t.Error("Dictionary returned incorrect or non-existent IP Address")
	}
	if results[0].Hostname != "www.huptwo34.com" {
		t.Error("Dictioanry returned incorrect hostname")
	}
	if results[0].Source != "Dictionary" {
		t.Error("Dictionary returned incorrect source")
	}
}

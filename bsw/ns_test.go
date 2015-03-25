package bsw

import (
	"testing"
)

func TestNS(t *testing.T) {
	_, results, err := NS("stacktitan.com", "8.8.8.8")
	if err != nil {
		t.Error("error returned from NS")
		t.Log(err)
	}
	found := false
	for _, r := range results {
		if r.Hostname == "ns1.digitalocean.com" {
			found = true
		}
	}
	if !found {
		t.Error("NS did not find correct ns server")
		t.Log(results)
	}
}

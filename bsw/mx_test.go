package bsw

import (
	"testing"
)

func TestMX(t *testing.T) {
	_, results, err := MX("stacktitan.com", "8.8.8.8")
	if err != nil {
		t.Error("error returned from MX")
		t.Log(err)
	}
	found := false
	for _, r := range results {
		if r.Hostname == "mx1.emailsrvr.com" {
			found = true
		}
	}
	if !found {
		t.Error("MX did not find correct mx server")
		t.Log(results)
	}
}

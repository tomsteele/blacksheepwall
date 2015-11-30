package bsw

import (
	"testing"
)

func TestNS(t *testing.T) {
	tsk := NS("stacktitan.com", "8.8.8.8")
	if err := tsk.Err(); err != nil {
		t.Error("error returned from NS")
		t.Log(err)
	}
	found := false
	for _, r := range tsk.Results() {
		if r.Hostname == "ns1.digitalocean.com" {
			found = true
		}
	}
	if !found {
		t.Error("NS did not find correct ns server")
	}
}

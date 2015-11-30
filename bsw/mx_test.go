package bsw

import (
	"testing"
)

func TestMX(t *testing.T) {
	tsk := MX("stacktitan.com", "8.8.8.8")
	if err := tsk.Err(); err != nil {
		t.Error("error returned from MX")
		t.Log(err)
	}
	found := false
	for _, r := range tsk.Results() {
		if r.Hostname == "mx1.emailsrvr.com" {
			found = true
		}
	}
	if !found {
		t.Error("MX did not find correct mx server")
	}
}

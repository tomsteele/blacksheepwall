package bsw

import (
	"testing"
)

func TestAXFR(t *testing.T) {
	tsk := AXFR("zonetransfer.me", "8.8.8.8")
	if tsk.Err() != nil {
		t.Error("error returned from AXFR")
		t.Log(tsk.Err())
	}
	if len(tsk.Results()) < 10 {
		t.Error("expected more results from AXFR")
	}
}

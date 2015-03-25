package bsw

import (
	"testing"
)

func TestAXFR(t *testing.T) {
	_, results, err := AXFR("zonetransfer.me", "8.8.8.8")
	if err != nil {
		t.Error("error returned from AXFR")
		t.Log(err)
	}
	if len(results) < 10 {
		t.Error("expected more results from AXFR")
	}
}

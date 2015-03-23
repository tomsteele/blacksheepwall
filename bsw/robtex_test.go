package bsw

import (
	"testing"
)

func TestRobtex(t *testing.T) {
	tsk, results, err := Robtex("104.131.56.170")
	if err != nil {
		t.Error("error returned from robtex")
		t.Log(err)
	}
	if tsk != "robtex.com" {
		t.Error("task should be robtex.com")
	}
	if len(results) < 1 {
		t.Error("robtex did not return any results")
	}
}

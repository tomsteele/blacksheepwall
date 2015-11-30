package bsw

import (
	"strings"
	"testing"
)

func TestInvalidKeyToPath(t *testing.T) {
	_, err := FindBingSearchPath("notavalidkey")
	if err == nil {
		t.Error("FindBingSearchPath did not return error for bad key")
	}
}

func TestInvalidBingKey(t *testing.T) {
	tsk := BingAPIIP("4.2.2.2", "notavalidkey", "/Data.ashx/Bing/Search/v1/Web")
	if tsk.Err() == nil {
		t.Error("BingAPI did not return error for bad key and path")
	}
}

func TestBingIP(t *testing.T) {
	tsk := BingIP("198.41.208.143")
	if err := tsk.Err(); err != nil {
		t.Error("bing returned an error")
		t.Log(err)
	}
	if tsk.Task() != "bing ip" {
		t.Error("task from Bing was not bing")
	}
	found := false
	for _, r := range tsk.Results() {
		if strings.Contains(r.Hostname, "reddit.com") {
			found = true
		}
	}
	if !found {
		t.Error("Bing did not find the correct domain")
	}
}

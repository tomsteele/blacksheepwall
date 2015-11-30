package bsw

import "testing"

func TestLogontubeAPI(t *testing.T) {
	tsk := LogonTubeAPI("stacktitan.com")
	if err := tsk.Err(); err != nil {
		t.Log(err)
		t.Fatal("Error returned from logontube.com")
	}
	if !tsk.HasResults() {
		t.Fatal("No results")
	}
	results := tsk.Results()
	if results[0].Hostname != "stacktitan.com" {
		t.Error("LogonTubeAPI returned incorrect Hostname")
	}
	if results[0].Source != "logontube.com API" {
		t.Error("LogonTubeAPI returned incorrect Source")
	}
	if results[0].IP != "104.131.56.170" {
		t.Error("LogonTubeAPI returned incorrect IP")
	}
}

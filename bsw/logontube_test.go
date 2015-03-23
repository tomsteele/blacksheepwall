package bsw

import "testing"

func TestLogontubeAPI(t *testing.T) {
	_, results, _ := LogonTubeAPI("stacktitan.com")
	if len(results) != 1 {
		t.Error("Results length not 1")
	}
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

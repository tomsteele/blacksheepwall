package bsw

import (
	"os"
	"strings"
	"testing"
)

func TestShodanAPIReverse(t *testing.T) {
	key := os.Getenv("SHODAN_API_KEY")
	if key == "" {
		t.Fatal("SHODAN_API_KEY environment variable not set")
	}
	tsk, results, err := ShodanAPIReverse([]string{"104.131.56.170"}, key)
	if err != nil {
		t.Error("ShodanAPIReverse returned an error")
		t.Log(err)
	}
	if tsk != "shodan API reverse" {
		t.Error("task from ShodanAPIReverse not shodan API reverse")
	}
	found := false
	for _, r := range results {
		if strings.Contains(r.Hostname, "stacktitan.com") {
			found = true
		}
	}
	if !found {
		t.Error("ShodanAPIReverse did not find the correct domain")
	}
}

func TestShodanAPIHostSerach(t *testing.T) {
	key := os.Getenv("SHODAN_API_KEY")
	if key == "" {
		t.Fatal("SHODAN_API_KEY environment variable not set")
	}
	tsk, results, err := ShodanAPIHostSearch("stacktitan.com", key)
	if err != nil {
		t.Error("ShodanAPIHostSearch returned an error")
		t.Log(err)
	}
	if tsk != "shodan API host search" {
		t.Error("task from ShodanAPIHostSearch not shodan API host search")
	}
	found := false
	for _, r := range results {
		if strings.Contains(r.Hostname, "stacktitan.com") {
			found = true
		}
	}
	if !found {
		t.Error("ShodanAPIHostSearch did not find the correct domain")
	}
}

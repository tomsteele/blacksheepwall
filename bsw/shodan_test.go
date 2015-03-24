package bsw

import (
	"os"
	"strings"
	"testing"
)

func TestShodanAPI(t *testing.T) {
	key := os.Getenv("SHODAN_API_KEY")
	if key == "" {
		t.Fatal("SHODAN_API_KEY environment variable not set")
	}
	tsk, results, err := ShodanAPI([]string{"104.131.56.170"}, key)
	if err != nil {
		t.Error("ShodanAPI returned an error")
		t.Log(err)
	}
	if tsk != "shodan API" {
		t.Error("task from ShodanAPI not shodan API")
	}
	found := false
	for _, r := range results {
		if strings.Contains(r.Hostname, "stacktitan.com") {
			found = true
		}
	}
	if !found {
		t.Error("ShodanAPI did not find the correct domain")
	}

}

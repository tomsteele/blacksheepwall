package bsw

import (
	"testing"
)

func TestInvalidKeyToPath(t *testing.T) {
	_, err := FindBingSearchPath("notavalidkey")
	if err == nil {
		t.Error("FindBingSearchPath did not return error for bad key")
	}
}

func TestInvalidBingKey(t *testing.T) {
	_, _, err := BingAPI("4.2.2.2", "notavalidkey", "/Data.ashx/Bing/Search/v1/Web")
	if err == nil {
		t.Error("BingAPI did not return error for bad key and path")
	}
}

package apisigner

import (
	"fmt"
	"net/http"
	"testing"
)

func TestSigner(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost,
		"https://examplebucket.s3.amazonaws.com/test.txt",
		nil)

	req.Header.Set("Host", req.Host)
	req.Header.Set("content-type", "application/json")

	SignSingleChunkReqeust(req, HMAC_SHA256, "12345", "12345")

	fmt.Printf("req.Header.Get(\"Authorization\"): %v\n", req.Header.Get("Authorization"))
}

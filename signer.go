package apisigner

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// 参照 aws signature v4, 实现了一个简单的请求签名算法

type SignAlgo int

// Algorithm used for signing the request
const (
	HMAC_SHA256 SignAlgo = iota
)

var (
	signAlgoNames = map[SignAlgo]string{
		HMAC_SHA256: "HMAC-SHA256",
	}
)

func getSignAlgoName(algo SignAlgo) string {
	return signAlgoNames[algo]
}

// signs a single chunk request
func SignSingleChunkReqeust(req *http.Request, signAlgo SignAlgo,
	accessKeyId, secretAccessKey string) error {
	signStr, signedHeaders, err := createStringToSign(req, signAlgo)
	if err != nil {
		return err
	}

	fmt.Printf("sign str:\n%s\n\n", signStr)
	fmt.Printf("signed headers:\n%s\n\n", signedHeaders)

	h := hmac.New(sha256.New, []byte(secretAccessKey))
	h.Write([]byte(signStr))
	signature := hex.EncodeToString(h.Sum(nil))
	req.Header.Set("Authorization",
		fmt.Sprintf("%s Credential=%s,SignedHeaders=%s,Signature=%s",
			getSignAlgoName(signAlgo), accessKeyId, signedHeaders, signature))
	return nil
}

const (
	request_time_header_name = "X-Request-Time"
	request_time_format      = "20060102T150405Z"
)

func createStringToSign(req *http.Request, signAlog SignAlgo) (string, string, error) {
	// Add request time header
	now := time.Now().UTC()
	reqTimeStr := now.Format(request_time_format)
	req.Header.Set(request_time_header_name, reqTimeStr)
	// Create canonical request
	canonicalRequestStr, signedHeaders, err := getCanonicalRequest(req)
	if err != nil {
		return "", "", err
	}
	fmt.Printf("canonicalRequestStr:\n%s\n\n", canonicalRequestStr)
	// Create string to sign
	var sb strings.Builder
	sb.WriteString(getSignAlgoName(signAlog))
	sb.WriteString("\n")
	sb.WriteString(reqTimeStr)
	sb.WriteString("\n")
	h := sha256.New()
	h.Write([]byte(canonicalRequestStr))
	hash := hex.EncodeToString(h.Sum(nil))
	sb.WriteString(hash)
	return sb.String(), signedHeaders, nil
}

func getCanonicalRequest(req *http.Request) (string, string, error) {
	var sb strings.Builder
	sb.WriteString(getHttpMethod(req))
	sb.WriteString("\n")
	sb.WriteString(getCanonicalUri(req))
	sb.WriteString("\n")
	sb.WriteString(getCanonicalQueryString(req))
	sb.WriteString("\n")
	canonicalHeaders, signedHeaders := getCanonicalHeaders(req)
	sb.WriteString(canonicalHeaders)
	sb.WriteString("\n")
	sb.WriteString(signedHeaders)
	sb.WriteString("\n")
	payloadHash, err := getPayloadHash(req)
	if err != nil {
		return "", "", err
	}
	sb.WriteString(payloadHash)
	return sb.String(), signedHeaders, nil
}

func getHttpMethod(req *http.Request) string {
	return strings.ToUpper(req.Method)
}

func getCanonicalUri(req *http.Request) string {
	return req.URL.Path
}

func getCanonicalQueryString(req *http.Request) string {
	rawQueris := req.URL.Query()
	var queries []string
	for k := range rawQueris {
		queries = append(queries, url.QueryEscape(k)+"="+url.QueryEscape(rawQueris.Get(k)))
	}
	sort.Strings(queries)
	return strings.Join(queries, "&")
}

func getCanonicalHeaders(req *http.Request) (string, string) {
	var headers []string
	var signedHeaders []string
	for k := range req.Header {
		lowerHeader := strings.ToLower(k)
		headers = append(headers, lowerHeader+":"+strings.TrimSpace(req.Header.Get(k)))
		signedHeaders = append(signedHeaders, lowerHeader)
	}
	sort.Strings(headers)
	sort.Strings(signedHeaders)
	return strings.Join(headers, "\n"), strings.Join(signedHeaders, ";")
}

func getPayloadHash(req *http.Request) (string, error) {
	var err error
	if req.GetBody == nil {
		return hex.EncodeToString(sha256.New().Sum(nil)), nil
	}
	r, err := req.GetBody()
	if err != nil {
		return "", err
	}
	defer r.Close()
	h := sha256.New()
	_, err = io.Copy(h, r)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

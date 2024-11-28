package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

func normalize(value string) string {
	// Percent-encode a string, excluding unreserved characters.
	return url.QueryEscape(value)
}

func formatTimestamp(t time.Time) string {
	// Format timestamp as 'yyyy-MM-dd'T'HH:mm:ss.SSS'Z''
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func hmacSHA256(key []byte, message string) []byte {
	// Compute HMAC-SHA256 and return the raw digest.
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return mac.Sum(nil)
}

func buildCanonicalQueryString(queryParameters map[string]string) string {
	if len(queryParameters) == 0 {
		return ""
	}
	// Sort the query parameters
	var keys []string
	for k := range queryParameters {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var queryParts []string
	for _, k := range keys {
		v := queryParameters[k]
		encodedKey := normalize(k)
		encodedValue := normalize(v)
		queryParts = append(queryParts, fmt.Sprintf("%s=%s", encodedKey, encodedValue))
	}
	return strings.Join(queryParts, "&")
}

func buildCanonicalRequest(httpMethod, uri string, queryParameters map[string]string, signedHeaders []string, canonicalHeaders map[string]string, payload string) string {
	var cr strings.Builder
	cr.WriteString(httpMethod)
	cr.WriteString("\n")
	cr.WriteString(uri)
	cr.WriteString("\n")

	// Canonical query string
	canonicalQueryString := buildCanonicalQueryString(queryParameters)
	cr.WriteString(canonicalQueryString)
	cr.WriteString("\n")

	// Signed headers
	cr.WriteString(strings.Join(signedHeaders, ";"))
	cr.WriteString("\n")

	// Canonical headers
	for _, headerName := range signedHeaders {
		headerValue := canonicalHeaders[headerName]
		cr.WriteString(fmt.Sprintf("%s:%s\n", headerName, headerValue))
	}
	cr.WriteString("\n")

	// Normalized payload
	normalizedPayload := normalize(payload)
	cr.WriteString(normalizedPayload)

	return cr.String()
}

func main() {
	// Inputs
	accessKey := "globalaktest"
	secretKey := "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p"
	host := "10.22.26.181:28080"
	uri := "/rest/cmsapp/v1/ping"
	httpMethod := "POST"
	timestamp := time.Now().UTC()
	formattedTimestamp := formatTimestamp(timestamp)
	payload := `{"say": "Hello world!"}`

	// Example query parameters (if any)
	queryParameters := map[string]string{
		// "param1": "value1",
	}

	// Compute Content-Length
	contentLength := fmt.Sprintf("%d", len(payload))

	// Construct headers
	headers := map[string]string{
		"host":           host,
		"content-length": contentLength,
		"content-type":   "application/json;charset=UTF-8",
	}

	// Lowercase and sort header names
	var signedHeaders []string
	for k := range headers {
		signedHeaders = append(signedHeaders, strings.ToLower(k))
	}
	sort.Strings(signedHeaders)

	// Canonical headers with normalized values
	canonicalHeaders := make(map[string]string)
	for _, k := range signedHeaders {
		v := headers[k]
		normalizedValue := normalize(strings.TrimSpace(v))
		canonicalHeaders[k] = normalizedValue
	}

	// Build CanonicalRequest
	canonicalRequest := buildCanonicalRequest(
		httpMethod, uri, queryParameters, signedHeaders, canonicalHeaders, payload,
	)

	// Build authStringPrefix
	authVersion := "auth-v2"
	signedHeadersStr := strings.Join(signedHeaders, ";")
	authStringPrefix := fmt.Sprintf("%s/%s/%s/%s", authVersion, accessKey, formattedTimestamp, signedHeadersStr)

	// Compute SigningKey (raw bytes)
	signingKey := hmacSHA256([]byte(secretKey), authStringPrefix)

	// Compute Signature (raw bytes)
	signatureBytes := hmacSHA256(signingKey, canonicalRequest)

	// Base64-encode the signature
	signature := base64.StdEncoding.EncodeToString(signatureBytes)

	// Build Authorization header
	authorization := fmt.Sprintf("%s/%s", authStringPrefix, signature)

	// Construct final headers for the request
	requestHeaders := map[string]string{
		"Authorization":  authorization,
		"Host":           headers["host"],
		"Content-Length": headers["content-length"],
		"Content-Type":   headers["content-type"],
	}

	// Create HTTP client with proxy
	proxyURL, err := url.Parse("http://proxy.example.com:8080") // Replace with your proxy URL
	if err != nil {
		fmt.Println("Invalid proxy URL:", err)
		os.Exit(1)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		// Skip SSL verification (not recommended for production)
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		// Dialer with timeout
		DialContext: (&net.Dialer{
			Timeout: 30 * time.Second,
		}).DialContext,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}

	// Build the request
	page := fmt.Sprintf("https://%s%s", host, uri)
	req, err := http.NewRequest(httpMethod, page, strings.NewReader(payload))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Add query parameters to the URL if any
	if len(queryParameters) > 0 {
		q := req.URL.Query()
		for k, v := range queryParameters {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	// Set headers
	for k, v := range requestHeaders {
		req.Header.Set(k, v)
	}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request error:", err)
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("Error closing response body: %v\n", err)
		}
	}()

	// Read the response
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	// Print the response
	fmt.Println("\nResponse Status Code:")
	fmt.Println(resp.StatusCode)
	fmt.Println("\nResponse Headers:")
	for k, v := range resp.Header {
		fmt.Printf("%s: %s\n", k, strings.Join(v, ", "))
	}
	fmt.Println("\nResponse Body:")
	fmt.Println(string(bodyBytes))
}

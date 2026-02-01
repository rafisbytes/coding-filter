package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"
)

func main() {
	proxy := goproxy.NewProxyHttpServer()

	// Block all requests except to google.com
	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// Extract the host from the request
		host := r.Host
		if r.URL.Host != "" {
			host = r.URL.Host
		}

		// Remove port if present
		hostname := strings.Split(host, ":")[0]

		// Allow only google.com and its subdomains
		if !isAllowedDomain(hostname) {
			// Return a blocked response
			return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden,
				fmt.Sprintf("Access Denied: %s is blocked. Only google.com is allowed.", hostname))
		}

		return r, nil
	})

	// Log all CONNECT requests (HTTPS)
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	log.Println("Proxy filter started on :8080")
	log.Println("Only google.com traffic is allowed")
	log.Fatal(http.ListenAndServe(":8080", proxy))
}

// isAllowedDomain checks if the domain is allowed (google.com or subdomains)
func isAllowedDomain(hostname string) bool {
	// Normalize the hostname
	hostname = strings.ToLower(hostname)

	// Allow google.com and all its subdomains
	if hostname == "google.com" || strings.HasSuffix(hostname, ".google.com") {
		return true
	}

	// Also allow common google domains
	allowedDomains := []string{
		"google.com",
		"www.google.com",
		"accounts.google.com",
		"mail.google.com",
		"drive.google.com",
		"maps.google.com",
		"youtube.com",
		"www.youtube.com",
	}

	for _, domain := range allowedDomains {
		if hostname == domain || strings.HasSuffix(hostname, "."+domain) {
			return true
		}
	}

	return false
}

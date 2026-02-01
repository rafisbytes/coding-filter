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
			// Return an HTML blocked response
			htmlResponse := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Access Denied</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f0f0; }
        .container { max-width: 600px; margin: 100px auto; padding: 20px; background-color: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #d32f2f; }
        p { color: #666; }
        .blocked-domain { font-weight: bold; color: #d32f2f; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚫 You were caught! 🚫</h1>
        <p>You tried to be distracted... but the PROFESOR is watching you!</p>
    </div>
</body>
</html>
            `, hostname)

			return r, goproxy.NewResponse(r, goproxy.ContentTypeHtml, http.StatusForbidden, htmlResponse)
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
	if strings.HasSuffix(hostname, ".google.com") {
		return true
	}

	// Also allow common google domains
	allowedDomains := []string{
		"onlineide.pro",
	}

	for _, domain := range allowedDomains {
		if hostname == domain || strings.HasSuffix(hostname, "."+domain) {
			return true
		}
	}

	return false
}

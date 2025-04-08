package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/xo/aws-proxy/pkg/cert"
	"github.com/xo/aws-proxy/pkg/policy"
)

// AWSProxy is the main proxy server
type AWSProxy struct {
	proxy       *goproxy.ProxyHttpServer
	certManager *cert.CertManager
	policy      *policy.PolicyEngine
	logger      *log.Logger
	caCertFile  string
	caKeyFile   string
}

// Custom certificate storage adapter for goproxy
type certStorageAdapter struct {
	certManager *cert.CertManager
	logger      *log.Logger
}

// Fetch implements the goproxy.CertStorage interface
func (c *certStorageAdapter) Fetch(hostname string, gen func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	// Try to generate certificate using our cert manager
	c.logger.Printf("Certificate requested for domain: %s", hostname)
	tlsCert, err := c.certManager.GenerateCertForHost(hostname)
	if err != nil {
		c.logger.Printf("Failed to generate certificate for %s: %v, falling back to default generator", hostname, err)
		return gen()
	}
	return tlsCert, nil
}

// NewAWSProxy creates a new AWS proxy
func NewAWSProxy(logger *log.Logger, certFile, keyFile string, permissive bool) (*AWSProxy, error) {
	// Create a certificate manager
	certManager, err := cert.NewCertManager(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	// Set the logger for the certificate manager
	certManager.SetLogger(logger)

	// Create a policy engine
	policyEngine := policy.NewPolicyEngine(logger, permissive)

	// Create a new proxy
	proxy := goproxy.NewProxyHttpServer()

	// Create a certificate storage adapter for goproxy
	certStorage := &certStorageAdapter{
		certManager: certManager,
		logger:      logger,
	}

	// Set the certificate storage on the proxy
	proxy.CertStore = certStorage

	// Create the AWS proxy
	awsProxy := &AWSProxy{
		proxy:       proxy,
		certManager: certManager,
		policy:      policyEngine,
		logger:      logger,
		caCertFile:  certManager.GetCACertFile(),
		caKeyFile:   certManager.GetCAKeyFile(),
	}

	// Set up the proxy
	awsProxy.setupProxy()

	logger.Printf("Certificate file: %s", awsProxy.caCertFile)
	logger.Printf("Key file: %s", awsProxy.caKeyFile)
	logger.Printf("To use with AWS CLI, set: export AWS_CA_BUNDLE=%s", awsProxy.caCertFile)

	return awsProxy, nil
}

// setupProxy configures the proxy server
func (p *AWSProxy) setupProxy() {
	// Always allow CONNECT requests to establish tunnels
	p.proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	// Load the CA certificate and key for MITM
	caCert, err := os.ReadFile(p.caCertFile)
	if err == nil {
		p.logger.Printf("Successfully loaded CA certificate from %s", p.caCertFile)

		// Set the CA certificate for goproxy
		goproxyCa, err := tls.LoadX509KeyPair(p.caCertFile, p.caKeyFile)
		if err != nil {
			p.logger.Printf("Failed to load CA certificate and key: %v", err)
		} else {
			p.logger.Printf("Successfully loaded CA certificate and key for TLS")
			goproxy.GoproxyCa = goproxyCa

			// Set up a custom TLS config
			caCertPool := x509.NewCertPool()
			if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
				p.logger.Printf("Failed to append CA certificate to pool")
			} else {
				p.logger.Printf("Successfully added CA certificate to pool")
			}
		}
	}

	// Handle all requests
	p.proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		p.logger.Printf("Request: %s %s", req.Method, req.URL)

		// Check for AWS API calls
		if req.Header.Get("Authorization") != "" && strings.Contains(req.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			p.logger.Printf("Found AWS Authorization header (SigV4 signature)")

			// Log AWS headers
			for k, v := range req.Header {
				if strings.HasPrefix(k, "X-Amz-") {
					p.logger.Printf("AWS Header: %s: %s", k, v[0])
				}
			}
		}

		return req, nil
	})

	// Handle all responses
	p.proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp != nil && ctx.Req != nil {
			p.logger.Printf("Response: %d %s %s", resp.StatusCode, ctx.Req.Method, ctx.Req.URL)

			// Log full response body for STS requests
			p.logger.Printf("Processing STS response for: %s", ctx.Req.URL)

			// Read the response body
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				p.logger.Printf("Error reading STS response body: %v", err)
			} else {
				// Close the original body
				resp.Body.Close()

				// Log the full response body
				p.logger.Printf("STS Response Body:\n%s", string(bodyBytes))

				// Extract AWS access key from the request
				accessKey := ""
				authHeader := ctx.Req.Header.Get("Authorization")
				if authHeader != "" && strings.Contains(authHeader, "AWS4-HMAC-SHA256") {
					credStart := strings.Index(authHeader, "Credential=")
					if credStart >= 0 {
						slashPos := strings.Index(authHeader[credStart+11:], "/")
						if slashPos >= 0 {
							accessKey = authHeader[credStart+11 : credStart+11+slashPos]
						}
					}
				}

				// Extract role ARN from the response if it's a GetCallerIdentity response
				if strings.Contains(string(bodyBytes), "GetCallerIdentityResponse") {
					arnStart := strings.Index(string(bodyBytes), "<Arn>")
					arnEnd := strings.Index(string(bodyBytes), "</Arn>")
					if arnStart >= 0 && arnEnd > arnStart {
						roleARN := string(bodyBytes)[arnStart+5 : arnEnd]
						p.logger.Printf("Extracted from GetCallerIdentity - AWS_ACCESS_KEY:ROLE_ARN = %s:%s",
							accessKey, roleARN)
					}
				}

				// Extract role ARN from the response if it's an AssumeRole response
				if strings.Contains(string(bodyBytes), "AssumeRoleResponse") {
					// Look for the AssumedRoleUser/Arn element
					arnStart := strings.Index(string(bodyBytes), "<Arn>")
					arnEnd := strings.Index(string(bodyBytes), "</Arn>")
					if arnStart >= 0 && arnEnd > arnStart {
						roleARN := string(bodyBytes)[arnStart+5 : arnEnd]
						p.logger.Printf("Extracted from AssumeRole - AWS_ACCESS_KEY:ROLE_ARN = %s:%s",
							accessKey, roleARN)
					}
				}

				// Restore the body for future readers
				resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
			}
		}
		return resp
	})
}

// ServeHTTP implements the http.Handler interface
func (p *AWSProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.proxy.ServeHTTP(w, r)
}

// Close closes the proxy
func (p *AWSProxy) Close() {
	// Nothing to do for now
}

// GetCACertFile returns the CA certificate file
func (p *AWSProxy) GetCACertFile() string {
	return p.caCertFile
}

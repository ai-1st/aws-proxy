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

type contextKey string

const (
	isAssumeRoleKey contextKey = "isAssumeRole"
)

// Custom certificate storage adapter for goproxy
type certStorageAdapter struct {
	certManager *cert.CertManager
	logger      *log.Logger
}

// Fetch implements the goproxy.CertStorage interface
func (c *certStorageAdapter) Fetch(hostname string, gen func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	// Try to generate certificate using our cert manager
	tlsCert, err := c.certManager.GenerateCertForHost(hostname)
	if err != nil {
		c.logger.Printf("Failed to generate certificate for %s: %v, falling back to default generator", hostname, err)
		return gen()
	}
	return tlsCert, nil
}

// NewAWSProxy creates a new AWS proxy
func NewAWSProxy(logger *log.Logger, certFile, keyFile string, permissive bool, allowedAccounts []string) (*AWSProxy, error) {
	// Create a certificate manager
	certManager, err := cert.NewCertManager(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	// Set the logger for the certificate manager
	certManager.SetLogger(logger)

	// Create a policy engine
	policyEngine, err := policy.NewPolicyEngine(logger, permissive, allowedAccounts)
	if err != nil {
		return nil, err
	}

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
	logger.Printf("To use with AWS CLI on the local machine, set: export AWS_CA_BUNDLE=%s", awsProxy.caCertFile)

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
		// Check if the request is allowed
		if !p.policy.IsAllowed(req) {

			// Drain the request body if it exists to prevent TLS warnings
			if req.Body != nil {
				io.Copy(io.Discard, req.Body)
				req.Body.Close()
			}

			// Create AWS-style error response
			errorResponse :=
				`<?xml version="1.0" encoding="UTF-8"?>
			<ErrorResponse>
				<Error>
					<Code>AccessDenied</Code>
					<Message>Request blocked by aws-proxy policy</Message>
				</Error>
			</ErrorResponse>`

			return req, goproxy.NewResponse(req, "application/xml", http.StatusForbidden, errorResponse)
		}

		// Check if this is an AssumeRole request
		isAssumeRole := p.policy.IsAssumeRole(req)
		ctx.UserData = isAssumeRole

		// Allow the request to proceed
		return req, nil
	})

	// Handle all responses
	p.proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp != nil && ctx.Req != nil {
			// Process STS responses
			if ctx.UserData != nil && ctx.UserData.(bool) {
				// Read the response body
				bodyBytes, err := io.ReadAll(resp.Body)
				if err != nil {
					p.logger.Printf("BAD RESPONSE: Error reading response body: %v", err)
				} else {
					// Close the original body
					resp.Body.Close()

					// Process the response using policy engine
					p.policy.ProcessAssumeRoleResponse(ctx.Req, bodyBytes)

					// Restore the body for future readers
					resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
				}
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

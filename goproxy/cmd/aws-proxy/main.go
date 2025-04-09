package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/xo/aws-proxy/pkg/proxy"
)

var (
	addr            = flag.String("addr", ":8080", "Proxy listen address")
	verbose         = flag.Bool("verbose", true, "Enable verbose logging")
	certFile        = flag.String("cert", "aws-proxy.crt", "Path to TLS certificate file (default: aws-proxy.crt in current directory)")
	keyFile         = flag.String("key", "aws-proxy.key", "Path to TLS key file (default: aws-proxy.key in current directory)")
	permissive      = flag.Bool("permissive", true, "Allow all requests regardless of IAM role")
	allowedAccounts = flag.String("allowed-accounts", "", "Comma-separated list of allowed AWS account IDs")
)

func main() {
	flag.Parse()

	// Set up logging
	logger := log.New(os.Stdout, "[aws-proxy] ", log.LstdFlags)
	logger.Printf("Starting AWS Proxy on %s", *addr)
	logger.Printf("Permissive mode: %v", *permissive)

	// Convert relative paths to absolute paths
	certPath := *certFile
	keyPath := *keyFile
	if !filepath.IsAbs(certPath) {
		absPath, err := filepath.Abs(certPath)
		if err == nil {
			certPath = absPath
		}
	}
	if !filepath.IsAbs(keyPath) {
		absPath, err := filepath.Abs(keyPath)
		if err == nil {
			keyPath = absPath
		}
	}

	logger.Printf("Certificate file: %s", certPath)
	logger.Printf("Key file: %s", keyPath)

	// Parse allowed account IDs
	var allowedAccountsList []string
	if *allowedAccounts != "" {
		allowedAccountsList = strings.Split(*allowedAccounts, ",")
		// Remove any empty strings that might result from trailing commas
		var cleanList []string
		for _, acc := range allowedAccountsList {
			if acc = strings.TrimSpace(acc); acc != "" {
				cleanList = append(cleanList, acc)
			}
		}
		allowedAccountsList = cleanList
	}
	logger.Printf("Allowed AWS accounts: %v", allowedAccountsList)

	// Create a new AWS proxy
	awsProxy, err := proxy.NewAWSProxy(logger, certPath, keyPath, *permissive, allowedAccountsList)
	if err != nil {
		logger.Fatalf("Error creating AWS proxy: %v", err)
	}
	defer awsProxy.Close()

	// Set up a server
	server := &http.Server{
		Addr:    *addr,
		Handler: awsProxy,
	}

	// Start the server
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("HTTP server error: %v", err)
		}
	}()

	logger.Printf("Proxy server started on %s", *addr)
	logger.Printf("To use with AWS CLI, set: export AWS_CA_BUNDLE=%s", awsProxy.GetCACertFile())

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Println("Shutting down proxy server...")
}

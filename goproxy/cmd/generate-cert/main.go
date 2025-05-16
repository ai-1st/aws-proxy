package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/xo/aws-proxy/pkg/cert"
)

func main() {
	// Define command line flags
	certFile := flag.String("cert", "certs/aws-proxy.crt", "Path to output certificate file")
	keyFile := flag.String("key", "keys/aws-proxy.key", "Path to output key file")
	ipAddresses := flag.String("ips", "127.0.0.1,::1", "Comma-separated list of IP addresses to include in the certificate")
	dnsNames := flag.String("dns", "localhost,aws-proxy", "Comma-separated list of DNS names to include in the certificate")

	flag.Parse()

	// Set up logging
	logger := log.New(os.Stdout, "[generate-cert] ", log.LstdFlags)

	// Create the certs directory if it doesn't exist
	certsDir := filepath.Dir(*certFile)
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		logger.Fatalf("Failed to create certificates directory: %v", err)
	}

	// Parse IP addresses
	ips := strings.Split(*ipAddresses, ",")
	for i, ip := range ips {
		ips[i] = strings.TrimSpace(ip)
	}

	// Parse DNS names
	dns := strings.Split(*dnsNames, ",")
	for i, name := range dns {
		dns[i] = strings.TrimSpace(name)
	}

	logger.Printf("Generating certificate with the following settings:")
	logger.Printf("Certificate file: %s", *certFile)
	logger.Printf("Key file: %s", *keyFile)
	logger.Printf("IP addresses: %v", ips)
	logger.Printf("DNS names: %v", dns)

	// Generate a new CA certificate
	ca, key, err := cert.GenerateCA()
	if err != nil {
		logger.Fatalf("Failed to generate CA: %v", err)
	}

	// Generate a TLS certificate - we don't need to store this as we're just using the CA
	_, err = cert.GenerateTLSCert(ca, key, ips, dns)
	if err != nil {
		logger.Fatalf("Failed to generate TLS certificate: %v", err)
	}

	// Create a temporary certificate manager to save the certificate
	tempCM := &cert.CertManager{
		CACert:     ca,
		CAPrivKey:  key,
		CACertFile: *certFile,
		CAKeyFile:  *keyFile,
	}

	// Save the certificate
	if err := tempCM.SaveCA(*certFile, *keyFile); err != nil {
		logger.Fatalf("Failed to save certificate: %v", err)
	}

	logger.Printf("Certificate successfully generated and saved to %s", *certFile)
	logger.Printf("Key successfully saved to %s", *keyFile)
	logger.Printf("To use with AWS CLI, set: export AWS_CA_BUNDLE=%s", *certFile)
}

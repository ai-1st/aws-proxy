package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CertManager handles certificate generation and storage
type CertManager struct {
	CACert     *x509.Certificate
	CAPrivKey  *rsa.PrivateKey
	CertFile   string
	KeyFile    string
	CACertFile string // Path to the CA certificate file
	CAKeyFile  string // Path to the CA key file
	tlsConfig  *tls.Config
	logger     *log.Logger // Logger for certificate operations
	certStore  *CertificateStorage // Certificate storage with LRU cache
}

// NewCertManager creates a new certificate manager
func NewCertManager(certFile, keyFile string) (*CertManager, error) {
	// If certFile is empty, use aws-proxy.crt in the current directory
	if certFile == "" {
		certFile = "aws-proxy.crt"
	}
	
	// If keyFile is empty, use aws-proxy.key in the current directory
	if keyFile == "" {
		keyFile = "aws-proxy.key"
	}
	
	// Convert relative paths to absolute paths
	if !filepath.IsAbs(certFile) {
		absPath, err := filepath.Abs(certFile)
		if err == nil {
			certFile = absPath
		}
	}
	
	if !filepath.IsAbs(keyFile) {
		absPath, err := filepath.Abs(keyFile)
		if err == nil {
			keyFile = absPath
		}
	}

	// Create a default logger
	logger := log.New(os.Stdout, "[cert-manager] ", log.LstdFlags)
	
	// Create certificate storage with LRU cache (cache size of 100)
	certStore, err := NewCertificateStorage(100, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate storage: %v", err)
	}

	cm := &CertManager{
		CertFile:   certFile,
		KeyFile:    keyFile,
		CACertFile: certFile, // Use the provided cert file as the CA cert file
		CAKeyFile:  keyFile,  // Use the provided key file as the CA key file
		logger:     logger,
		certStore:  certStore,
	}

	// Check if cert and key files exist
	certExists := fileExists(certFile)
	keyExists := fileExists(keyFile)

	// If both files exist, load them
	if certExists && keyExists {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate: %v", err)
		}

		// Parse the certificate
		if len(cert.Certificate) > 0 {
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %v", err)
			}
			cm.CACert = x509Cert
		}

		// Extract the private key
		if key, ok := cert.PrivateKey.(*rsa.PrivateKey); ok {
			cm.CAPrivKey = key
		} else {
			return nil, fmt.Errorf("private key is not RSA")
		}

		// Create TLS config
		cm.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	} else {
		// Certificate or key file doesn't exist
		return nil, fmt.Errorf("certificate or key file not found: %s, %s. Please generate them first using the generate-cert command", certFile, keyFile)
	}

	return cm, nil
}

// Helper function to check if a file exists
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// GenerateCA creates a new CA certificate and private key
func GenerateCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate a new private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create a template for the CA certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"AWS Proxy CA"},
			CommonName:   "AWS Proxy CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	// Create the CA certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %v", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	return cert, privateKey, nil
}

// GenerateTLSCert creates a TLS certificate signed by the CA
func GenerateTLSCert(ca *x509.Certificate, caKey *rsa.PrivateKey, ipAddresses []string, dnsNames []string) (tls.Certificate, error) {
	// Generate a new private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create a template for the certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"AWS Proxy"},
			CommonName:   "AWS Proxy Server",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Add IP addresses
	template.IPAddresses = []net.IP{}
	for _, ip := range ipAddresses {
		template.IPAddresses = append(template.IPAddresses, net.ParseIP(ip))
	}
	
	// If no IP addresses were provided, add localhost by default
	if len(template.IPAddresses) == 0 {
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	}
	
	// Add DNS names
	template.DNSNames = dnsNames
	
	// If no DNS names were provided, add localhost by default
	if len(template.DNSNames) == 0 {
		template.DNSNames = []string{"localhost", "aws-proxy"}
	}

	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, ca, &privateKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Create a certificate for TLS
	cert := tls.Certificate{
		Certificate: [][]byte{derBytes, ca.Raw},
		PrivateKey:  privateKey,
	}

	return cert, nil
}

// GenerateCertForHost creates a certificate for a specific host
func (cm *CertManager) GenerateCertForHost(host string) (*tls.Certificate, error) {
	// First check if we have a cached certificate
	if cm.certStore != nil {
		if cert, err := cm.certStore.Fetch(host); err == nil && cert != nil {
			return cert, nil
		}
	}

	// Generate a new private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create a template for the certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"GoProxy untrusted MITM proxy Inc"},
			CommonName:   host,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour), // 1 day
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Add the host as a DNS name
	template.DNSNames = []string{host}

	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, cm.CACert, &privateKey.PublicKey, cm.CAPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Create a certificate for TLS
	cert := tls.Certificate{
		Certificate: [][]byte{derBytes, cm.CACert.Raw},
		PrivateKey:  privateKey,
	}

	// Store the certificate in the cache
	if cm.certStore != nil {
		if err := cm.certStore.Store(host, &cert); err != nil {
			cm.logger.Printf("Warning: Failed to store certificate in cache: %v", err)
		}
	}

	return &cert, nil
}

// SaveCA saves the CA certificate and private key to files
func (cm *CertManager) SaveCA(certFile, keyFile string) error {
	// Save the certificate
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to open certificate file for writing: %v", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cm.CACert.Raw}); err != nil {
		return fmt.Errorf("failed to write certificate: %v", err)
	}

	// Save the private key if a key file is provided
	if keyFile != "" {
		keyOut, err := os.Create(keyFile)
		if err != nil {
			return fmt.Errorf("failed to open key file for writing: %v", err)
		}
		defer keyOut.Close()

		privBytes := x509.MarshalPKCS1PrivateKey(cm.CAPrivKey)
		if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
			return fmt.Errorf("failed to write private key: %v", err)
		}
	}

	return nil
}

// GetTLSConfig returns the TLS config
func (cm *CertManager) GetTLSConfig() *tls.Config {
	return cm.tlsConfig
}

// GetCACertFile returns the path to the CA certificate file
func (cm *CertManager) GetCACertFile() string {
	return cm.CACertFile
}

// GetCAKeyFile returns the path to the CA key file
func (cm *CertManager) GetCAKeyFile() string {
	return cm.CAKeyFile
}

// SetLogger sets the logger for the certificate manager
func (cm *CertManager) SetLogger(logger *log.Logger) {
	cm.logger = logger
}

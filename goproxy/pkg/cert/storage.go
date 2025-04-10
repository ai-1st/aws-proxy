package cert

import (
	"crypto/tls"
	"log"
	"sync"

	lru "github.com/hashicorp/golang-lru"
)

// CertificateStorage implements certificate storage with LRU caching
type CertificateStorage struct {
	certCache *lru.Cache
	logger    *log.Logger
	mu        sync.RWMutex
}

// NewCertificateStorage creates a new certificate storage with LRU caching
func NewCertificateStorage(cacheSize int, logger *log.Logger) (*CertificateStorage, error) {
	cache, err := lru.New(cacheSize)
	if err != nil {
		return nil, err
	}

	return &CertificateStorage{
		certCache: cache,
		logger:    logger,
	}, nil
}

// Fetch retrieves a certificate from the cache or returns nil if not found
func (s *CertificateStorage) Fetch(host string) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if cert, ok := s.certCache.Get(host); ok {
		return cert.(*tls.Certificate), nil
	}
	return nil, nil
}

// Store adds a certificate to the cache
func (s *CertificateStorage) Store(host string, cert *tls.Certificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.certCache.Add(host, cert)
	return nil
}

// SetLogger sets the logger for the certificate storage
func (s *CertificateStorage) SetLogger(logger *log.Logger) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logger = logger
}

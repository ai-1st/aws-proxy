package policy

import (
	"context"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	lru "github.com/hashicorp/golang-lru"
	"bytes"
)

// AccessKeyInfo stores information about an AWS access key
type AccessKeyInfo struct {
	AccessKeyID string
	AccountID   string
	RoleARN     string
}

// PolicyEngine handles IAM role validation
type PolicyEngine struct {
	// LRU cache of access key IDs to AccessKeyInfo
	accessKeyCache *lru.Cache
	// Map of allowed account IDs
	allowedAccounts map[string]bool
	// Mutex for thread safety
	mu sync.RWMutex
	// Logger
	logger *log.Logger
	// Permissive mode - allow all requests regardless of role
	permissive bool
	// AWS STS client
	stsClient *sts.Client
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(logger *log.Logger, permissive bool, allowedAccounts []string) (*PolicyEngine, error) {
	// Create a new LRU cache with a default size of 1000 entries
	cache, err := lru.New(1000)
	if err != nil {
		return nil, err
	}

	// Create a map of allowed accounts
	accountMap := make(map[string]bool)
	for _, account := range allowedAccounts {
		accountMap[account] = true
	}

	// Create an AWS STS client
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}
	stsClient := sts.NewFromConfig(cfg)

	return &PolicyEngine{
		accessKeyCache:  cache,
		allowedAccounts: accountMap,
		logger:          logger,
		permissive:      permissive,
		stsClient:       stsClient,
	}, nil
}

// AddAllowedAccount adds an account ID to the allowed list
func (p *PolicyEngine) AddAllowedAccount(accountID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allowedAccounts[accountID] = true
}

// IsAllowed checks if a request is allowed based on its credentials
func (p *PolicyEngine) IsAllowed(req *http.Request) bool {
	// In permissive mode, always allow
	if p.permissive {
		return true
	}

	// Check if the request is for an amazonaws.com subdomain
	host := req.Host
	if !strings.HasSuffix(host, ".amazonaws.com") {
		p.logger.Printf("BLOCK: Request to non-amazonaws.com domain: %s", host)
		return false
	}

	// Extract the access key ID from the Authorization header
	accessKeyID := p.extractAccessKeyID(req)
	if accessKeyID == "" {
		p.logger.Printf("BLOCK: No access key ID found in request")
		return false
	}

	// Check if the access key is in the cache
	if info, ok := p.getAccessKeyInfo(accessKeyID); ok {
		p.logger.Printf("PASS: Access key %s, account: %s, role_arn: %s", 
			accessKeyID, info.AccountID, info.RoleARN)
		return true
	}

	// If the key is not in the cache, validate it with STS.GetAccessKeyInfo
	input := &sts.GetAccessKeyInfoInput{
		AccessKeyId: &accessKeyID,
	}

	result, err := p.stsClient.GetAccessKeyInfo(context.Background(), input)
	if err != nil {
		p.logger.Printf("BLOCK: Error validating access key %s: %v", accessKeyID, err)
		return false
	}

	accountID := *result.Account
	allowed := p.allowedAccounts[accountID]

	// If allowed, add to cache
	if allowed {
		p.CacheAccessKey(accessKeyID, accountID, "")
		p.logger.Printf("PASS: Access key %s from allowed account %s has been cached", accessKeyID, accountID)
		return true
	}
	p.logger.Printf("BLOCK: Access key %s from account %s is not allowed", accessKeyID, accountID)
	return false
}

// extractAccessKeyID extracts the AWS access key ID from the Authorization header
func (p *PolicyEngine) extractAccessKeyID(req *http.Request) string {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	// AWS Signature Version 4 format: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, ...
	credStart := strings.Index(authHeader, "Credential=")
	if credStart < 0 {
		return ""
	}

	// Extract the access key ID portion
	credPart := authHeader[credStart+11:]
	slashPos := strings.Index(credPart, "/")
	if slashPos < 0 {
		return ""
	}

	return credPart[:slashPos]
}

// getAccessKeyInfo gets the cached information for an access key
func (p *PolicyEngine) getAccessKeyInfo(accessKeyID string) (*AccessKeyInfo, bool) {
	// First try with the original key
	value, ok := p.accessKeyCache.Get(accessKeyID)
	if ok {
		return value.(*AccessKeyInfo), true
	}

	// If not found, try with the > prefix (which seems to be added by the LRU cache)
	value, ok = p.accessKeyCache.Get(">" + accessKeyID)
	if ok {
		return value.(*AccessKeyInfo), true
	}

	// Not found in either format
	return nil, false
}

// CacheAccessKey caches an access key with its account ID and role ARNs
func (p *PolicyEngine) CacheAccessKey(accessKeyID, accountID string, roleARN string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	info := &AccessKeyInfo{
		AccessKeyID: accessKeyID,
		AccountID:   accountID,
		RoleARN:    roleARN,
	}
	p.accessKeyCache.Add(accessKeyID, info)
}

// IsAssumeRole checks if a request is an STS AssumeRole request
func (p *PolicyEngine) IsAssumeRole(req *http.Request) bool {
	// Check if the request is to the STS service
	if !strings.Contains(req.Host, "sts.") {
		return false
	}

	// If there's no body, it's not an AssumeRole request
	if req.Body == nil {
		return false
	}

	// Read the request body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return false
	}

	// Create a new reader for the request body
	req.Body = io.NopCloser(bytes.NewReader(body))

	return strings.Contains(string(body), "Action=AssumeRole")
}

// ProcessAssumeRoleResponse processes an AssumeRole response to extract role information
func (p *PolicyEngine) ProcessAssumeRoleResponse(req *http.Request, bodyBytes []byte) {
	body := string(bodyBytes)

	// Extract the source access key ID from the request
	sourceAccessKeyID := p.extractAccessKeyID(req)
	if sourceAccessKeyID == "" {
		p.logger.Printf("BAD RESPONSE: No source access key ID found in AssumeRole request: %s", body)
		return
	}

	// Extract the ARN from the response
	arnStart := strings.Index(body, "<Arn>")
	arnEnd := strings.Index(body, "</Arn>")
	if arnStart < 0 || arnEnd <= arnStart {
		p.logger.Printf("BAD RESPONSE: No ARN found in AssumeRole response: %s", body)
		return
	}

	roleARN := body[arnStart+5 : arnEnd]

	// Extract the new access key ID from the response
	keyStart := strings.Index(body, "<AccessKeyId>")
	keyEnd := strings.Index(body, "</AccessKeyId>")
	if keyStart < 0 || keyEnd <= keyStart {
		p.logger.Printf("BAD RESPONSE: No AccessKeyId found in AssumeRole response: %s", body)
		return
	}

	newAccessKeyID := body[keyStart+13 : keyEnd]
	// Verify once again that the source access key is in our cache and allowed
	_, ok := p.getAccessKeyInfo(sourceAccessKeyID)
	if !ok {
		p.logger.Printf("BAD RESPONSE: Source access key %s not in allowed - why did even pass this request? %s", 
		sourceAccessKeyID, body)
		return
	}

	// Cache the new access key with the role ARN
	p.CacheAccessKey(newAccessKeyID, "", roleARN)
	p.logger.Printf("PARSED: Access key %s -> %s", newAccessKeyID, roleARN)
}

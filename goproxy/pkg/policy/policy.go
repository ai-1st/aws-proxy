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
	RoleARNs    []string
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
		logger.Printf("Added allowed account: %s", account)
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
	p.logger.Printf("Added allowed account: %s", accountID)
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
		p.logger.Printf("Request to non-amazonaws.com domain blocked: %s", host)
		return false
	}

	// Extract the access key ID from the Authorization header
	accessKeyID := p.extractAccessKeyID(req)
	if accessKeyID == "" {
		p.logger.Printf("No access key ID found in request")
		return false
	}

	// Check if the access key is in the cache
	if info, ok := p.getAccessKeyInfo(accessKeyID); ok {
		p.logger.Printf("Access key %s found in cache (account: %s)", accessKeyID, info.AccountID)
		return true
	}

	// If the key is not in the cache, validate it with STS.GetAccessKeyInfo
	p.logger.Printf("Access key %s not found in cache, validating with STS", accessKeyID)
	allowed, err := p.validateAccessKey(req.Context(), accessKeyID)
	if err != nil {
		p.logger.Printf("Error validating access key %s: %v", accessKeyID, err)
		return false
	}

	return allowed
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

// validateAccessKey validates an access key with STS.GetAccessKeyInfo
func (p *PolicyEngine) validateAccessKey(ctx context.Context, accessKeyID string) (bool, error) {
	input := &sts.GetAccessKeyInfoInput{
		AccessKeyId: &accessKeyID,
	}

	result, err := p.stsClient.GetAccessKeyInfo(ctx, input)
	if err != nil {
		return false, err
	}

	accountID := *result.Account
	p.logger.Printf("Access key %s belongs to account %s", accessKeyID, accountID)

	// Check if the account is allowed
	p.mu.RLock()
	allowed := p.allowedAccounts[accountID]
	p.mu.RUnlock()

	// If allowed, add to cache
	if allowed {
		p.CacheAccessKey(accessKeyID, accountID, nil)
		p.logger.Printf("Access key %s from allowed account %s has been cached", accessKeyID, accountID)
	} else {
		p.logger.Printf("Access key %s from account %s is not allowed", accessKeyID, accountID)
	}

	return allowed, nil
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
func (p *PolicyEngine) CacheAccessKey(accessKeyID, accountID string, roleARNs []string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	info := &AccessKeyInfo{
		AccessKeyID: accessKeyID,
		AccountID:   accountID,
		RoleARNs:    roleARNs,
	}
	p.accessKeyCache.Add(accessKeyID, info)
	p.logger.Printf("Cached access key %s for account %s with roles %v", accessKeyID, accountID, roleARNs)
}

// IsAssumeRole checks if a request is an STS AssumeRole request
func (p *PolicyEngine) IsAssumeRole(req *http.Request) bool {
	// Check if the request is to the STS service
	if !strings.Contains(req.Host, "sts.") {
		p.logger.Printf("Request to non-STS domain: %s", req.Host)
		return false
	}

	// If there's no body, it's not an AssumeRole request
	if req.Body == nil {
		p.logger.Printf("No request body")
		return false
	}

	// Read the request body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		p.logger.Printf("Error reading request body: %v", err)
		return false
	}

	// Create a new reader for the request body
	req.Body = io.NopCloser(bytes.NewReader(body))

	p.logger.Printf("Request body: %s", string(body))

	return strings.Contains(string(body), "Action=AssumeRole")
}

// ProcessAssumeRoleResponse processes an AssumeRole response to extract role information
func (p *PolicyEngine) ProcessAssumeRoleResponse(req *http.Request, bodyBytes []byte) {
	body := string(bodyBytes)

	// Extract the source access key ID from the request
	sourceAccessKeyID := p.extractAccessKeyID(req)
	if sourceAccessKeyID == "" {
		p.logger.Printf("No source access key ID found in AssumeRole request")
		return
	}

	// Extract the ARN from the response
	arnStart := strings.Index(body, "<Arn>")
	arnEnd := strings.Index(body, "</Arn>")
	if arnStart < 0 || arnEnd <= arnStart {
		p.logger.Printf("No ARN found in AssumeRole response")
		return
	}

	roleARN := body[arnStart+5 : arnEnd]
	p.logger.Printf("Extracted ARN from AssumeRole: %s", roleARN)

	// Extract the new access key ID from the response
	keyStart := strings.Index(body, "<AccessKeyId>")
	keyEnd := strings.Index(body, "</AccessKeyId>")
	if keyStart < 0 || keyEnd <= keyStart {
		p.logger.Printf("No AccessKeyId found in AssumeRole response")
		return
	}

	newAccessKeyID := body[keyStart+12 : keyEnd]
	p.logger.Printf("Extracted new access key from AssumeRole: %s", newAccessKeyID)

	// Verify once again that the source access key is in our cache and allowed
	_, ok := p.getAccessKeyInfo(sourceAccessKeyID)
	if !ok {
		p.logger.Printf("Source access key %s not in allowed - why did even pass this request?", sourceAccessKeyID)
		return
	}

	// Cache the new access key with the role ARN
	p.CacheAccessKey(newAccessKeyID, "", []string{roleARN})
	p.logger.Printf("Cached access key %s with role %s", newAccessKeyID, roleARN)
}

package policy

import (
	"log"
	"net/http"
	"strings"
	"sync"
)

// PolicyEngine handles IAM role validation
type PolicyEngine struct {
	// Map of access key IDs to role ARNs
	accessKeyToRole map[string]string
	// Map of allowed role ARNs
	allowedRoles map[string]bool
	// Mutex for thread safety
	mu sync.RWMutex
	// Logger
	logger *log.Logger
	// Permissive mode - allow all requests regardless of role
	permissive bool
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(logger *log.Logger, permissive bool) *PolicyEngine {
	return &PolicyEngine{
		accessKeyToRole: make(map[string]string),
		allowedRoles:    make(map[string]bool),
		logger:          logger,
		permissive:      permissive,
	}
}

// AddAllowedRole adds a role ARN to the allowed list
func (p *PolicyEngine) AddAllowedRole(roleARN string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allowedRoles[roleARN] = true
	p.logger.Printf("Added allowed role: %s", roleARN)
}

// MapAccessKeyToRole maps an access key ID to a role ARN
func (p *PolicyEngine) MapAccessKeyToRole(accessKeyID, roleARN string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.accessKeyToRole[accessKeyID] = roleARN
	p.logger.Printf("Mapped access key %s to role %s", accessKeyID, roleARN)
}

// IsAllowed checks if a request is allowed based on its credentials
func (p *PolicyEngine) IsAllowed(req *http.Request) bool {
	// In permissive mode, always allow
	if p.permissive {
		return true
	}

	// Extract the access key ID from the Authorization header
	// In a real implementation, we would parse the SigV4 signature
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		// No Authorization header, allow if it's a GetCallerIdentity request
		// as it will help us map the credentials later
		return p.isGetCallerIdentity(req)
	}

	// For now, just log that we found an Authorization header
	// In a real implementation, we would extract the access key ID and check if it's allowed
	p.logger.Printf("Found Authorization header, would check access key ID in full implementation")

	// Always allow in this permissive implementation
	return true
}

// isGetCallerIdentity checks if a request is a GetCallerIdentity call
func (p *PolicyEngine) isGetCallerIdentity(req *http.Request) bool {
	// Check if this is an STS request
	if !strings.Contains(req.Host, "sts.amazonaws.com") {
		return false
	}

	// Check if this is a GetCallerIdentity action
	// This could be in the URL path, query parameters, or X-Amz-Target header
	if strings.Contains(req.URL.Path, "GetCallerIdentity") {
		return true
	}

	if req.URL.Query().Get("Action") == "GetCallerIdentity" {
		return true
	}

	if strings.Contains(req.Header.Get("X-Amz-Target"), "GetCallerIdentity") {
		return true
	}

	return false
}

// ProcessSTSResponse processes an STS response to extract role information
func (p *PolicyEngine) ProcessSTSResponse(req *http.Request, resp *http.Response) {
	// In a real implementation, we would parse the response to extract role information
	// For now, just log that we found an STS response
	if strings.Contains(req.Host, "sts.amazonaws.com") {
		p.logger.Printf("STS response detected - would parse for role information in full implementation")
	}
}

// ProcessGetCallerIdentityResponse processes a GetCallerIdentity response to extract role information
func (p *PolicyEngine) ProcessGetCallerIdentityResponse(req *http.Request, resp *http.Response) {
	// In a real implementation, we would parse the response to extract role information
	// For now, just log that we found a GetCallerIdentity response
	if p.isGetCallerIdentity(req) {
		p.logger.Printf("GetCallerIdentity response detected - would parse for role information in full implementation")
	}
}

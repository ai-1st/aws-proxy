package policy

import (
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccessKeyCache(t *testing.T) {
	// Create a new policy engine with a test logger
	allowedAccounts := []string{"123456789012"}
	testLogger := log.New(io.Discard, "", 0)
	engine, err := NewPolicyEngine(testLogger, false, allowedAccounts)
	if err != nil {
		t.Fatalf("Failed to create policy engine: %v", err)
	}

	// Manually add a test access key to the cache
	testAccessKey := "AKIATESTKEY12345678"
	testAccountID := "123456789012"
	testRoles := []string{"arn:aws:iam::123456789012:role/test-role"}
	
	engine.CacheAccessKey(testAccessKey, testAccountID, testRoles)
	
	// Verify the key is in the cache
	info, found := engine.getAccessKeyInfo(testAccessKey)
	if !found {
		t.Fatalf("Access key not found in cache after adding")
	}
	
	if info.AccountID != testAccountID {
		t.Errorf("Expected account ID %s, got %s", testAccountID, info.AccountID)
	}
	
	if len(info.RoleARNs) != 1 || info.RoleARNs[0] != testRoles[0] {
		t.Errorf("Expected roles %v, got %v", testRoles, info.RoleARNs)
	}
	
	// Test with a request that has the cached access key
	req := httptest.NewRequest("GET", "https://sts.amazonaws.com/", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+testAccessKey+"/20230101/us-east-1/sts/aws4_request")
	
	// Should be allowed since the key is in the cache and account is whitelisted
	if !engine.IsAllowed(req) {
		t.Errorf("Request with cached access key should be allowed")
	}
	
	// Test with an unknown access key
	req = httptest.NewRequest("GET", "https://sts.amazonaws.com/", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAUNKNOWNKEY12345/20230101/us-east-1/sts/aws4_request")
	
	// Should not be allowed since the key is not in the cache
	if engine.IsAllowed(req) {
		t.Errorf("Request with unknown access key should not be allowed")
	}
	
	// Test GetCallerIdentity request (should be allowed even with unknown key)
	req = httptest.NewRequest("POST", "https://sts.amazonaws.com/", strings.NewReader("Action=GetCallerIdentity&Version=2011-06-15"))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAUNKNOWNKEY12345/20230101/us-east-1/sts/aws4_request")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	// Should be allowed since it's a GetCallerIdentity request
	if !engine.IsAllowed(req) {
		t.Errorf("GetCallerIdentity request should be allowed")
	}
	
	// Test processing STS AssumeRole response
	assumeRoleResp := `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
	  <AssumeRoleResult>
		<Credentials>
		  <AccessKeyId>ASIATESTASSUMEDROLE</AccessKeyId>
		  <SecretAccessKey>secretKey</SecretAccessKey>
		  <SessionToken>sessionToken</SessionToken>
		  <Expiration>2023-01-01T00:00:00Z</Expiration>
		</Credentials>
		<AssumedRoleUser>
		  <AssumedRoleId>AROATESTID:session</AssumedRoleId>
		  <Arn>arn:aws:sts::123456789012:assumed-role/test-role/session</Arn>
		</AssumedRoleUser>
	  </AssumeRoleResult>
	</AssumeRoleResponse>`
	
	// Create an AssumeRole request
	req = httptest.NewRequest("POST", "https://sts.amazonaws.com/", strings.NewReader("Action=AssumeRole&Version=2011-06-15"))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+testAccessKey+"/20230101/us-east-1/sts/aws4_request")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	// Process the response
	engine.ProcessSTSResponse(req, []byte(assumeRoleResp))
	
	// Verify the assumed role key is in the cache
	assumedKeyInfo, found := engine.getAccessKeyInfo("ASIATESTASSUMEDROLE")
	if !found {
		t.Fatalf("Assumed role access key not found in cache after processing response")
	}
	
	if assumedKeyInfo.AccountID != testAccountID {
		t.Errorf("Expected account ID %s for assumed role, got %s", testAccountID, assumedKeyInfo.AccountID)
	}
	
	expectedRole := "arn:aws:sts::123456789012:assumed-role/test-role/session"
	if len(assumedKeyInfo.RoleARNs) != 1 || assumedKeyInfo.RoleARNs[0] != expectedRole {
		t.Errorf("Expected role %s for assumed role, got %v", expectedRole, assumedKeyInfo.RoleARNs)
	}
}

# aws-proxy: Design and Implementation Plan

## Overview and Motivation

**Use Case:** The `aws-proxy` tool is a man-in-the-middle (MITM) proxy designed to intercept and inspect AWS API calls made by applications (e.g. third-party Lambda functions, EC2 instances, Fargate tasks) within a VPC. The primary motivations are to enforce security policies and improve efficiency:

1. **Security Policy Enforcement:** Ensure that **only approved IAM roles** (or roles assumed from those approved roles) are used in AWS API calls. By intercepting calls, `aws-proxy` can detect if credentials belong to whitelisted roles and **block** any attempts to use unauthorized credentials or assume disallowed roles. This prevents malicious or inadvertent data exfiltration to external AWS accounts by permitting only trusted roles/credentials.

2. **Caching of Redundant Calls:** Many AWS API calls (especially in AI/ML contexts like Amazon Bedrock model inferences) can be repeated with identical inputs. `aws-proxy` will cache responses for such repeated requests to **reduce latency and costs**. By avoiding redundant calls to AWS for identical requests, we can lower response times, minimize cost, and reduce the chance of hitting AWS service rate limits.

In summary, `aws-proxy` acts as a secure gatekeeper for AWS API traffic in the VPC – **inspecting requests for compliance with IAM role policies and caching frequent responses** – without requiring changes to the applications themselves.


## Traffic Routing and Enforcement Methods

To ensure all AWS API calls go through `aws-proxy`, we can employ several routing strategies (or a combination thereof):

- **HTTP(S)_PROXY Environment Variable:** Many AWS SDKs and tools (including the AWS CLI) respect the `HTTP_PROXY` and/or `HTTPS_PROXY` environment variables. By injecting an environment variable pointing to the `aws-proxy` endpoint, outbound AWS requests will be directed to the proxy. For example, setting `HTTPS_PROXY=http://<proxy-host>:<port>` means all HTTPS calls go via `aws-proxy`. This method is straightforward in environments where we can control environment variables (e.g., Lambda environment variables, container environment files, EC2 user-data scripts).

- **/etc/hosts DNS Override:** Overriding DNS resolution of AWS service domains to point to the proxy’s IP forces the application to connect to the proxy, even if the application does not recognize environment proxy settings. For example, mapping `sts.amazonaws.com` to the proxy’s IP address ensures the application tries to connect to the proxy instead of AWS.

- **Default Route (Subnet Routing/NAT):** At the VPC network level, we can replace or complement the NAT gateway with an instance (or container) running `aws-proxy`, making it the default route for outbound traffic. This “transparent proxy” setup ensures even if the application attempts to connect directly to the real AWS endpoints, the traffic is still routed through `aws-proxy`.

Which approach is chosen depends on the deployment environment and the degree of control over the application’s configuration. In all cases, **the end result is that the application’s outbound AWS requests will be intercepted** by the proxy.


## Man-in-the-Middle TLS Interception Design

Since AWS API calls are typically HTTPS, `aws-proxy` must perform TLS interception (MITM) to inspect requests. This involves:

- Generating or having an internal **Root CA** certificate that the client environment trusts.
- Dynamically generating certificates for AWS endpoints (e.g., `s3.amazonaws.com`, `bedrock.us-west-2.amazonaws.com`) signed by this internal CA.
- Terminating the TLS connection from the client and establishing a separate TLS connection to the real AWS endpoint, thus allowing the proxy to inspect and (optionally) modify the request/response.

**Embedding the CA in Clients:** We need to install the root CA certificate into the trust store or the SDK environment for each platform (EC2, ECS, Fargate, Lambda) so that the proxy’s forged certificates are accepted as valid. For Lambda, we can embed the certificate in a layer and set `AWS_CA_BUNDLE`. For EC2 or container images, we can insert the CA into the system’s certificate store.


## Excluding Metadata Calls & Handling Credential Retrieval

When an application (such as an EC2 instance or Lambda environment) starts, it typically retrieves temporary credentials from the **instance metadata service** (for EC2, or automatically from the Lambda environment). The response from the metadata service does **not** contain the full IAM role ARN, but only credential strings (access key, secret key, token). We **do not** need to intercept these metadata calls for the proxy’s security enforcement, and in many cases, the metadata call is local (169.254.169.254) and does not traverse the VPC in the same way as normal internet-bound traffic. Thus, `aws-proxy` is not required to intercept them.

However, any **new** role that the application uses (i.e., not obtained via a recognized `AssumeRole` path) must be validated. Therefore, we require that if an application obtains credentials from metadata (which do not explicitly show the role ARN), the application must call `GetCallerIdentity` so that `aws-proxy` can learn the actual role ARN being used. This call is always allowed to pass through **unblocked** since it cannot be used to exfiltrate data. Once the proxy sees the `GetCallerIdentity` response (which includes the account and the ARN), it can evaluate whether to allow subsequent calls with these credentials.


## Handling CONNECT Tunnels vs Direct HTTPS

Depending on the routing method:

- **Explicit Proxy (CONNECT method):** If `HTTP_PROXY` is set, the AWS SDK typically sends an HTTP `CONNECT` request to the proxy. The proxy acknowledges and then performs a TLS handshake with the client. It likewise opens a TLS connection to the AWS endpoint. 
- **Transparent Mode:** If using DNS override or default route, the client initiates a direct TLS handshake to `aws-proxy` (assuming it’s the real AWS). `aws-proxy` sees the SNI for the AWS host and uses the correct certificate. The rest of the interception logic is the same.

In both cases, we end up with **two distinct TLS sessions** (client -> proxy and proxy -> AWS) to allow full inspection.


## Security Policy Enforcement (IAM Role Whitelisting)

**Whitelisted Roles/Accounts:** The proxy has a config specifying which IAM Role ARNs (or which AWS account IDs) are allowed. If a role is recognized, it can proceed; if not, requests are blocked.

**Enforcement Mechanism:** Every AWS API call includes an `Authorization` header (SigV4). From it, the proxy extracts the Access Key ID. The proxy must know which role that Access Key ID belongs to:
1. If the application used `AssumeRole`, `aws-proxy` sees the STS call in real-time and can record the resulting temporary Access Key ID as belonging to the newly assumed role (if it’s whitelisted).
2. If the application obtains credentials from the instance metadata (i.e., outside of `AssumeRole`), we require it to call `GetCallerIdentity` so the proxy can see the role’s ARN. The proxy marks that Access Key ID as belonging to that ARN (which is either allowed or not). 
3. The proxy always lets `GetCallerIdentity` calls pass so that it can discover role ARNs. (These calls carry minimal risk of data exfiltration.)
4. When the proxy sees a request signed with an Access Key ID that it has not yet mapped to an allowed role, it blocks the request. Conversely, if the mapped role is not in the whitelist, it also blocks.

**Blocked Requests:** If a request fails the role check, `aws-proxy` can return HTTP 403 or a TLS handshake failure. The attempt is recorded in logs.

**STS `AssumeRole` Inspection:** For calls to `sts.amazonaws.com`, if the role to be assumed is unapproved, the proxy blocks the request so that the application can’t obtain unauthorized temporary credentials.

This ensures that all calls from an unrecognized role are disallowed, preventing any chance of external or rogue roles accessing internal resources.


## Response Caching Strategy

`aws-proxy` will cache responses for repeated requests with identical payloads. This is especially useful for certain services (e.g., Bedrock model inferences) where identical inputs produce identical outputs, or for read-only queries.

- **Cache Key:** Derived from the normalized request data (host, path, method, relevant headers, request body). Exclude ephemeral data (like timestamps or signatures).
- **Cached Response:** Stored with an appropriate TTL. Might be short to avoid staleness. The proxy returns the cached response for subsequent matching requests.
- **Implementation:** For ephemeral usage, an in-memory store (like a map or LRU structure) is sufficient. If multiple proxy instances need to share the cache, a distributed store (like Redis) might be used. 
- **Security:** We must ensure sensitive data in responses is not stored longer than needed, or we encrypt at rest if the caching solution demands it. 
- **Logging:** Cache hits and misses can be logged for operational insight.


## **Open-Source Go Implementation** (New Option)

In addition to other platform approaches, we propose a **simple, open-source design** using Go:

### Objectives

- **Simplicity:** Provide a lean, performant codebase that’s straightforward for others to inspect and understand.
- **Transparency:** Use standard Go libraries and well-known open-source modules, avoiding complex or proprietary Nginx extensions or heavy frameworks.
- **Reviewability:** Give clear documentation, modular code structure, and minimal dependencies so that enterprise security teams can audit the code.  

### Implementation Details

1. **Language**: **Go**  
   - Offers a good balance of performance and straightforward concurrency (goroutines, channels).  
   - Produces a single statically compiled binary for easy deployment.

2. **Libraries**:
   - [`goproxy`](https://github.com/elazarl/goproxy) for core MITM proxy features:
     - Handles HTTP(S) interception.  
     - Manages the `CONNECT` method to create tunnels.  
     - Supports dynamic certificate generation for MITM.  
   - `crypto/tls` for lower-level TLS config (e.g., generating root CA cert or ephemeral certs).  
   - `bigcache` (or similar in-memory caching library) to implement a thread-safe, performant cache.  

3. **Request Flow**:
   1. The client, configured with `HTTPS_PROXY`, issues a `CONNECT` request to the proxy (e.g., `CONNECT bedrock.us-west-2.amazonaws.com:443 HTTP/1.1`).  
   2. `aws-proxy` (using `goproxy`) accepts the tunnel, generates/presents a forged certificate for `bedrock.us-west-2.amazonaws.com` signed by the internal CA.  
   3. The client verifies that certificate (it trusts the internal CA). Now the client sends the actual HTTPS request.  
   4. The proxy decrypts the request, extracts the Access Key ID from the `Authorization` header, and validates the IAM role:  
      - If the proxy does not know the role mapping for this key, it checks if this is a `GetCallerIdentity` (which is always allowed). If so, the proxy sees the ARN in the response and updates the key-to-ARN mapping. If it’s any other call from an unknown key, block it.  
      - If the role is known but not in the whitelist, block the request.  
   5. If the request is allowed, the proxy checks the cache. On a cache hit, it returns the stored response immediately; on a miss, it forwards the request over a new TLS connection to the real AWS endpoint.  
   6. Upon receiving the response from AWS, it stores it in `bigcache` with a TTL (if caching is enabled for this request type). Then it encrypts the response back to the client.  

4. **STS and Credential Mapping**:
   - For `AssumeRole` calls (to `sts.amazonaws.com`), parse the request payload to see the target role. If not whitelisted, block. If whitelisted, when the proxy sees the STS response, it extracts the new Access Key ID from the temporary credentials and adds it to the known-good map for the session’s duration.  
   - For credentials obtained via instance metadata, the application is required to call `GetCallerIdentity` at least once so that the proxy can discover the role ARN for the new Access Key ID.  

5. **Certificate Authority and Distribution**:
   - The internal CA is generated (e.g., upon installation or first startup) or can be provided as files in the container/host.  
   - The root certificate is installed in the relevant trust store for clients.  
   - `goproxy` automatically generates ephemeral certificates for each domain on the fly, signed by the root CA.  

6. **Logging & Observability**:
   - Every request can be logged (e.g., as an HTTP access log with the role check result).  
   - A separate security log tracks blocked calls (role mismatch) and critical STS calls.  
   - Cache hit/miss metrics could be exposed via a simple `/metrics` endpoint if we want to integrate with Prometheus.  

### Pros & Cons

- **Pros**:
  - **High-level Code**: Easier to audit than large Nginx configs and custom C modules.  
  - **Extensible**: We can add new logic in Go as needed (e.g., additional STS validations, custom caching logic).  
  - **Single Binary**: Deployment is straightforward.  
  - **Good Concurrency**: Go is well-suited for a proxy that may handle many simultaneous requests.

- **Cons**:
  - **Custom Implementation**: We must maintain the MITM logic ourselves (though `goproxy` covers the basics).  
  - **Performance**: Although Go is performant, raw Nginx might handle extremely high RPS more efficiently. For most use cases, Go is likely sufficient.

This Go-based approach should meet the needs for a simpler, open-source proxy that enterprise security teams can adopt with minimal friction, while still providing the MITM interception and caching features required.


## Proposed Architecture and Component Design

Below is a **high-level architecture** showing the major components. The arrangement is similar for any platform choice (Nginx/OpenResty, Python/mitmproxy, or Go/goproxy), but we highlight the Go approach here:

1. **Proxy Server** (Go + goproxy)
   - Receives connections from clients (over CONNECT or transparent routing).
   - Terminates TLS with a dynamically generated certificate for the AWS endpoint.
   - Inspects the request (headers, body).
   - Calls into **Policy Engine** to validate IAM role usage.
   - Retrieves or stores data in the **Cache** if caching is enabled for that request.
   - Forwards the request to AWS over a separate TLS connection, returning the response to the client.

2. **Certificate Authority (CA) & Cert Manager**:
   - Maintains the root CA private key, used to sign ephemeral certificates for each AWS domain.
   - The root certificate is pre-installed on all client systems so they trust our MITM certificates.

3. **Policy Engine**:
   - Maintains a whitelist of allowed role ARNs or account IDs.
   - Maps Access Key IDs to roles (discovered via STS calls or `GetCallerIdentity`).
   - Allows or blocks requests based on whether the role is recognized and whitelisted.

4. **Cache** (in-memory or distributed):
   - Receives requests to store or retrieve responses based on a cache key derived from the request.
   - Applies TTL and eviction policies.

5. **AWS Upstream**:
   - The proxy connects to the real AWS endpoints (over TLS), verifying the upstream server certificates to avoid impersonation or man-in-the-middle at the upstream side.
   - AWS returns responses that the proxy either caches or directly returns to the client.

**Excluded: Metadata Service** – The instance metadata calls do not typically traverse the proxy and do not need interception. Instead, we rely on `GetCallerIdentity` to reveal new Access Key -> ARN mappings for any roles obtained from metadata.

**Sequence Diagram** (CONNECT scenario):
1. Application sets `HTTPS_PROXY` to `aws-proxy`.
2. Application calls an AWS endpoint; the HTTP library sends `CONNECT endpoint:443`.
3. `aws-proxy` acknowledges, does TLS handshake with the client using a forged cert for `endpoint`.
4. The client sends the encrypted request. `aws-proxy` decrypts and extracts credentials.
5. `aws-proxy` checks if it’s a `GetCallerIdentity` call or if the Access Key is known/allowed. If blocked, returns 403. If allowed, checks cache.
6. If cache miss, the proxy opens a TLS connection to the real AWS. Once AWS responds, it optionally caches and then returns the data to the client.


## Summary

By intercepting and inspecting AWS API calls, `aws-proxy` enforces strict role usage policies and can substantially reduce redundant calls. The updated specification includes:

- The requirement that roles obtained from instance metadata must be validated via `GetCallerIdentity`.
- An **open-source Go** implementation option using `goproxy`, which emphasizes **simplicity, transparency, and reviewability** for enterprise security teams. 
- Retained design elements (TLS MITM, dynamic cert generation, STS whitelisting, caching) and flexible routing enforcement options.

This design should be straightforward to implement, maintain, and audit, providing robust security controls and cost-saving optimizations in AWS environments.
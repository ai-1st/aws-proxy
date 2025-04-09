# aws-proxy: Design and Implementation Plan

## Overview and Motivation

**Use Case:** The `aws-proxy` tool is a man-in-the-middle (MITM) proxy designed to intercept and inspect AWS API calls made by applications (e.g. third-party Lambda functions, EC2 instances, Fargate tasks) within a VPC. The primary motivations are to enforce security policies and improve efficiency:

1. **Security Policy Enforcement:** Ensure that **only approved IAM roles** (or roles assumed from those approved roles) are used in AWS API calls. By intercepting calls, `aws-proxy` can detect if credentials belong to whitelisted roles and **block** any attempts to use unauthorized credentials or assume disallowed roles. This prevents malicious or inadvertent data exfiltration to external AWS accounts by permitting only trusted roles/credentials.

2. **Caching of Redundant Calls:** Many AWS API calls (especially in AI/ML contexts like Amazon Bedrock model inferences) can be repeated with identical inputs. `aws-proxy` will cache responses for such repeated requests to **reduce latency and costs**. By avoiding redundant calls to AWS for identical requests, we can lower response times, minimize cost, and reduce the chance of hitting AWS service rate limits.

In summary, `aws-proxy` acts as a secure gatekeeper for AWS API traffic in the VPC – **inspecting requests for compliance with IAM role policies and caching frequent responses** – without requiring changes to the applications themselves.

## Generic MITM Proxy Design

### Traffic Routing and Enforcement Methods

To ensure all AWS API calls go through `aws-proxy`, we can employ several routing strategies (or a combination thereof):

- **HTTP(S)_PROXY Environment Variable:** Many AWS SDKs and tools (including the AWS CLI) respect the `HTTP_PROXY` and/or `HTTPS_PROXY` environment variables. By injecting an environment variable pointing to the `aws-proxy` endpoint, outbound AWS requests will be directed to the proxy. For example, setting `HTTPS_PROXY=http://<proxy-host>:<port>` means all HTTPS calls go via `aws-proxy`. This method is straightforward in environments where we can control environment variables (e.g., Lambda environment variables, container environment files, EC2 user-data scripts).

- **/etc/hosts DNS Override:** Overriding DNS resolution of AWS service domains to point to the proxy's IP forces the application to connect to the proxy, even if the application does not recognize environment proxy settings. For example, mapping `sts.amazonaws.com` to the proxy's IP address ensures the application tries to connect to the proxy instead of AWS.

- **Default Route (Subnet Routing/NAT):** At the VPC network level, we can replace or complement the NAT gateway with an instance (or container) running `aws-proxy`, making it the default route for outbound traffic. This "transparent proxy" setup ensures even if the application attempts to connect directly to the real AWS endpoints, the traffic is still routed through `aws-proxy`.

Which approach is chosen depends on the deployment environment and the degree of control over the application's configuration. In all cases, **the end result is that the application's outbound AWS requests will be intercepted** by the proxy.

### Man-in-the-Middle TLS Interception Design

Since AWS API calls are typically HTTPS, `aws-proxy` must perform TLS interception (MITM) to inspect requests. This involves:

- Generating or having an internal **Root CA** certificate that the client environment trusts.
- Dynamically generating certificates for AWS endpoints (e.g., `s3.amazonaws.com`, `bedrock.us-west-2.amazonaws.com`) signed by this internal CA.
- Terminating the TLS connection from the client and establishing a separate TLS connection to the real AWS endpoint, thus allowing the proxy to inspect and (optionally) modify the request/response.

**Embedding the CA in Clients:** We need to install the root CA certificate into the trust store or the SDK environment for each platform (EC2, ECS, Fargate, Lambda) so that the proxy's forged certificates are accepted as valid. For Lambda, we can embed the certificate in a layer and set `AWS_CA_BUNDLE`. For EC2 or container images, we can insert the CA into the system's certificate store.

### Excluding Metadata Calls & Handling Credential Retrieval

When an application (such as an EC2 instance or Lambda environment) starts, it typically retrieves temporary credentials from the **instance metadata service** (for EC2, or automatically from the Lambda environment). The response from the metadata service does **not** contain the full IAM role ARN, but only credential strings (access key, secret key, token). We **do not** need to intercept these metadata calls for the proxy's security enforcement, and in many cases, the metadata call is local (169.254.169.254) and does not traverse the VPC in the same way as normal internet-bound traffic. Thus, `aws-proxy` is not required to intercept them.

### Handling CONNECT Tunnels vs Direct HTTPS

Depending on the routing method:

- **Explicit Proxy (CONNECT method):** If `HTTP_PROXY` is set, the AWS SDK typically sends an HTTP `CONNECT` request to the proxy. The proxy acknowledges and then performs a TLS handshake with the client. It likewise opens a TLS connection to the AWS endpoint. 
- **Transparent Mode:** If using DNS override or default route, the client initiates a direct TLS handshake to `aws-proxy` (assuming it's the real AWS). `aws-proxy` sees the SNI for the AWS host and uses the correct certificate. The rest of the interception logic is the same.

In both cases, we end up with **two distinct TLS sessions** (client -> proxy and proxy -> AWS) to allow full inspection.

## Access Key Control and Validation

### Security Policy Enforcement (IAM Role Whitelisting)

**Whitelisted Roles/Accounts:** The proxy has a config specifying which IAM Role ARNs (or which AWS account IDs) are allowed. If a role is recognized, it can proceed; if not, requests are blocked.

**Enforcement Mechanism:** Every AWS API call includes an `Authorization` header (SigV4). From it, the proxy extracts the Access Key ID. The proxy must know which role that Access Key ID belongs to:
1. If the application used `AssumeRole`, `aws-proxy` sees the STS call in real-time and can record the resulting temporary Access Key ID as belonging to the newly assumed role (if it's whitelisted).
2. If the application obtains credentials from the instance metadata (i.e., outside of `AssumeRole`), we require it to call `GetCallerIdentity` so the proxy can see the role's ARN. The proxy marks that Access Key ID as belonging to that ARN (which is either allowed or not). 
3. The proxy always lets `GetCallerIdentity` calls pass so that it can discover role ARNs. (These calls carry minimal risk of data exfiltration.)
4. When the proxy sees a request signed with an Access Key ID that it has not yet mapped to an allowed role, it blocks the request. Conversely, if the mapped role is not in the whitelist, it also blocks.

**Blocked Requests:** If a request fails the role check, `aws-proxy` can return HTTP 403 or a TLS handshake failure. The attempt is recorded in logs.

**STS `AssumeRole` Inspection:** For calls to `sts.amazonaws.com`, if the role to be assumed is unapproved, the proxy blocks the request so that the application can't obtain unauthorized temporary credentials.

This ensures that all calls from an unrecognized role are disallowed, preventing any chance of external or rogue roles accessing internal resources.

### Access Key Validation and LRU Caching

The `aws-proxy` implements an LRU (Least Recently Used) cache to efficiently map AWS access keys to their corresponding account IDs and IAM roles. This approach provides several benefits:

1. **Improved Performance**: By caching validated access keys, we can avoid redundant validation calls to AWS STS for subsequent requests using the same credentials.

2. **Reduced Dependency on GetCallerIdentity**: Instead of requiring all clients to call GetCallerIdentity before using an access key, we can validate unknown keys using STS.GetAccessKeyInfo to obtain their account ID.

3. **Automatic Whitelist Enforcement**: By checking the account ID against a provided whitelist, we can ensure only approved AWS accounts are being used.

The validation and caching process works as follows:

1. **Initial Request**: When a request with an unknown Access Key ID is received:
   - Extract the Access Key ID from the Authorization header
   - Call STS.GetAccessKeyInfo to determine which AWS account it belongs to
   - Validate the account ID against a whitelist of approved accounts
   - If valid, add the key to the LRU cache with its account ID and an empty list of roles
   - If invalid, reject the request

2. **Cached Keys**: For subsequent requests with the same Access Key ID:
   - Retrieve the cached entry
   - Allow the request to proceed without additional validation

3. **Role Discovery**: When processing STS responses:
   - For GetCallerIdentity responses, extract the role ARN and update the cache
   - For AssumeRole responses, extract both the source access key and the new temporary credentials
   - Add the new temporary credentials to the cache, inheriting trust from the source key

4. **Trust Model**: Access keys are trusted if:
   - They belong to an approved account (via whitelist)
   - They were issued by STS in response to an AssumeRole call from an already trusted key

This approach maintains a strong security posture while minimizing the overhead of validation, particularly for applications that make frequent API calls with the same credentials.

## Response Caching for Duplicate Requests

### Response Caching Strategy

`aws-proxy` implements caching for responses to repeated requests with identical payloads. This is particularly valuable for services where identical inputs consistently produce the same outputs, or for read-only queries that don't modify state.

- **Cache Key Generation**: The cache key is derived from the normalized request data, including host, path, method, relevant headers, and request body. Ephemeral data such as timestamps or signatures are excluded to ensure consistent key generation.

- **Cached Response Storage**: Responses are stored with appropriate Time-To-Live (TTL) values to prevent staleness. When a matching request is received, the proxy returns the cached response without forwarding to AWS.

- **Implementation**: For ephemeral usage, an in-memory store (like a map or LRU structure) is sufficient. If multiple proxy instances need to share the cache, a distributed store (like Redis) might be used.

- **Security Considerations**: The caching mechanism ensures sensitive data in responses is not stored longer than necessary, or is encrypted at rest if the caching solution requires it.

- **Operational Insights**: Cache hits and misses are logged to provide operational visibility and help optimize caching strategies.

### Bedrock Model Invocation Caching

A particularly high-value use case for response caching is Amazon Bedrock model invocations, where we've identified a significant percentage of duplicate requests:

1. **High Duplication Rate**: Analysis has shown that in many AI/ML workloads, identical prompts or inputs are frequently sent to Bedrock models, resulting in redundant API calls and increased costs.

2. **Consistent Outputs**: For deterministic models, identical inputs produce identical outputs, making these requests ideal candidates for caching.

3. **Cost Savings**: By caching Bedrock responses, we can significantly reduce the number of billable API calls, leading to substantial cost savings, especially for high-volume applications.

4. **Latency Reduction**: Cached responses can be returned immediately, reducing the latency compared to making a new API call to Bedrock.

5. **Implementation Details**:
   - The cache key includes the model ID, input parameters, and request body
   - TTL values are configurable based on the specific model and use case
   - Optional cache invalidation strategies can be implemented for models that may receive updates

6. **Metrics and Monitoring**: The proxy tracks cache hit rates and cost savings specifically for Bedrock invocations, providing insights into the effectiveness of the caching strategy.

By implementing targeted caching for Bedrock model invocations, `aws-proxy` can deliver significant performance improvements and cost reductions while maintaining the security benefits of access key validation and role enforcement.

## Implementation Options

### Open-Source Go Implementation

In addition to other platform approaches, we propose a **simple, open-source design** using Go:

#### Objectives

- **Simplicity:** Provide a lean, performant codebase that's straightforward for others to inspect and understand.
- **Transparency:** Use standard Go libraries and well-known open-source modules, avoiding complex or proprietary Nginx extensions or heavy frameworks.
- **Reviewability:** Give clear documentation, modular code structure, and minimal dependencies so that enterprise security teams can audit the code.  

#### Implementation Details

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
      - If the proxy does not know the role mapping for this key, it checks if this is a `GetCallerIdentity` (which is always allowed). If so, the proxy sees the ARN in the response and updates the key-to-ARN mapping. If it's any other call from an unknown key, block it.  
      - If the role is known but not in the whitelist, block the request.  
   5. If the request is allowed, the proxy checks the cache. On a cache hit, it returns the stored response immediately; on a miss, it forwards the request over a new TLS connection to the real AWS endpoint.  
   6. Upon receiving the response from AWS, it stores it in `bigcache` with a TTL (if caching is enabled for that request type). Then it encrypts the response back to the client.  

4. **STS and Credential Mapping**:
   - For `AssumeRole` calls (to `sts.amazonaws.com`), parse the request payload to see the target role. If not whitelisted, block. If whitelisted, when the proxy sees the STS response, it extracts the new Access Key ID from the temporary credentials and adds it to the known-good map for the session's duration.  
   - For credentials obtained via instance metadata, the application is required to call `GetCallerIdentity` at least once so that the proxy can discover the role ARN for the new Access Key ID.  

### OpenResty Implementation

An alternative implementation uses OpenResty (Nginx with Lua):

1. **Access Control**: Implemented with `access_by_lua_block` to only allow requests with known ACCESS_KEY_ID (stored in LRU cache) or GetCallerIdentity requests.

2. **Response Parsing**: Uses `body_filter_by_lua_block` to extract IAM roles from AssumeRoleResponse and GetCallerIdentityResponse.

3. **Container Setup**: Runs in a Docker container using openresty/openresty:alpine-fat image with luasocket and lua-cjson dependencies.

4. **SSL Support**: Includes self-signed certificates for HTTPS interception.

5. **Network Configuration**: Container exposes ports 80 (HTTP redirect) and 443 (HTTPS).

## Proposed Architecture and Component Design

Below is a **high-level architecture** showing the major components:

1. **Proxy Server**
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

4. **Caching System**:
   - Implements an LRU cache for both access keys and response data.
   - Provides configurable TTL settings for different request types.
   - Optimized for high-throughput services like Bedrock model invocations.
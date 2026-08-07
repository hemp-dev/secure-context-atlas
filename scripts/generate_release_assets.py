#!/usr/bin/env python3
"""Generate the reviewed 0.2-0.5 card and evaluation assets.

The generated cards are defensive, evidence-oriented records. Fixtures are
synthetic retrieval cases; they are deliberately not executable exploit code.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REVIEW_DATE = "2026-08-08"

DIRECTORIES = {
    "authorization-access": "authorization",
    "authentication-identity": "authentication",
    "injection": "injection",
    "browser-client": "browser",
    "http-proxy-cache": "http",
    "api-protocols": "api",
    "files-paths-storage": "files",
    "business-logic-state": "business",
    "availability-resources": "availability",
    "information-secrets-privacy": "secrets",
    "crypto-transport": "crypto",
    "configuration-deployment": "configuration",
    "supply-chain-cicd": "supply",
    "cloud-containers-infra": "cloud",
    "ai-llm-rag-agents": "ai",
}


def d(identifier: str, title: str, family: str, cwe: str, surfaces: list[str], platforms: list[str], summary: str, source: str, sink: str, signals: list[str], priority: str = "P1", genai: list[str] | None = None) -> dict:
    return {
        "id": identifier,
        "title": title,
        "family": family,
        "cwe": cwe,
        "surfaces": surfaces,
        "platforms": platforms,
        "summary": summary,
        "source": source,
        "sink": sink,
        "signals": signals,
        "priority": priority,
        "genai": genai or [],
    }


CARDS = [
    d("vuln.authorization.mass-assignment", "Mass assignment and unsafe property binding", "authorization-access", "CWE-915", ["REST", "GraphQL", "RPC"], ["web", "api", "mobile"], "A caller-controlled object is bound to fields that change authorization, ownership, pricing or workflow state without an explicit property policy.", "request body or patch document", "model update or security-sensitive property", ["Generic deserializer accepts privileged fields", "Allow and deny lists are not versioned", "Nested objects bypass top-level property policy"]),
    d("vuln.authorization.property-level", "Broken object-property authorization", "authorization-access", "CWE-285", ["REST", "GraphQL", "mobile API"], ["web", "api", "multi-tenant"], "A response or mutation exposes a sensitive object property even though the caller may access the surrounding object but not that property.", "field selection, request body or object serializer", "sensitive field read or write", ["Serializer returns internal fields by default", "Field policy is applied only in the UI", "GraphQL resolver trusts parent-object authorization"]),
    d("vuln.authorization.tenant-filter", "Missing tenant predicate in shared data access", "authorization-access", "CWE-639", ["REST", "GraphQL", "jobs", "search"], ["multi-tenant", "api", "database"], "A shared data-access path omits the tenant or principal predicate, allowing an otherwise valid query to cross an isolation boundary.", "tenant claim, route identifier or background job context", "database query, cache or search result", ["Repository method accepts no tenant context", "Background worker reconstructs identity incompletely", "Cache key omits tenant or authorization scope"]),
    d("vuln.authorization.webhook-signature", "Webhook signature verification bypass", "authorization-access", "CWE-345", ["webhook", "API", "queue"], ["api", "integration", "supply-chain"], "A webhook or callback is treated as trusted without authenticating its origin, binding the signature to the exact body and preventing replay.", "webhook body, headers and timestamp", "state change, job enqueue or downstream API call", ["Signature checked after parsing or normalization", "Timestamp/nonce is not bounded", "Fallback path accepts unsigned callbacks"]),
    d("vuln.authorization.delegated-admin", "Delegated administration privilege escalation", "authorization-access", "CWE-269", ["admin API", "console", "workflow"], ["web", "api", "enterprise"], "A delegated administrator receives a broader scope than the delegated resource, tenant, action or time window allows.", "role assignment, delegation request or group claim", "privileged operation or policy update", ["Role inheritance is implicit", "Scope is checked at login but not at action time", "Delegation can grant or revoke the delegator itself"]),
    d("vuln.authorization.signed-link", "Signed-link scope and expiry confusion", "authorization-access", "CWE-863", ["download", "email", "API"], ["web", "api", "storage"], "A signed URL or capability token authorizes more resources, actions or time than the issuer intended because scope and lifecycle are incomplete.", "signed link, capability token or share identifier", "file read, object mutation or privileged action", ["Signature covers an ID but not action/tenant", "Expiry is checked inconsistently", "Token is reusable after revocation or ownership change"]),
    d("vuln.authorization.service-impersonation", "Service identity and end-user impersonation confusion", "authorization-access", "CWE-441", ["service-to-service", "queue", "API"], ["microservices", "cloud", "enterprise"], "A service identity is accepted as if it represented an end user, so downstream authorization loses the original principal and tenant context.", "forwarded identity, service token or queue metadata", "downstream authorization decision", ["Caller identity is copied from an unsigned header", "Worker uses a broad service account", "Impersonation is not time- or scope-bounded"]),
    d("vuln.authorization.capability-confusion", "Capability and destination confusion", "authorization-access", "CWE-441", ["proxy", "tool", "integration"], ["api", "cloud", "ai"], "A capability intended for one destination or operation is reused for another, creating a confused deputy across principals or services.", "destination, tool name or capability token", "network call, cloud action or tool invocation", ["Destination is caller-controlled", "Capability token lacks audience", "Proxy forwards ambient authority"]),
    d("vuln.authentication.password-reset", "Password-reset token lifecycle failure", "authentication-identity", "CWE-640", ["web", "mobile", "email"], ["web", "api", "identity"], "A password-reset flow accepts a token that is predictable, reusable, unscoped, overlong-lived or not bound to the intended account and purpose.", "reset token, email link or recovery request", "credential change or account recovery", ["Token is stored or logged in plaintext", "Reset does not rotate sessions", "Account selection is inferred from client input"]),
    d("vuln.authentication.mfa-recovery", "MFA recovery and step-up bypass", "authentication-identity", "CWE-287", ["login", "recovery", "admin"], ["web", "api", "mobile"], "An account-recovery or fallback path reaches a protected operation without preserving the assurance level required by the normal MFA flow.", "recovery factor, support action or device enrollment", "session elevation or credential change", ["Recovery is weaker than the factor it replaces", "New factor can be enrolled before re-authentication", "Step-up state is represented only in the client"]),
    d("vuln.authentication.saml-validation", "SAML assertion and audience validation failure", "authentication-identity", "CWE-347", ["SAML", "SSO", "web"], ["web", "enterprise", "identity"], "A relying party creates an identity from a SAML assertion without strict issuer, audience, recipient, time, signature and subject confirmation validation.", "SAML response or assertion", "principal construction and role mapping", ["XML signature is not bound to the consumed assertion", "Audience or recipient is wildcarded", "Unsigned attributes influence authorization"]),
    d("vuln.authentication.account-enumeration", "Account and recovery-state enumeration", "authentication-identity", "CWE-204", ["login", "recovery", "registration"], ["web", "api", "identity"], "Observable response differences reveal whether an account, identifier, recovery token or administrative state exists.", "login, registration or recovery identifier", "response, timing, error or notification behaviour", ["Different status/body for existing user", "Timing reveals password or token state", "Rate limits are absent or shared incorrectly"]),
    d("vuln.authentication.password-storage", "Weak password hashing and credential storage", "authentication-identity", "CWE-916", ["login", "database", "migration"], ["web", "api", "mobile"], "Passwords or recovery secrets are stored with a fast, unsalted or misconfigured derivation that does not provide an appropriate offline-cracking cost.", "password input or credential record", "credential verifier or database", ["Plain hash or reversible encryption", "Work factor is static and obsolete", "Pepper is hardcoded or logged"]),
    d("vuln.injection.nosql", "NoSQL operator and query injection", "injection", "CWE-943", ["REST", "GraphQL", "document database"], ["web", "api", "database"], "Untrusted structured input changes a document-query operator, predicate or projection instead of remaining data.", "JSON body, query parameter or filter object", "NoSQL query, update or aggregation", ["Request object is passed directly to a query", "Operator keys are accepted from clients", "Type coercion changes predicate semantics"]),
    d("vuln.injection.ldap", "LDAP filter and distinguished-name injection", "injection", "CWE-90", ["LDAP", "SSO", "directory"], ["enterprise", "web", "api"], "Untrusted directory input changes an LDAP filter or distinguished name and alters identity or search semantics.", "username, group, filter or directory path", "LDAP search, bind or modify operation", ["Filter string is concatenated", "Escaping differs by filter/DN context", "Search result is treated as authorization"]),
    d("vuln.injection.xpath", "XPath injection", "injection", "CWE-643", ["XML", "SOAP", "policy"], ["web", "api", "enterprise"], "Untrusted data reaches an XPath expression and changes node selection or an authentication/policy decision.", "request, XML field or identity attribute", "XPath query or policy predicate", ["Expression is assembled by concatenation", "Boolean result drives login or access", "Namespace/context is caller-influenced"]),
    d("vuln.injection.header", "HTTP header injection and response splitting", "injection", "CWE-113", ["HTTP", "redirect", "proxy"], ["web", "api", "browser"], "Untrusted data reaches an HTTP header or response boundary without strict validation and changes downstream message interpretation.", "request value, filename or redirect target", "response header, cookie or proxy message", ["CR/LF is accepted after decoding", "Header value is copied from an exception or object field", "Multiple proxy layers normalize differently"]),
    d("vuln.injection.log", "Log injection and event-integrity failure", "injection", "CWE-117", ["logs", "audit", "observability"], ["web", "api", "cloud", "ci-cd"], "Untrusted content changes log structure, severity, correlation or audit interpretation because the logging boundary is not encoded or structured safely.", "request, username, filename or model output", "logger, audit sink or SIEM parser", ["Newline/control characters are logged raw", "User value becomes a field name or severity", "Audit events are mixed with free-form content"]),
    d("vuln.injection.csv", "CSV and spreadsheet formula injection", "injection", "CWE-1236", ["export", "report", "spreadsheet"], ["web", "api", "analytics"], "Untrusted cell content is exported in a form that a spreadsheet consumer interprets as a formula or external reference.", "user name, search term or database field", "CSV/XLSX export or downstream spreadsheet", ["Values beginning with formula markers are emitted unchanged", "Export context is not distinguished from display context", "Downloaded file is trusted by operators"]),
    d("vuln.injection.regex", "Regular-expression denial of service", "injection", "CWE-1333", ["validation", "search", "routing"], ["web", "api", "worker"], "An attacker-controlled pattern or input triggers disproportionate regular-expression work and consumes bounded service resources.", "regex pattern, search string or user-defined rule", "regex engine or repeated validation", ["Backtracking expression accepts untrusted input", "No match timeout or input bound", "Pattern compilation occurs per request"]),
    d("vuln.injection.xml-schema", "XML schema and entity processing ambiguity", "injection", "CWE-611", ["XML", "SOAP", "file import"], ["web", "api", "worker"], "XML parser configuration differs across paths, allowing external entities, expansive structures or schema assumptions to change the interpreted document.", "XML body, upload or provider response", "XML parser, resolver or schema validator", ["DTD/entity processing varies by library", "Validation occurs after parsing", "Resolver can reach network or local resources"]),
    d("vuln.browser.cors", "Overbroad CORS and credentialed cross-origin access", "browser-client", "CWE-942", ["browser", "REST", "GraphQL"], ["web", "api", "browser"], "A browser trust policy allows an attacker-controlled origin to read credentialed or sensitive responses.", "Origin header and credentialed browser request", "CORS response policy and browser-readable response", ["Origin reflected without exact allowlist", "Credentials enabled with broad origin", "Preflight and actual request policies differ"]),
    d("vuln.browser.clickjacking", "UI redress and framing policy failure", "browser-client", "CWE-1021", ["browser", "admin console", "payment"], ["web", "browser", "mobile-web"], "A sensitive page can be framed or visually overlaid so a user performs an action without seeing the intended interface.", "browser navigation and embedding context", "framed sensitive action or UI", ["Frame policy absent or inconsistent", "Sensitive action lacks re-authentication or origin signal", "Legacy and modern headers disagree"]),
    d("vuln.browser.postmessage", "Cross-window message origin and data validation failure", "browser-client", "CWE-940", ["browser", "iframe", "extension"], ["web", "browser", "mobile"], "A window or worker trusts cross-origin messages without validating sender origin, source window, schema and authorization context.", "postMessage event, iframe or extension message", "DOM action, token use or state mutation", ["Wildcard target origin", "event.data used without schema validation", "Source window is not bound to a session"]),
    d("vuln.browser.open-redirect", "Unvalidated redirect and navigation target", "browser-client", "CWE-601", ["HTTP", "login", "email"], ["web", "browser", "identity"], "A user-controlled destination changes navigation or authentication flow without a safe same-origin or allowlisted policy.", "return URL, link parameter or provider response", "Location header, browser navigation or OAuth redirect", ["Absolute URL accepted from query", "Scheme/host normalization is incomplete", "Redirect endpoint is reused for trust decisions"]),
    d("vuln.http.host-header", "Host header and forwarded-host trust confusion", "http-proxy-cache", "CWE-346", ["HTTP", "proxy", "link generation"], ["web", "api", "cloud"], "Application behaviour or generated security-sensitive URLs trusts an unvalidated host or forwarded-host value supplied across proxy boundaries.", "Host, forwarded host or proxy metadata", "absolute URL, password-reset link or routing decision", ["Proxy headers accepted from clients", "Canonical host is not enforced", "Tenant/domain selection uses request host"]),
    d("vuln.http.cache-authorization", "Shared-cache authorization and privacy confusion", "http-proxy-cache", "CWE-525", ["HTTP", "CDN", "API"], ["web", "api", "cdn"], "A shared cache stores or serves a response across principals because authorization state, tenant or privacy classification is missing from cache policy.", "authenticated request and cache metadata", "shared cache response", ["Private response uses public cache directive", "Authorization header is ignored in cache key", "Invalidation does not cover tenant or role changes"]),
    d("vuln.api.webhook-replay", "Webhook replay and duplicate side effects", "api-protocols", "CWE-294", ["webhook", "queue", "payment"], ["api", "integration", "workflow"], "A valid callback can be replayed or delivered out of order to repeat a side effect because freshness and idempotency are not enforced together.", "webhook body, event ID and timestamp", "payment, provisioning or state transition", ["Event ID is logged but not atomically claimed", "Timestamp is ignored", "Retry path bypasses signature or deduplication"]),
    d("vuln.api.content-type-confusion", "Content-type and parser confusion", "api-protocols", "CWE-436", ["REST", "upload", "proxy"], ["web", "api", "worker"], "Different components interpret the same bytes as different media types or structures, bypassing validation and security policy.", "request body, content-type and filename", "parser, validator or downstream service", ["Sniffing differs between proxy and application", "Validation uses one parser and execution another", "Multipart boundaries are handled inconsistently"]),
    d("vuln.api.inventory", "Incomplete API inventory and shadow endpoint exposure", "api-protocols", "CWE-200", ["REST", "GraphQL", "gRPC", "WebSocket"], ["api", "web", "mobile"], "Undocumented, deprecated or alternate API paths remain reachable without the same authentication, authorization, rate and logging controls as the supported surface.", "route, schema, version or protocol discovery", "shadow endpoint or deprecated handler", ["Inventory is derived only from gateway config", "Old version remains deployed", "Internal/admin path shares public routing"]),
    d("vuln.files.archive-bomb", "Archive expansion and decompression resource exhaustion", "files-paths-storage", "CWE-409", ["archive", "upload", "worker"], ["server", "worker", "cloud"], "A compressed or nested archive expands beyond bounded storage, CPU or file-count budgets during validation or extraction.", "uploaded archive or provider-supplied package", "decompressor, filesystem or media parser", ["Compression ratio is unbounded", "Nested archives are recursively extracted", "File count and total size are checked after expansion"]),
    d("vuln.files.symlink", "Symlink and mount escape during file processing", "files-paths-storage", "CWE-59", ["file", "archive", "worker"], ["server", "container", "desktop"], "A file-processing operation follows a symlink or mount that escapes the intended storage root or changes the security context after validation.", "filename, archive member or workspace path", "filesystem read/write or cleanup", ["Check is performed before symlink resolution", "Workspace is shared across jobs", "Archive extraction preserves links"]),
    d("vuln.files.temp-file", "Insecure temporary-file and workspace handling", "files-paths-storage", "CWE-377", ["upload", "export", "build"], ["server", "worker", "ci-cd"], "Temporary files or workspaces can be guessed, shared, retained or accessed by a different principal during a sensitive operation.", "temporary name, upload or job identifier", "temporary filesystem path or cleanup job", ["Predictable filename", "Shared directory permissions", "Cleanup occurs after a long delay or not at all"]),
    d("vuln.files.object-storage", "Object-storage public exposure and key-scope failure", "files-paths-storage", "CWE-732", ["S3", "blob storage", "CDN"], ["cloud", "storage", "api"], "Object storage policy, signed URL or key prefix grants broader read/write/list access than the intended tenant or operation.", "object key, bucket policy or signed URL", "object storage API or CDN", ["Public ACL or wildcard resource", "Key prefix is treated as authorization", "Signed URL permits unintended method or duration"]),
    d("vuln.files.include", "Local or remote file inclusion through dynamic path selection", "files-paths-storage", "CWE-98", ["template", "include", "plugin"], ["server", "web", "worker"], "A dynamic file or module selection reaches an include/loader boundary without a fixed allowlist and containment policy.", "template name, locale, plugin or path parameter", "include, module loader or interpreter", ["Path is assembled from request data", "Extension/normalization can be bypassed", "Loader has network or process-capable modules"]),
    d("vuln.business.replay", "Replay of security-sensitive business actions", "business-logic-state", "CWE-294", ["payment", "approval", "API", "mobile"], ["web", "api", "workflow"], "A previously valid request can be reused after its intended time, state or actor context because freshness, nonce or state binding is incomplete.", "request, signed action or queued event", "state transition or external side effect", ["Nonce is not consumed atomically", "Action is not bound to user/session/state", "Retry and manual replay are indistinguishable"]),
    d("vuln.business.idempotency", "Idempotency-key scope and atomicity failure", "business-logic-state", "CWE-841", ["payment", "provisioning", "API"], ["api", "workflow", "distributed"], "An idempotency mechanism does not uniquely and atomically bind a business action to its principal, request semantics and final result.", "idempotency key, request body and principal", "database write, payment or external call", ["Key is global or tenantless", "Request hash is not compared", "Record is created after side effect"]),
    d("vuln.business.price-tampering", "Client-controlled price, quantity or entitlement", "business-logic-state", "CWE-841", ["checkout", "billing", "API"], ["web", "api", "mobile"], "A client-controlled monetary or entitlement value reaches a business decision without recomputation from trusted product, tax, inventory or policy data.", "price, quantity, coupon or entitlement fields", "order, invoice, grant or refund", ["Server accepts client total", "Currency/rounding differs between services", "Discount constraints run only in the UI"]),
    d("vuln.business.approval-separation", "Missing maker-checker separation in approvals", "business-logic-state", "CWE-841", ["admin", "workflow", "finance"], ["enterprise", "web", "api"], "The same principal can initiate and approve a sensitive workflow or alter the approval evidence after the fact.", "approval request, role and workflow state", "release, payment, access grant or policy change", ["Initiator can self-approve", "Delegation erases original actor", "Approval is not bound to exact change digest"]),
    d("vuln.availability.rate-limit", "Rate-limit identity and quota bypass", "availability-resources", "CWE-770", ["API", "login", "search"], ["web", "api", "cloud"], "A resource limit is keyed to an unstable or attacker-controlled identity, or different paths apply inconsistent quotas that allow disproportionate work.", "request, identity, tenant or proxy metadata", "rate limiter, queue or downstream resource", ["Limit keyed only by IP or header", "Retry/async path is unmetered", "Expensive operation shares quota with cheap one"]),
    d("vuln.availability.queue-amplification", "Queue and retry amplification", "availability-resources", "CWE-400", ["queue", "webhook", "worker"], ["cloud", "api", "ci-cd"], "A single input or failure causes unbounded retries, fan-out or downstream work that exhausts queues, workers or provider quotas.", "message, failure or callback", "retry scheduler, queue or fan-out worker", ["Retries lack bounded backoff/dead letter", "One event creates unbounded children", "Failure classification retries permanent errors"]),
    d("vuln.secrets.info-disclosure", "Sensitive information exposure through responses or metadata", "information-secrets-privacy", "CWE-200", ["API", "error", "metadata", "export"], ["web", "api", "cloud"], "A response or metadata endpoint exposes data beyond the caller's need-to-know boundary through fields, identifiers, headers or provider details.", "request and internal object/error state", "HTTP response, metadata or export", ["Serializer returns internal fields", "Error path bypasses redaction", "Metadata endpoint shares cross-tenant state"]),
    d("vuln.secrets.error-disclosure", "Detailed error and stack-trace disclosure", "information-secrets-privacy", "CWE-209", ["API", "web", "worker"], ["web", "api", "cloud"], "Errors disclose stack frames, queries, tokens, file paths, provider responses or tenant information to an untrusted caller.", "exception, parse error or downstream failure", "HTTP error, log or monitoring event", ["Debug mode in deployment", "Exception serialized directly", "Correlation data includes secrets or full input"]),
    d("vuln.secrets.timing", "Observable timing side channel", "information-secrets-privacy", "CWE-208", ["login", "token", "lookup", "crypto"], ["web", "api", "identity"], "Timing or resource differences reveal secret validity, account state, authorization or data-dependent behaviour across a measurable boundary.", "candidate secret, identifier or query", "response timing or resource usage", ["Early-exit secret comparison", "Existing and missing records take different paths", "Cache/database behaviour reveals state"]),
    d("vuln.secrets.backup-exposure", "Backup, snapshot and export exposure", "information-secrets-privacy", "CWE-530", ["backup", "snapshot", "export"], ["cloud", "database", "storage"], "Backups or exports retain sensitive data with weaker access, retention, encryption or tenant isolation controls than the primary store.", "backup job, snapshot or export request", "archive, snapshot store or restore path", ["Backup bucket uses different policy", "Encryption key scope is broader", "Deletion policy excludes derived backups"]),
    d("vuln.crypto.key-rotation", "Key lifecycle and rotation failure", "crypto-transport", "CWE-324", ["encryption", "signing", "secrets"], ["cloud", "api", "mobile"], "Cryptographic keys remain active beyond their intended scope or cannot be rotated, revoked and re-encrypted without unsafe fallback.", "key identifier, secret reference or encrypted record", "decrypt/sign/verify operation", ["No key version in ciphertext", "Old keys remain accepted indefinitely", "Rotation falls back to hardcoded material"]),
    d("vuln.crypto.certificate-validation", "Certificate and peer-identity validation bypass", "crypto-transport", "CWE-295", ["TLS", "mTLS", "mobile", "database"], ["web", "api", "mobile", "iot"], "A client encrypts a connection but does not authenticate the intended peer because certificate, hostname, chain or pinning validation is disabled or inconsistent.", "provider URL and certificate chain", "TLS/mTLS client connection", ["Verification callback always succeeds", "Hostname is disabled", "Different client paths use different trust stores"]),
    d("vuln.configuration.insecure-default", "Insecure default configuration", "configuration-deployment", "CWE-1188", ["deployment", "auth", "storage"], ["cloud", "container", "web"], "A system starts with a security-sensitive default such as public access, debug mode, broad permissions or weak credentials when explicit configuration is absent.", "missing configuration or deployment value", "startup policy, listener or access decision", ["Default allow/public/guest branch", "Environment variable missing silently", "Sample config copied to production"]),
    d("vuln.configuration.debug", "Debug and diagnostic mode exposed in deployment", "configuration-deployment", "CWE-489", ["web", "API", "admin"], ["web", "cloud", "container"], "Diagnostic features expose source, state, interactive controls or verbose data outside a controlled development boundary.", "deployment flag, debug route or error state", "diagnostic endpoint, console or response", ["Debug enabled by default", "Non-production check trusts hostname", "Admin console is reachable from public route"]),
    d("vuln.supply.artifact-integrity", "Unsigned or weakly bound build artifact", "supply-chain-cicd", "CWE-494", ["release", "container", "package"], ["ci-cd", "cloud", "registry"], "A release artifact is consumed without verifying authenticity, provenance and binding to the reviewed source revision and build context.", "artifact, digest, manifest or release metadata", "deployment, package registry or updater", ["Mutable tag used as identity", "Signature does not cover digest/metadata", "Artifact can be replaced between stages"]),
    d("vuln.supply.workflow-injection", "Untrusted CI metadata reaches privileged workflow code", "supply-chain-cicd", "CWE-829", ["CI", "SCM", "release"], ["ci-cd", "repository", "cloud"], "Pull-request data, branch names, issue text or repository content is interpolated into a privileged CI command or action.", "commit metadata, PR title, branch or changed file", "runner command, action input or deployment", ["Expression is placed in shell context", "Untrusted event gets write tokens", "Workflow checks out attacker-controlled code before trust split"]),
    d("vuln.supply.container-image", "Untrusted container image and mutable tag resolution", "supply-chain-cicd", "CWE-494", ["Docker", "Kubernetes", "CI"], ["container", "kubernetes", "cloud"], "A workload runs an image whose provenance, digest, signature or build inputs are not verified against the intended release.", "image reference, registry response or build context", "container runtime or cluster admission", ["latest/mutable tag in deployment", "Registry trust is implicit", "Image scan is disconnected from deployed digest"]),
    d("vuln.supply.iac-drift", "Infrastructure-as-code drift and unmanaged privilege", "supply-chain-cicd", "CWE-1269", ["Terraform", "Kubernetes", "cloud"], ["cloud", "ci-cd", "infrastructure"], "Runtime security state diverges from reviewed infrastructure code, leaving unmanaged public access, identity or network privilege.", "manual change, generated plan or provider state", "cloud resource, IAM policy or network boundary", ["Drift is not detected", "Plan review omits provider defaults", "Emergency change bypasses policy checks"]),
    d("vuln.cloud.serverless-iam", "Serverless function privilege and event-source confusion", "cloud-containers-infra", "CWE-732", ["serverless", "event", "API"], ["cloud", "lambda", "functions"], "A serverless function receives broad identity, event data or network access beyond the operation and tenant scope it serves.", "event payload, trigger metadata or function role", "cloud API, storage or downstream event", ["One role shared by unrelated functions", "Event source is trusted without signature/context", "Function can access all tenant data"]),
    d("vuln.cloud.k8s-service-account", "Kubernetes service-account and workload identity overreach", "cloud-containers-infra", "CWE-269", ["Kubernetes", "pod", "cluster API"], ["kubernetes", "cloud", "container"], "A workload receives a service account or cloud identity with broader cluster, namespace or provider permissions than its task requires.", "pod spec, service account token or workload identity binding", "Kubernetes/cloud control-plane API", ["Default service account mounted", "Wildcard verbs/resources", "Namespace identity mapped to broad cloud role"]),
    d("vuln.cloud.metadata-boundary", "Cloud metadata and instance-identity boundary failure", "cloud-containers-infra", "CWE-918", ["cloud", "HTTP", "container"], ["cloud", "server", "container"], "A workload or user-controlled request can reach cloud metadata or instance-identity endpoints and turn the response into usable authority.", "URL, redirect or proxy request", "metadata endpoint or credential service", ["Metadata endpoint reachable from untrusted worker", "Hop-limit/network policy absent", "Returned role credentials are not isolated"]),
    d("vuln.ai.indirect-prompt-injection", "Indirect prompt injection through retrieved or external content", "ai-llm-rag-agents", "CWE-20", ["RAG", "browser", "tool", "agent"], ["ai", "rag", "agent"], "Untrusted retrieved content, web page, email or tool result changes model behaviour because data is merged into instructions without provenance and policy separation.", "retrieved document, web content or tool result", "model context, decision or tool call", ["Retrieved text is marked as instruction", "Source trust is not preserved", "Model output can invoke capabilities without confirmation"] , "P0", ["LLM01:2025", "ASI01"]),
    d("vuln.ai.tool-authorization", "AI tool authorization and capability-scope failure", "ai-llm-rag-agents", "CWE-862", ["agent", "tool", "MCP", "function call"], ["ai", "agent", "mcp"], "An AI agent can invoke a tool or MCP capability without an authorization decision bound to the user, tenant, destination, arguments and side effects.", "model output, tool name and arguments", "tool/MCP server, cloud API or state-changing function", ["Tool registry is global", "Arguments are trusted from model output", "Approval checks name but not scope or destination"], "P0", ["ASI02", "ASI03"]),
    d("vuln.ai.memory-poisoning", "Agent memory and context poisoning", "ai-llm-rag-agents", "CWE-1321", ["memory", "RAG", "agent"], ["ai", "rag", "agent"], "Untrusted content is persisted as memory, preference or policy and later treated as trusted context across users, tenants or tasks.", "conversation, document or tool result", "memory store, retrieval context or agent policy", ["Writes lack provenance and owner", "Memory is retrieved across tenant boundary", "User content can alter system policy"], "P0", ["ASI06"]),
    d("vuln.ai.rag-source-trust", "RAG provenance and source-trust confusion", "ai-llm-rag-agents", "CWE-829", ["RAG", "vector database", "search"], ["ai", "rag", "multi-tenant"], "Retrieved content is used for a security-sensitive decision without preserving source, tenant, freshness, authorization and trust level.", "document, embedding result or search filter", "retrieval context, answer or action", ["Vector metadata omits tenant/policy", "Top-k result outranks system policy", "Deleted or revoked source remains retrievable"], "P0", ["LLM08:2025", "ASI06"]),
    d("vuln.ai.tool-output", "Untrusted tool output treated as authority", "ai-llm-rag-agents", "CWE-20", ["agent", "tool", "MCP"], ["ai", "agent", "mcp"], "Tool results are parsed or presented to the model without schema, provenance and policy checks, so data can become an instruction or capability grant.", "tool result, API response or error", "model context, next tool call or state mutation", ["Raw tool output is concatenated into prompt", "Tool result can select another tool", "No output size/type/tenant validation"], "P0", ["ASI02", "ASI05"]),
    d("vuln.ai.agent-identity", "Agent identity and user-delegation confusion", "ai-llm-rag-agents", "CWE-441", ["agent", "workflow", "tool"], ["ai", "agent", "enterprise"], "A downstream service cannot distinguish the end user, agent policy and service identity, allowing an autonomous step to exceed delegated authority.", "user request, agent session or service token", "downstream API or workflow action", ["Agent uses broad service token", "User approval is not cryptographically bound", "Delegation survives session or tenant change"], "P0", ["ASI03", "ASI09"]),
    d("vuln.ai.agent-loop", "Unbounded agent loop and tool-call consumption", "ai-llm-rag-agents", "CWE-400", ["agent", "tool", "workflow"], ["ai", "agent", "cloud"], "An agent can repeat reasoning, retrieval or tool calls without bounded steps, time, tokens, fan-out and cost controls.", "model output, tool failure or retry state", "agent loop, queue, provider or external API", ["No maximum turns or wall-clock budget", "Failure retries indefinitely", "One task can fan out across tools/tenants"], "P0", ["LLM10:2025", "ASI08"]),
    d("vuln.ai.model-supply-chain", "Model, adapter and prompt supply-chain trust failure", "ai-llm-rag-agents", "CWE-829", ["model", "adapter", "prompt", "registry"], ["ai", "ml", "ci-cd"], "A model, adapter, prompt template or evaluation asset is loaded without provenance, integrity, license and compatibility verification.", "model URI, artifact, plugin or prompt package", "model loader, inference runtime or deployment", ["Mutable model reference", "Unverified serialized weights", "Prompt/adapter changes are not reviewed or hashed"], "P0", ["LLM03:2025", "ASI04"]),
    d("vuln.ai.context-leakage", "Sensitive context and cross-tenant prompt disclosure", "ai-llm-rag-agents", "CWE-200", ["LLM", "RAG", "logs", "tool"], ["ai", "rag", "multi-tenant"], "Sensitive instructions, retrieved documents, credentials or another tenant's context becomes visible in model output, logs or tool arguments.", "prompt, retrieval result, memory or tool response", "model output, trace, provider or tool", ["Context includes data without field-level policy", "Output is returned without redaction", "Telemetry stores full prompt and tool payload"] , "P0", ["LLM02:2025", "ASI06"]),
    d("vuln.ai.inter-agent-trust", "Inter-agent message authenticity and scope failure", "ai-llm-rag-agents", "CWE-345", ["agent", "queue", "workflow"], ["ai", "agent", "distributed"], "An agent accepts another agent's message, task or result without authenticating origin, binding it to a workflow and limiting its requested capabilities.", "agent message, task envelope or queue event", "next agent, tool call or workflow transition", ["Messages lack sender/audience/signature", "Task identity is mutable", "Agent result is trusted without independent validation"], "P1", ["ASI07", "ASI03"]),
    d("vuln.ai.evaluation-leakage", "Evaluation and feedback data leakage", "ai-llm-rag-agents", "CWE-200", ["evaluation", "feedback", "training"], ["ai", "ml", "ci-cd"], "Evaluation prompts, hidden tests, user feedback or sensitive labels cross into model, logging or training paths where they can be disclosed or overfit.", "evaluation case, user feedback or grader output", "model provider, artifact, log or training dataset", ["Hidden test data is in prompts/logs", "Feedback is reused without consent or isolation", "Evaluation fixture contains real data"] , "P1", ["LLM02:2025", "ASI09"]),
]


def slug(identifier: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", identifier.split(".")[-1]).strip("-")


def frontmatter(record: dict) -> str:
    values = {
        "id": record["id"],
        "title": record["title"],
        "aliases": [],
        "summary": record["summary"],
        "family": record["family"],
        "canonical_cwe": record["cwe"],
        "related_cwe": [],
        "capec": [],
        "owasp_mappings": ["A05:2025"] if record["family"] == "injection" else [],
        "asvs_mappings": [],
        "wstg_mappings": [],
        "masvs_mappings": [],
        "api_security_mappings": [],
        "genai_mappings": record["genai"],
        "applies_to": ["source code", "configuration", "architecture"],
        "surfaces": record["surfaces"],
        "languages": ["any"],
        "frameworks": ["framework-agnostic"],
        "platforms": record["platforms"],
        "preconditions": ["An untrusted or lower-trust input reaches the described boundary.", "The intended validation, authorization, isolation or resource control is absent, incomplete or applied on only one path."],
        "trust_boundaries": ["untrusted input to application", "application to privileged/resource sink"],
        "data_flow": {"sources": [record["source"]], "transformations": ["decode, normalize or parse input", "application-specific routing or policy translation"], "controls": ["validation, authorization, provenance or budget control if present"], "sinks": [record["sink"]], "authorization_points": ["the decision point immediately before the sink"]},
        "code_signals": record["signals"],
        "configuration_signals": [f"Configuration, default or error paths can bypass {record['title'].lower()}.", "Review identity, boundary, limit and failure settings for every alternate path."],
        "architecture_signals": [f"Trace {record['source']} to {record['sink']} across synchronous, asynchronous and provider boundaries.", "Check whether a gateway-only control is assumed to protect internal or worker paths."],
        "audit_questions": [f"What exact source and sink are reachable for {record['title']}?", "Which control must run before the sink and where is its decision evidence?", "Do retries, alternate protocols, error paths and tenant changes preserve the same control?"],
        "safe_verification": ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.", "Assert the expected denial, isolation, limit or safe encoding and inspect only test output; never use real credentials, public targets or destructive state."],
        "false_positives": ["A library, route or configuration name is only a signal; confirm reachability and the exact security-sensitive sink.", "A compensating control may be implemented at a different layer; record its evidence before reporting a finding."],
        "impact": ["confidentiality, integrity or availability boundary failure", "impact depends on asset, principal, tenant and blast radius"],
        "severity_factors": ["Severity increases with privilege, sensitivity, tenant count, persistence and external reachability."],
        "exploitability_factors": ["Reachability, input control and missing control evidence are required; use synthetic fixtures only."],
        "remediation": ["Enforce the control at the sink-facing service boundary and make the policy explicit.", "Use least privilege, typed inputs, provenance and bounded resources across alternate and asynchronous paths.", "Add telemetry that records the decision without storing secrets or sensitive content."],
        "secure_patterns": ["Deny by default with a typed, testable policy decision.", "Isolate capabilities, bound time/size/fan-out and bind identity, tenant, destination and action."],
        "regression_tests": [f"Create a local or staging synthetic fixture for {record['title']}; assert the control blocks or safely contains the unsafe path and records a redacted decision."],
        "related_vulnerabilities": [],
        "references": [f"https://cwe.mitre.org/data/definitions/{record['cwe'].split('-')[1]}.html"],
        "source_provenance": ["sources/research-notes.md:normalized defensive topic", "sources/manifest.yaml:mitre-cwe"],
        "last_reviewed": REVIEW_DATE,
        "maturity": "curated",
        "priority": record["priority"],
        "review_status": "reviewed",
        "fixture_ids": [f"eval.{slug(record['id'])}.positive", f"eval.{slug(record['id'])}.negative"],
        "detector_refs": [],
    }
    lines = ["---"]
    for key, value in values.items():
        lines.append(f"{key}: {json.dumps(value, ensure_ascii=False, separators=(',', ':'))}")
    lines.append("---")
    lines.append("")
    lines.append(f"# {record['title']}")
    lines.append("")
    lines.append(record["summary"])
    lines.append("")
    lines.append("## Defensive audit note")
    lines.append("")
    lines.append("Treat the named signal as a hypothesis. Confirm the reachable source, transformations, missing control and sink with code/configuration evidence before reporting a finding.")
    lines.append("")
    lines.append("## Safe boundary")
    lines.append("")
    lines.append("Verification belongs in a local or staging harness with synthetic data, canaries, mocks, bounded timeouts and no external side effects.")
    lines.append("")
    lines.append(f"Canonical ID: `{record['id']}`; canonical ontology: `{record['cwe']}`.")
    return "\n".join(lines) + "\n"


def make_fixture(record: dict, polarity: str) -> dict:
    positive = polarity == "positive"
    return {
        "id": f"eval.{slug(record['id'])}.{polarity}",
        "vulnerability_id": record["id"],
        "polarity": polarity,
        "expected_status": "candidate" if positive else "not-applicable",
        "expected_cwe": record["cwe"],
        "query": f"{record['title']} {record['source']} {record['sink']}",
        "snippet": (
            f"synthetic canary from {record['source']} reaches {record['sink']} without the documented control"
            if positive else
            f"synthetic canary from {record['source']} is validated, scoped and denied before {record['sink']}"
        ),
        "evidence_required": ["source", "sink", "control"],
        "safe_boundary": "local synthetic fixture; no network and no real credentials",
    }


def main() -> int:
    generated = 0
    fixtures: list[dict] = []
    fixture_dir = ROOT / "evals" / "fixtures"
    for record in CARDS:
        target = ROOT / "vulnerabilities" / DIRECTORIES[record["family"]] / f"{slug(record['id'])}.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(frontmatter(record), encoding="utf-8")
        generated += 1
        for polarity in ("positive", "negative"):
            fixture = make_fixture(record, polarity)
            path = fixture_dir / f"{slug(record['id'])}-{polarity}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(fixture, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            fixtures.append({"id": fixture["id"], "path": str(path.relative_to(ROOT)), "vulnerability_id": record["id"], "polarity": polarity})
    manifest = {"schema_version": "1.0", "suite": "secure-context-atlas-deterministic-v1", "description": "Synthetic retrieval and evidence-contract fixtures for high-priority vulnerability cards.", "min_retrieval_recall_at_5": 0.9, "max_forbidden_fixture_count": 0, "fixtures": fixtures}
    (ROOT / "evals" / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"generated {generated} cards and {len(fixtures)} evaluation fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# Security Policy

The security of Sentz is fundamental to our mission. We greatly appreciate the efforts of security researchers, auditors, and members of the security community who help identify vulnerabilities and responsibly disclose them.

This document describes how to report security vulnerabilities, the information we need to investigate a report, and the expectations we have for responsible security research.

If you believe you have discovered a security vulnerability, please report it to:

**[security@sentz.com](mailto:security@sentz.com)**

Please do not publicly disclose a vulnerability until we have had a reasonable opportunity to investigate and remediate the issue.

# Security Bounty Program

Sentz operates a security bounty program and may provide rewards for eligible vulnerability reports.

Eligibility, scope, severity, and reward determinations are made at Sentz's sole discretion and may vary based on factors including:

* Security impact
* Exploitability
* Affected users or systems
* Report quality
* Originality of the finding
* Existing mitigations

Not all reports will qualify for bounty consideration.

---

# Scope

Unless otherwise specified, we welcome reports relating to security vulnerabilities affecting Sentz-controlled products, services, infrastructure, and codebases.

Examples may include:

* Sentz mobile applications
* Sentz wallet infrastructure
* Sentz blockchain network and protocol implementations
* Consensus and transaction validation logic
* Cryptographic systems and key management
* Public APIs and backend services
* Web applications and web properties
* Developer SDKs and client libraries
* Payment and transaction infrastructure
* Privacy-preserving systems and protocols

---

# Privacy Vulnerabilities

Privacy is a core security property of the Sentz ecosystem.

We encourage reports involving:

* Metadata leakage
* User deanonymization
* Transaction graph analysis weaknesses
* Privacy bypasses
* Correlation attacks
* Information disclosure through protocol behavior
* Side-channel attacks
* Cryptographic privacy failures

A vulnerability does not need to directly expose funds to qualify as a significant security issue.

Reports demonstrating degradation of privacy guarantees are treated as security vulnerabilities even when no direct financial impact exists.

---

# Responsible Disclosure Guidelines

We ask researchers to:

* Act in good faith.
* Respect user privacy.
* Avoid accessing, modifying, or destroying user data.
* Avoid actions that could degrade service availability.
* Limit testing to the minimum necessary to demonstrate the issue.
* Avoid disrupting production systems.
* Avoid conducting attacks against third-party infrastructure.
* Provide sufficient information for us to reproduce and validate findings.

Activities that create risk for users, compromise privacy, or impact system availability may be considered ineligible for bounty consideration.

---

# How to Submit a Vulnerability Report

Please submit reports to:

**[security@sentz.com](mailto:security@sentz.com)**

To facilitate efficient review, reports should include the information described below.

---

# Vulnerability Report Format

## 1. Vulnerability Summary

Provide a concise description of the alleged vulnerability.

Include:

* Affected product, application, service, endpoint, protocol component, SDK, or infrastructure component.
* The security weakness being reported.
* The conditions under which the issue occurs.

---

## 2. Security Impact

Clearly explain the security property that is violated.

Examples include:

* Authentication bypass
* Authorization bypass
* Privilege escalation
* Unauthorized access to data
* Remote code execution
* Consensus manipulation
* Transaction forgery
* Double-spend conditions
* Key compromise
* Denial of service
* Privacy violations
* Cryptographic weaknesses
* Economic or protocol attacks

Please describe:

* Realistic attacker capabilities.
* Impact on users, systems, funds, privacy, or network operations.
* The expected severity of the issue.

---

## 3. Reproduction Steps

Provide exact instructions required to reproduce the issue.

Include:

* Step-by-step instructions.
* Environmental requirements.
* Required permissions.
* Configuration assumptions.
* Software versions.
* Commit hashes when applicable.
* Test environment information.

Reports that cannot be reproduced may be difficult to assess.

---

## 4. Proof of Exploitability

Provide evidence demonstrating that the vulnerability can be exercised in practice.

Examples include:

* Screenshots
* Logs
* Network traces
* Requests and responses
* Proof-of-concept code
* Test transactions
* Smart contract interactions
* Demonstration videos

Whenever possible, demonstrate actual impact rather than theoretical possibility.

---

## 5. Mitigation Analysis

Please identify:

* Existing controls
* Security boundaries
* Architectural assumptions
* Environmental dependencies
* Conditions necessary for successful exploitation

Explain why existing mitigations do not prevent exploitation.

Understanding how a reported issue interacts with existing security controls significantly improves our ability to assess risk.

---

## 6. Additional Requirements for Blockchain and Cryptographic Findings

For reports involving:

* Consensus mechanisms
* Cryptographic protocols
* Key management
* Wallet security
* Smart contracts
* Cross-chain bridges
* Token accounting
* Economic incentives
* Network-level attacks
* Privacy-preserving protocols

please provide:

* The affected trust assumptions.
* The attacker model.
* Required prerequisites.
* Whether the attack has been demonstrated or remains theoretical.
* Evidence supporting claimed impact.
* Economic analysis where relevant.

Where practical, include a proof-of-concept demonstrating exploitation.

---

## AI-Assisted Security Research

As AI-assisted security research becomes increasingly common, we welcome submissions that leverage AI tools.

However, to enable efficient review and accurate assessment, we request that AI-assisted submissions follow the format above, and also include an AI Assistance Disclosure.

## 7. AI Assistance Disclosure

Identify any AI systems used during the research process.

Please distinguish between:

### Findings directly observed and validated by the researcher

and

### Hypotheses, attack paths, or analyses suggested by AI systems

## 8. Researcher's Validation

Provide a statement confirming that you personally reproduced and validated the reported behavior.

Include:

* The observed outcome.
* The resulting impact.
* The evidence supporting your conclusion.

Reports consisting solely of AI-generated prompts, speculative attack chains, model-generated analyses, or hypothetical attack paths without independent validation are generally insufficient for vulnerability assessment and may not qualify for bounty consideration.

---

# Severity Assessment

Sentz evaluates vulnerability reports using a risk-based approach.

Factors considered may include:

* Exploitability
* Security impact
* Affected assets
* Affected users
* Existing mitigations
* Required attacker capabilities
* Reliability of exploitation
* Privacy implications
* Potential financial impact
* Potential ecosystem impact

Severity determinations are made at Sentz's discretion.

---

# What Generally Does Not Qualify

The following generally do not qualify as security vulnerabilities by themselves:

* Missing security headers without demonstrable impact.
* Version disclosure.
* Best-practice recommendations without an associated exploit path.
* Self-XSS requiring only the reporting user's actions.
* Vulnerabilities affecting unsupported software versions.
* Reports based solely on automated scanner output.
* Reports based solely on AI-generated analysis.
* Theoretical attacks without evidence of exploitability.
* Social engineering attacks against Sentz personnel.
* Physical attacks requiring device possession unless physical access is part of the threat model being evaluated.
* Issues that require unrealistic assumptions or attacker capabilities.

---

# Safe Harbor

Sentz supports responsible security research conducted in good faith.

We will not pursue legal action against researchers who:

* Follow this policy.
* Act in good faith.
* Avoid causing harm to users.
* Avoid violating privacy.
* Avoid service disruption.
* Promptly report discovered vulnerabilities.
* Provide us a reasonable opportunity to investigate and remediate findings before public disclosure.

This safe harbor applies only to activities conducted for the purpose of good-faith security research and in accordance with this policy.

---

# Communication and Disclosure

Please submit all security reports to:

**[security@sentz.com](mailto:security@sentz.com)**

When possible, include:

* Your preferred contact information.
* A preferred communication channel.
* Public key information if encrypted communication is desired.

We may request additional information during investigation and validation.

We appreciate the work of security researchers and the broader security community in helping protect the Sentz ecosystem, its users, and its infrastructure.

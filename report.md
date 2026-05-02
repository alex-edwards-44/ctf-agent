# Vulnerability Triage Report

**Generated**: 2026-05-01 19:44:39  
**Target**: `https://github.com/gunnarrl/grading-council`  
**Total cost**: $1.97

## Summary

| Category | Count |
|----------|-------|
| 🔴 Confirmed | 2 |
| 🟡 Likely | 0 |
| ❓ Uncertain | 1 |
| ✅ False Positive | 1 |
| ⏭ Not triaged | 0 |
| **Total** | **4** |

## Confirmed Vulnerabilities (2)

### 🔴 `generate_exam_links.py:41` · CWE-345: Insufficient Verification of Data Authenticity

**Rule**: `tmp.unsigned-base64-pii-in-url`  
**Severity**: ERROR  
**Exploitability**: 🔥 trivial  
**Confidence**: 95%


**Semgrep message**: Student PII (student_id, student_name, project_details) is base64-encoded and appended to a URL as a plain query parameter with no HMAC or signature. Any recipient of the URL can decode `vars` to read the full project_details blob. More critically, an attacker can forge a new base64 payload with a different student_id and hand that URL to the agent, causing the AI grader to grade them as a different student.


**Flagged code**:
```
requires login
```

**Verdict**: Student PII is base64-encoded without HMAC/signature and placed in URL query parameters, enabling trivial data exposure and identity forgery. Production code at line 41 of generate_exam_links.py.

**Proof of concept**:
```
python3 -c "import base64,json;print(base64.b64encode(json.dumps({\"student_id\":\"FORGED_ID\",\"student_name\":\"Attacker\"}).encode()).decode())"
```

**Remediation**: Sign the vars payload with HMAC and verify signature before trusting.

---

### 🟡 `grading_script.py:42` · CWE-798: Use of Hard-coded Credentials

**Rule**: `tmp.api-key-placeholder-check-incomplete`  
**Severity**: WARNING  
**Exploitability**: — n/a  
**Confidence**: 95%


**Semgrep message**: The API key validation only rejects keys that start with "your_", but the .env.example file uses the key name itself as the placeholder value (e.g. ANTHROPIC_API_KEY=ANTHROPIC_API_KEY). These placeholder values would pass this check and cause runtime errors when calls are made with invalid keys.


**Flagged code**:
```
requires login
```

**Verdict**: The load_keys() function at line 42 validates API keys by checking if they start with "your_". However, the .env.example file uses the key name itself as the placeholder value (e.g., ANTHROPIC_API_KEY=ANTHROPIC_API_KEY). If a user copies .env.example to .env without editing it, these placeholder values pass the validation check and the script proceeds to make API calls with invalid keys, resulting in runtime errors. This is a real logic bug in the input validation.

**Proof of concept**:
```
The .env.example contains ANTHROPIC_API_KEY=ANTHROPIC_API_KEY. Copying it as-is to .env and running the script: the check os.getenv(key).startswith("your_") returns False for "ANTHROPIC_API_KEY", so validation passes and the script attempts API calls with an invalid key.
```

**Remediation**: Update the validation in load_keys() to also reject keys that equal the key name itself, or use a more robust check like verifying key format/length. For example: if not os.getenv(key) or os.getenv(key).startswith("your_") or os.getenv(key) == key:

---

## Uncertain (1)

### 🔴 `fetch_transcripts.py:51` · CWE-287: Improper Authentication

**Rule**: `tmp.self-reported-student-identity`  
**Severity**: ERROR  
**Exploitability**: — n/a  
**Confidence**: 50%


**Semgrep message**: Student identity is determined by searching the student's own spoken words for a matching student_id string. A student can simply say another student's ID at the start of the conversation to have their transcript attributed to that peer, causing grade fraud.


**Flagged code**:
```
requires login
```

**Verdict**: Solver did not return a verdict.

---

## False Positives (1)

### 🟡 `generate_exam_links.py:33` · CWE-20: Improper Input Validation

**Rule**: `tmp.token-extracted-by-string-split`  
**Severity**: WARNING  
**Exploitability**: — n/a  
**Confidence**: 90%


**Semgrep message**: The conversation signature token is extracted from the ElevenLabs signed URL by string splitting on "conversation_signature=". If the URL format ever changes or contains multiple occurrences of that string, this silently produces a malformed token that appears valid but causes authentication failures. Use urlparse/urlencode instead.


**Flagged code**:
```
requires login
```

**Verdict**: The string-split extraction on line 33 operates on ws_url, which is obtained from the ElevenLabs API response (resp.json()["signed_url"]), a trusted first-party API source. No attacker-controlled input flows into this parsing logic. The CWE-20 (Improper Input Validation) classification is incorrect because there is no untrusted input to validate. While using urllib.parse would be more robust against API format changes, the current code poses no security risk — at worst it causes a functional failure, not a security breach.

**Remediation**: For robustness (not security), replace the string split with: from urllib.parse import urlparse, parse_qs; token = parse_qs(urlparse(ws_url).query)["conversation_signature"][0]

---

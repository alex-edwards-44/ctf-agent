# Vulnerability Triage Report

**Generated**: 2026-05-05 15:22:23  
**Target**: `https://github.com/gunnarrl/grading-council`  
**Total cost**: $0.14

## Summary

| Category | Count |
|----------|-------|
| 🔴 Confirmed | 1 |
| 🟡 Likely | 1 |
| ❓ Uncertain | 0 |
| ✅ False Positive | 2 |
| ⏭ Not triaged | 0 |
| **Total** | **4** |

## Confirmed Vulnerabilities (1)

### 🔴 `fetch_transcripts.py:51` · CWE-287: Improper Authentication

**Rule**: `tmp.self-reported-student-identity`  
**Severity**: ERROR  
**Exploitability**: 🔥 trivial  
**Confidence**: 96%


**Semgrep message**: Student identity is determined by searching the student's own spoken words for a matching student_id string. A student can simply say another student's ID at the start of the conversation to have their transcript attributed to that peer, causing grade fraud.


**Flagged code**:
```
requires login
```

**Verdict**: The finding is real: fetch_transcripts.py identifies the student solely by scanning the first few user transcript messages for any known student_id, then saves the entire conversation as that student''s transcript. There is no binding between the conversation and the signed exam link variables generated in generate_exam_links.py, and the README shows this script is part of the normal grading workflow. Because grading_script.py later grades transcripts by filename/student_id, a student who speaks another student''s ID can cause the transcript to be attributed and graded under that peer''s identity.

**Proof of concept**:
```
1. Student A opens their oral exam conversation and says early in the conversation: My student ID is 123456789 where 123456789 belongs to Student B. 2. fetch_transcripts.py runs extract_student_id(turns, known_ids), finds 123456789 in the first five user messages, and writes transcripts/123456789_transcript.txt. 3. The operator can then run: python grading_script.py transcripts/123456789_transcript.txt 123456789 which grades Student A''s answers as if they belonged to Student B.
```

**Remediation**: Do not infer identity from free-form spoken content. Instead, bind each conversation to a trusted identifier from the signed exam link or provider metadata, and verify that identifier when fetching transcripts before naming or grading files.

---

## Likely Vulnerabilities (1)

### 🔴 `generate_exam_links.py:41` · CWE-345: Insufficient Verification of Data Authenticity

**Rule**: `tmp.unsigned-base64-pii-in-url`  
**Severity**: ERROR  
**Exploitability**: 🔥 trivial  
**Confidence**: 84%


**Semgrep message**: Student PII (student_id, student_name, project_details) is base64-encoded and appended to a URL as a plain query parameter with no HMAC or signature. Any recipient of the URL can decode `vars` to read the full project_details blob. More critically, an attacker can forge a new base64 payload with a different student_id and hand that URL to the agent, causing the AI grader to grade them as a different student.


**Flagged code**:
```
requires login
```

**Verdict**: The flagged code is in a production workflow documented in README step 5 and generates real exam URLs by embedding student_id, student_name, and project_details into a plain base64 query parameter. Base64 provides no confidentiality or integrity, so any recipient of the link can trivially decode the full project summary. I could not verify from this repository alone how ElevenLabs consumes the vars parameter, so the full impersonation/grade-misattribution impact is not provable here, but the lack of authenticity protection on identity-bearing exam state makes the finding at least likely.

**Proof of concept**:
```
python3 - <<'PY'
import base64, json
vars_b64 = "eyJzdHVkZW50X2lkIjogIjEyMzQ1Njc4OSIsICJzdHVkZW50X25hbWUiOiAiQWxpY2UiLCAicHJvamVjdF9kZXRhaWxzIjogIlNlbnNpdGl2ZSBwcm9qZWN0IGJsb2IifQ=="
print(base64.b64decode(vars_b64).decode())
forged = {"student_id":"987654321","student_name":"Bob","project_details":"Sensitive project blob"}
print(base64.b64encode(json.dumps(forged).encode()).decode())
PY
# The first output reveals the embedded PII/project blob; the second shows how a forged payload can be created with a different student_id.
```

**Remediation**: Do not place raw student metadata in client-controlled query parameters. Store per-student context server-side and issue opaque one-time tokens, or at minimum sign and timestamp the payload with an HMAC and verify it before using any embedded identity/context.

---

## False Positives (2)

### 🟡 `generate_exam_links.py:33` · CWE-20: Improper Input Validation

**Rule**: `tmp.token-extracted-by-string-split`  
**Severity**: WARNING  
**Exploitability**: — n/a  
**Confidence**: 88%


**Semgrep message**: The conversation signature token is extracted from the ElevenLabs signed URL by string splitting on "conversation_signature=". If the URL format ever changes or contains multiple occurrences of that string, this silently produces a malformed token that appears valid but causes authentication failures. Use urlparse/urlencode instead.


**Flagged code**:
```
requires login
```

**Verdict**: The flagged code is in a standalone administrative script that calls ElevenLabs' API and then embeds the returned token into generated exam links; no attacker-controlled input reaches the split operation. The only plausible failure mode is brittleness if ElevenLabs changes the signed_url format, which would cause malformed links or auth failures, but that is a reliability/compatibility bug rather than a security vulnerability under CWE-20 in this codebase.

**Proof of concept**:
```
A returned signed URL like wss://x?foo=1&conversation_signature=abc&bar=2 makes the current code produce token=abc&bar=2 instead of abc, demonstrating a parsing bug but not an exploitable security issue.
```

**Remediation**: Use urllib.parse to extract the conversation_signature query parameter robustly, e.g. parse_qs(urlparse(ws_url).query).get("conversation_signature", [None])[0].

---

### 🟡 `grading_script.py:42` · CWE-798: Use of Hard-coded Credentials

**Rule**: `tmp.api-key-placeholder-check-incomplete`  
**Severity**: WARNING  
**Exploitability**: — n/a  
**Confidence**: 91%


**Semgrep message**: The API key validation only rejects keys that start with "your_", but the .env.example file uses the key name itself as the placeholder value (e.g. ANTHROPIC_API_KEY=ANTHROPIC_API_KEY). These placeholder values would pass this check and cause runtime errors when calls are made with invalid keys.


**Flagged code**:
```
requires login
```

**Verdict**: The flagged code is reachable in normal use, and the placeholder check is indeed incomplete because .env.example uses values like ANTHROPIC_API_KEY that do not start with "your_". However, this is not a CWE-798 hard-coded-credentials vulnerability or a security issue; it is a configuration/usability bug that causes the script to proceed with invalid API keys and then fail when calling external APIs. No secret is exposed, no privilege boundary is crossed, and the impact is runtime error/availability only.

**Proof of concept**:
```
cp /target/.env.example /workspace/.env && python3 -c "import os; from dotenv import load_dotenv; load_dotenv('/workspace/.env'); print(os.getenv('ANTHROPIC_API_KEY'), os.getenv('ANTHROPIC_API_KEY').startswith('your_'))"
# Output shows placeholder value ANTHROPIC_API_KEY and False, so grading_script.py load_keys() would accept it and only fail later during API use.
```

**Remediation**: Treat exact placeholder values as invalid too, e.g. reject when value is empty, starts with "your_", or equals the env var name itself; optionally centralize this validation across scripts.

---

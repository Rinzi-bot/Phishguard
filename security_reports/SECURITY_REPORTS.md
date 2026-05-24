# Security Testing Reports - PhishGuard

## 1. Bandit (Static Analysis)
**Date:** 2026-05-21  
**Command:** `bandit -r app/ -f json`

**Findings Summary:**
- High: 0
- Medium: 2 (Fixed: Hardcoded debug=True moved to config)
- Low: 3

**Remediation:** All `assert` statements removed, secrets moved to `.env`

---

## 2. OWASP ZAP Baseline Scan
**Date:** 2026-05-21  
**Target:** http://localhost:5000

**Key Findings:**
- No High severity issues
- Medium: CSP Missing → Added via Flask-Talisman (recommended)
- Low: X-Frame-Options → Fixed with security headers

---

## 3. SonarQube Analysis
**Quality Gate:** Passed  
**Security Hotspots:** 1 (Reviewed and marked as safe)  
**Code Smells:** 4 (Reduced from 12)

**Overall Rating:** A
================================================================================
PHISHING URL DETECTOR
================================================================================
Rule-based phishing URL analysis with transparent scoring and JSON verdicts.

Version : 1.0.0
Author  : Rushikesh Kulkarni
Date    : 08 November 2026
Status  : Working prototype / educational triage tool
License : choose before publishing (MIT is a common choice; add a LICENSE file)

Suggested GitHub repository description:
  "Offline, explainable phishing URL detector: weighted indicators, JSON verdict
   (malicious / suspicious / legitimate), unknowns reported instead of guessed."
Suggested topics: phishing, cybersecurity, soc-analyst, url-analysis, threat-intelligence,
                  blue-team, python, homograph-attack, typosquatting


1. OVERVIEW
--------------------------------------------------------------------------------
Phishing URL Detector inspects a URL together with optional anchor text, message
context and a pre-parsed registrable domain, then returns a structured JSON verdict.
It never visits, fetches or resolves the URL (static, offline analysis), so it is
safe to run on malicious links. Every point of the score is explainable.

Key design rules
  * Confidence rule: anything that cannot be verified is listed under "unknowns".
  * "legitimate" means "no phishing indicators found", NOT "verified safe".
  * Every indicator carries its weight, e.g. "[+30]".
  * Python standard library only (3.8+). reportlab is needed only for build_report.py.


2. FEATURES
--------------------------------------------------------------------------------
  * Scheme checks: plain HTTP, missing scheme, data:/javascript: schemes
  * Host tricks: '@' userinfo, raw IP, obfuscated IP (decimal / hex / octal)
  * Homographs: Punycode decoding, mixed-script (Latin + Cyrillic/Greek) detection
  * Domain: high-abuse TLDs, URL shorteners, free-hosting platforms, subdomain depth,
    hyphen stuffing, credential words in the hostname
  * Brand impersonation: look-alike spelling (paypa1), brand in subdomain
    (paypal.com.evil.xyz), brand on unofficial domain, typosquats (44 brand keywords)
  * Query analysis: redirect parameters (open redirects), hidden base64 URLs,
    pre-filled victim e-mail
  * Anchor-text vs real-destination mismatch
  * Social-engineering context: urgency/threat, credential requests, prize/fee lures
  * Pre-parsed domain cross-check
  * Batch mode with CSV input, table output and built-in evaluation


3. PROJECT STRUCTURE
--------------------------------------------------------------------------------
  Phishing URL Detector/
  |-- phishing_detector.py          core engine + command-line interface
  |-- build_report.py               regenerates the PDF and this text report
  |-- prompt_template.txt           optional LLM-analyst prompt (second opinion)
  |-- requirements.txt
  |-- GitHub_Project_Report.txt     this file (use as README)
  |-- data/
  |   `-- sample_urls.csv           23 labelled sample URLs (invented domains)
  |-- tests/
  |   `-- test_detector.py          35 unit tests
  |-- results/
  |   |-- sample_results.json       full JSON verdicts for every sample
  |   |-- evaluation.txt            table + evaluation summary
  |   `-- unit_test_output.txt      verbose unit-test log
  `-- docs/
      `-- Phishing_URL_Detector_Project_Report.pdf   step-by-step analysis report

Tip: copy this file to README.md before pushing to GitHub.


4. INSTALLATION
--------------------------------------------------------------------------------
  git clone <your-repo-url>
  cd "Phishing URL Detector"
  python --version            # 3.8 or newer
  # nothing to install for the detector itself
  pip install -r requirements.txt     # only if you want to rebuild the PDF report


5. USAGE
--------------------------------------------------------------------------------
Single URL
  python phishing_detector.py --url "http://paypa1-secure-login.top/webscr"

With anchor text, context and a known domain
  python phishing_detector.py --url "https://bit.ly/abc" \
         --anchor "Track your parcel" \
         --context "Pay customs fee within 24 hours" --domain "bit.ly"

Several URLs from stdin (one per line)
  cat urls.txt | python phishing_detector.py --compact

Batch CSV (columns: url, anchor, context, domain, expected)
  python phishing_detector.py --batch data/sample_urls.csv --table --evaluate
  python phishing_detector.py --batch data/sample_urls.csv --output results/sample_results.json

As a library
  from phishing_detector import analyze_url
  result = analyze_url("https://example.org/login", context="Verify your account now")
  print(result["verdict"], result["risk_score"])

Template placeholders such as NONE, UNKNOWN or [INSERT URL HERE] are treated as
"not provided".


6. OUTPUT SCHEMA
--------------------------------------------------------------------------------
  {
    "verdict": "malicious" | "suspicious" | "legitimate",
    "risk_score": 0-100,
    "indicators_found": ["... [+points]"],
    "indicators_checked_absent": ["checks that ran and were clean"],
    "unknowns": ["data points that could not be verified"],
    "explanation": "one paragraph for technical or non-technical reviewers"
  }

Verdict thresholds: below 25 = legitimate, 25-59 = suspicious, 60+ = malicious.
Unparseable input returns "suspicious" with a neutral score of 50 and an explanation.


7. HOW IT WORKS (step by step)
--------------------------------------------------------------------------------
  1. Normalise input; read scheme (https/http/other/missing).
  2. Parse authority; flag '@' userinfo host deception.
  3. Classify host: domain, raw IP, obfuscated IP.
  4. Decode Punycode; detect non-ASCII and mixed-script homographs.
  5. Evaluate domain: TLD, shortener, free hosting, subdomain depth, hyphens, host words.
  6. Detect brand impersonation using a homoglyph/leetspeak "skeleton" and edit distance.
  7. Check port, length, percent-encoding, path depth and credential words in the path.
  8. Analyse query and fragment: redirect parameters, base64, pre-filled e-mail.
  9. Compare anchor text with the real destination.
 10. Score context: urgency, credential requests, lures, brand claims vs link.
 11. Sum weights (cap 100), apply combination rules, trusted-domain cap, unknown-domain floor.
 12. Emit the JSON verdict with found / absent / unknowns / explanation.

Scoring weights
  [Scheme] data:/javascript:/vbscript:/blob: scheme: +70
  [Scheme] Plain HTTP / unusual non-web scheme / mailto:, file:: +6 / +10 / +15
  [Host trick] '@' userinfo (extra if the userinfo looks like a domain): +35 (+15)
  [Host trick] Obfuscated IP / public raw IP / private or loopback IP: +40 / +30 / +15
  [Homograph] Mixed-script label or Punycode decoding to mixed scripts: +40
  [Homograph] Punycode or non-ASCII single-script label / undecodable Punycode: +25 / +15
  [Domain] High-abuse TLD: +12
  [Domain] URL shortener: +20
  [Domain] Free-hosting / user-content platform: +12
  [Domain] Subdomain depth >= 5 / >= 3: +14 / +8
  [Domain] >= 2 hyphens in the registrable label: +8
  [Domain] Credential words in hostname: 1 / 2 or more: +6 / +12
  [Brand] Look-alike spelling (homoglyph / leetspeak) of a brand: +38
  [Brand] Brand name on unofficial domain / embedded in domain: +35 / +30
  [Brand] Brand only in subdomain / possible typosquat: +35 / +35
  [Brand] Brand named in path of unrelated domain: +12
  [Network] Invalid port / unusual port: +15 / +12
  [Length] URL > 200 chars / > 100 chars / >= 6 percent-escapes / path depth > 6: +8 / +4 / +5 / +3
  [Path] Credential words in path: 1 / 2 or more: +8 / +12
  [Query] Redirect-style parameter to another domain / other parameter: +25 / +15
  [Query] Hidden base64 URL / opaque base64 blob: +18 / +6
  [Query] Pre-filled recipient e-mail address: +8
  [Cross-check] Pre-parsed registrable domain differs from parsed domain: +10
  [Anchor] Display text shows a different domain than the link target: +35
  [Context] Urgency / threat words: 1 / 2 / 3 or more: +6 / +12 / +18
  [Context] Credential request wording / prize-refund-fee lure: +8 / +8
  [Context] Message names a brand but link goes to an unrelated domain: +25
  [Combination] Brand impersonation + credential cue / HTTP + credential cue: +10 / +10

Trusted-domain rule : known-brand domain + https (or no scheme) + raw score < 25 -> score capped at 10.
Unknown-domain floor: a domain not on the list never scores below 8.


8. SAMPLE RESULTS (23 labelled URLs; domains are invented)
--------------------------------------------------------------------------------
   1. legitimate   0  https://www.google.com/
   2. legitimate   0  https://github.com/anthropics/claude-code
   3. legitimate   0  https://www.microsoft.com/en-in/windows
   4. legitimate  10  https://accounts.google.com/signin/v2/identifier
   5. legitimate   0  https://www.sbi.co.in/
   6. legitimate   0  https://en.wikipedia.org/wiki/Phishing
   7. legitimate   0  https://www.amazon.in/gp/cart/view.html
   8. legitimate  12  https://myportfolio.netlify.app/
   9. suspicious  34  http://bit.ly/3xYzAbC
  10. malicious   61  https://docs.google.com/forms/d/e/1FAIpQLSdEXAMPLE/viewform
  11. suspicious  32  https://account-verify.mysite-portal.xyz/login
  12. malicious   77  https://paypal.com.account-verify.xyz/login
  13. malicious   66  http://185.234.12.9/secure/paypal/signin.php?email=victim@exam
  14. malicious  100  https://paypa1-secure-login.top/webscr?cmd=_login
  15. malicious  100  https://login.microsoftonline.com.secure-auth.click/common/oau
  16. malicious   70  https://www.google.com@evil-site.top/login
  17. malicious  100  http://xn--pypal-4ve.com/
  18. malicious   86  https://secure.hdfc-netbanking-update.in/
  19. malicious   72  https://amaz0n-india-offers.shop/gift?redirect=aHR0cDovL2V2aWw
  20. suspicious  25  https://www.google.com/url?q=https://evil-login.top/steal
  21. malicious   70  data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
  22. malicious   72  http://login-update.securebank-alert.top:8443/index.html
  23. malicious   64  http://2130706433/admin/login

  Exact 3-class match     : 22/23 (95.7%)
  Phishing-vs-safe matrix : TP=15 TN=8 FP=0 FN=0
  Precision / recall      : 1.00 / 1.00
  Disagreements with the expected label:
  - sample #10: expected suspicious, got malicious (61/100)  https://docs.google.com/forms/d/e/1FAIpQLSdEXAMPLE/viewform

IMPORTANT: the sample set was hand-written by the author and used while developing
the rules (one rule was added after the first run exposed a missed case). These figures
show the engine behaves as designed; they are NOT an independent benchmark and must not
be quoted as real-world accuracy.


9. TESTING
--------------------------------------------------------------------------------
  python -m unittest discover -s tests -v
  35 tests, all passing. Covered: helpers, schema, determinism, trusted/unknown domains, every
  indicator family, anchor and context handling, robustness (empty input, placeholders,
  invalid port, missing scheme, IPv6, very long URL, score cap).


10. LIMITATIONS
--------------------------------------------------------------------------------
  * Offline only: no domain age, TLS, DNS, reputation feed or page-content checks.
    A clean-looking, freshly registered phishing domain can be rated low.
  * Small static brand/TLD/shortener lists; brands outside the list are not covered and
    legitimate lookalike names can be flagged.
  * Registrable domain is derived heuristically (no Public Suffix List).
  * Weights are hand-set expert heuristics, not learned from labelled data.
  * Rules can be evaded by an attacker who knows them; keywords are English-only.


11. ROADMAP
--------------------------------------------------------------------------------
  [ ] Optional online enrichment (RDAP/WHOIS age, TLS, Safe Browsing, PhishTank, URLhaus)
  [ ] Bundle Public Suffix List and full Unicode UTS #39 confusables
  [ ] Learn weights on a labelled corpus; report precision/recall on a held-out set
  [ ] Multilingual keywords, e-mail header parsing, QR-code (quishing) extraction
  [ ] CSV / STIX export, small web UI or browser extension


12. ETHICS AND DISCLAIMER
--------------------------------------------------------------------------------
Defensive tool for education and analyst triage. It does not fetch or execute anything
from the analysed URL and contains no phishing-kit or exploitation functionality.
Output is decision support, not proof: keep a human in the loop and follow your
organisation's policy when handling reported URLs and personal data inside them.
Provided "as is" without warranty.


13. SUGGESTED FIRST COMMIT
--------------------------------------------------------------------------------
  cd "Phishing URL Detector"
  cp GitHub_Project_Report.txt README.md
  git init
  git add .
  git commit -m "Initial release: rule-based phishing URL detector v1.0.0"
  git branch -M main
  git remote add origin https://github.com/<your-username>/phishing-url-detector.git
  git push -u origin main


14. REFERENCES
--------------------------------------------------------------------------------
  RFC 3986 (URI syntax), RFC 3492 (Punycode), RFC 5890 (IDNA),
  Unicode UTS #39 (Security Mechanisms), Public Suffix List (publicsuffix.org)

================================================================================

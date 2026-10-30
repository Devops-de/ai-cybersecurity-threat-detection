import re
import math
import numpy as np
from typing import Dict, Any, List
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

class PhishingEmailDetector:
    """
    Multimodal Phishing Email Analyzer:
    Combines NLP Semantic Analysis (TF-IDF + Logistic Regression)
    with deep heuristic domain verification, urgency detection, and URL risk scoring.
    """
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=500, stop_words="english", ngram_range=(1, 2))
        self.classifier = LogisticRegression(C=1.5, max_iter=200)
        self.suspicious_tlds = {".xyz", ".top", ".buzz", ".click", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".shop"}
        self.urgency_patterns = [
            r"urgent(ly)?", r"immediately", r"within 24 hours", r"account suspended",
            r"security alert", r"unauthorized access", r"action required", r"verify your account",
            r"wire transfer", r"gift card", r"payroll update", r"tax refund", r"final notice"
        ]
        self.credential_patterns = [
            r"login here", r"click here to (log in|verify|reset)", r"password (expired|reset)",
            r"update credentials", r"enter your pin", r"ssn", r"credit card"
        ]
        self._train_sample_corpus()

    def _train_sample_corpus(self):
        # High quality reference training data for phishing detection
        train_texts = [
            # Phishing examples
            "Urgent: Your Microsoft 365 account has been suspended due to suspicious activity. Click here to verify credentials.",
            "Immediate action required: Payroll direct deposit information could not be verified. Update your bank details now.",
            "Dear Customer, your PayPal account has unauthorized transactions. Sign in immediately to avoid permanent termination.",
            "Amazon order confirmation: Your iPhone 15 Pro order of $1,299 was placed. If this wasn't you, call support or click to cancel.",
            "HR Department: Mandatory employee benefit document update. Please enter your network password to access file.",
            "Wire transfer pending approval from CEO. Process this invoice within 2 hours to avoid vendor contract penalties.",
            "Security Notice: We detected an unfamiliar login from Russia. Verify your identity or your Google mailbox will be locked.",
            "IT Helpdesk: Mailbox quota reached 99%. Click the link below to upgrade storage quota or lose incoming emails.",
            "Tax Refund Notification: IRS has evaluated your refund of $850. Click link to submit banking details.",
            "Cryptocurrency alert: 1.5 BTC transferred to unknown wallet. Dispute transaction immediately by entering your private phrase.",
            # Benign examples
            "Hey team, here are the meeting notes from today's sprint retrospective. Let me know if anything was missed.",
            "Attached is the monthly security audit report for October 2026. All critical patches were applied successfully.",
            "Quick reminder that tomorrow is a company-wide holiday. Enjoy the long weekend!",
            "Project update: We have finalized the API specifications for the new microservices architecture. Review on GitHub.",
            "Weekly team lunch is planned for Friday 12:30 PM at the Italian place downtown. Please RSVP by Thursday.",
            "Here is the draft presentation for next week's client demonstration. Feedback appreciated by end of day.",
            "Your weekly GitHub digest: 14 pull requests merged, 3 issues opened in the core repository.",
            "Reminder: Antivirus software will run scheduled scans tonight at 11:00 PM. No downtime expected.",
            "Welcome to the team Sarah! Looking forward to working with you in the engineering group.",
            "The quarterly financial earnings call is scheduled for next Tuesday at 3 PM EST. Link is in the calendar invite."
        ]
        train_labels = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        
        X = self.vectorizer.fit_transform(train_texts)
        self.classifier.fit(X, train_labels)

    def _analyze_urls(self, text: str) -> List[Dict[str, Any]]:
        # Regex to capture URLs
        url_regex = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*"
        urls = re.findall(url_regex, text)
        url_findings = []

        for url in urls:
            risk = 0.0
            reasons = []
            
            # Check for IP address in URL
            if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
                risk += 0.50
                reasons.append("Raw IP address in URL host (high risk evasion)")

            # Check for suspicious TLDs
            for tld in self.suspicious_tlds:
                if tld in url.lower():
                    risk += 0.35
                    reasons.append(f"High-risk TLD detected ({tld})")
                    break

            # Check for typosquatting / brand spoofing in subdomains
            lower_url = url.lower()
            spoofed_brands = ["microsoft", "paypal", "google", "apple", "amazon", "netflix", "wellsfargo", "bankofamerica"]
            for brand in spoofed_brands:
                if brand in lower_url and not any(f".{brand}.com" in lower_url for brand in [brand]):
                    risk += 0.40
                    reasons.append(f"Potential typosquatting / brand impersonation: '{brand}'")

            # Check URL length and excessive subdomains
            if len(url) > 100:
                risk += 0.15
                reasons.append("Unusually long URL (possible payload encoding)")

            url_findings.append({
                "url": url,
                "risk_score": round(min(risk, 1.0), 2),
                "reasons": reasons
            })

        return url_findings

    def analyze_email(self, sender: str, subject: str, body: str, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Runs full phishing diagnostics on email payload.
        """
        full_text = f"{subject} {body}"
        headers = headers or {}
        
        # 1. ML NLP Confidence
        X_test = self.vectorizer.transform([full_text])
        ml_prob = float(self.classifier.predict_proba(X_test)[0][1])

        # 2. Urgency & Credential Harvesting Heuristics
        detected_urgency = []
        for pattern in self.urgency_patterns:
            if re.search(pattern, full_text, re.IGNORECASE):
                detected_urgency.append(pattern.replace("\\", "").replace("(", "").replace(")", "").replace("?", ""))

        detected_cred_traps = []
        for pattern in self.credential_patterns:
            if re.search(pattern, full_text, re.IGNORECASE):
                detected_cred_traps.append(pattern.replace("\\", "").replace("(", "").replace(")", ""))

        # 3. Sender & Header Analysis
        sender_risk = 0.0
        sender_flags = []
        sender_lower = sender.lower()

        # Check lookalike sender domain
        suspicious_sender_keywords = ["admin", "support", "security", "verify", "billing", "service-team", "account-update"]
        if any(kw in sender_lower for kw in suspicious_sender_keywords) and not sender_lower.endswith(("@company.com", "@enterprise.org")):
            sender_risk += 0.25
            sender_flags.append(f"Generic high-privilege sender alias outside primary corporate domain")

        # Check SPF / DKIM / DMARC status
        spf_status = headers.get("spf", "pass").lower()
        dmarc_status = headers.get("dmarc", "pass").lower()
        if spf_status in ["fail", "softfail"]:
            sender_risk += 0.35
            sender_flags.append(f"SPF authentication {spf_status.upper()}")
        if dmarc_status in ["fail"]:
            sender_risk += 0.30
            sender_flags.append(f"DMARC authentication FAILED")

        # 4. URL analysis
        url_findings = self._analyze_urls(body)
        max_url_risk = max([u["risk_score"] for u in url_findings], default=0.0)

        # 5. Composite Phishing Risk Score
        heuristic_score = 0.0
        heuristic_score += min(len(detected_urgency) * 0.15, 0.40)
        heuristic_score += min(len(detected_cred_traps) * 0.20, 0.40)
        heuristic_score += sender_risk
        heuristic_score += max_url_risk * 0.35

        composite_score = float(np.clip((ml_prob * 0.45) + (heuristic_score * 0.55), 0.02, 0.99))
        is_phishing = composite_score >= 0.65

        threat_level = "LOW"
        if composite_score >= 0.85:
            threat_level = "CRITICAL"
        elif composite_score >= 0.65:
            threat_level = "HIGH"
        elif composite_score >= 0.45:
            threat_level = "SUSPICIOUS"

        recommendations = []
        if is_phishing:
            recommendations.append("Quarantine email across enterprise mailboxes immediately.")
            recommendations.append(f"Block sender domain '{sender.split('@')[-1] if '@' in sender else sender}' at Secure Email Gateway (SEG).")
            if url_findings:
                recommendations.append("Sinkhole extracted URLs at corporate DNS/Proxy perimeter.")
            if detected_cred_traps:
                recommendations.append("Initiate password reset for any user who interacted with this email.")
        else:
            recommendations.append("Email conforms to typical organizational correspondence patterns.")

        return {
            "is_phishing": is_phishing,
            "phishing_score": round(composite_score, 4),
            "threat_level": threat_level,
            "ml_confidence": round(ml_prob, 4),
            "indicators": {
                "detected_urgency_triggers": detected_urgency,
                "credential_harvesting_cues": detected_cred_traps,
                "sender_flags": sender_flags,
                "urls_scanned": url_findings
            },
            "soc_recommendations": recommendations
        }

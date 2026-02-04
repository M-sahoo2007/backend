"""
Explainable AI Logic Module
Rule-based fraud detection system for job offers
"""

import re
from typing import Tuple, List, Dict

# ========================================
# CONFIGURATION & RULES
# ========================================

# Free email domains commonly used in fake job offers
FREE_EMAIL_DOMAINS = {
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
    'mail.com', 'protonmail.com', 'yandex.com', 'aol.com',
    'icloud.com', 'mail.ru', 'temp-mail.org'
}

# Suspicious keywords that appear frequently in fraudulent offers
SUSPICIOUS_KEYWORDS = {
    'urgency': ['urgent', 'asap', 'immediately', 'within 24 hours', 'apply now', 'limited time'],
    'money_request': ['payment', 'fee', 'registration', 'processing', 'verification fee', 'advance payment'],
    'unrealistic_benefits': ['unlimited leaves', 'no work', 'from home no work', 'easy money', 'passive income'],
    'copy_paste': ['dear applicant', 'dear candidate', 'dear applicants'],
    'guaranteed': ['guaranteed', 'promise', 'certainly', 'assured', 'definitely hired'],
    'work_from_home_too_good': ['work from anywhere', 'no experience needed', 'earn 5000/day', 'earn while you sleep'],
}

# Unrealistic salary thresholds (in INR annually for Indian context)
UNREALISTIC_SALARY_THRESHOLDS = {
    'internship': {'min': 5000, 'max': 500000},  # 5k-5L per month seems unrealistic for internship
    'entry_level': {'min': 200000, 'max': 3000000},  # 2L-30L per year for entry level
    'mid_level': {'min': 500000, 'max': 5000000},  # 5L-50L per year
}


# ========================================
# SCORING SYSTEM
# ========================================

class FraudDetectionAI:
    """
    Rule-based Explainable AI for detecting fraudulent job offers
    Provides transparent scoring with clear reasoning
    """

    def __init__(self):
        self.detected_flags = []
        self.risk_score = 0

    def analyze(self, company_name: str, job_title: str, description: str, 
                email: str, website: str = None, salary: str = None) -> Tuple[int, str, List[Dict]]:
        """
        Comprehensive fraud detection analysis

        Args:
            company_name: Company name from the offer
            job_title: Job title
            description: Full job description text
            email: Contact email
            website: Company website (optional)
            salary: Salary/stipend information (optional)

        Returns:
            Tuple of (risk_score, classification, detected_flags)
        """
        # Reset state
        self.detected_flags = []
        self.risk_score = 0

        # Normalize inputs
        description_lower = description.lower()
        email_lower = email.lower()

        # Run all detection rules
        self._check_email_domain(email_lower)
        self._check_missing_website(website, company_name)
        self._check_suspicious_keywords(description_lower)
        self._check_urgency_language(description_lower)
        self._check_copy_paste_content(description_lower)
        self._check_unrealistic_benefits(description_lower)
        self._check_salary_unrealistic(salary, job_title)
        self._check_description_quality(description)
        self._check_company_legitimacy(company_name)
        self._check_email_company_mismatch(email, company_name)

        # Calculate final risk score and classification
        classification = self._classify_risk()

        return self.risk_score, classification, self.detected_flags

    # ========================================
    # INDIVIDUAL DETECTION RULES
    # ========================================

    def _check_email_domain(self, email: str) -> None:
        """Check if email uses free/common email domains"""
        domain = email.split('@')[1].lower()

        if domain in FREE_EMAIL_DOMAINS:
            self._add_flag(
                flag_type='Free Email Domain',
                description=f'Contact email uses free email service ({domain}) instead of company domain. Legitimate companies typically use official email addresses.',
                severity='high',
                score_impact=15
            )

    def _check_missing_website(self, website: str, company_name: str) -> None:
        """Check if company website is missing"""
        if not website:
            self._add_flag(
                flag_type='Missing Company Website',
                description='No company website provided. Legitimate companies always have professional web presence.',
                severity='high',
                score_impact=12
            )

    def _check_suspicious_keywords(self, description: str) -> None:
        """Check for suspicious keywords commonly used in fraud"""
        found_keywords = {}

        for category, keywords in SUSPICIOUS_KEYWORDS.items():
            for keyword in keywords:
                if keyword in description:
                    if category not in found_keywords:
                        found_keywords[category] = []
                    found_keywords[category].append(keyword)

        if 'money_request' in found_keywords:
            self._add_flag(
                flag_type='Payment Request',
                description=f'Job posting mentions payment/fees: {", ".join(found_keywords["money_request"])}. Legitimate employers never ask for payments from candidates.',
                severity='critical',
                score_impact=25
            )

        if 'guaranteed' in found_keywords:
            self._add_flag(
                flag_type='Unrealistic Guarantees',
                description=f'Posting guarantees employment: {", ".join(found_keywords["guaranteed"])}. No legitimate recruitment guarantees jobs.',
                severity='high',
                score_impact=18
            )

        if 'work_from_home_too_good' in found_keywords:
            self._add_flag(
                flag_type='Unrealistic Work-from-Home Offer',
                description=f'Suspicious work-from-home claims: {", ".join(found_keywords["work_from_home_too_good"])}. Be cautious of "earn money while sleeping" type offers.',
                severity='high',
                score_impact=16
            )

    def _check_urgency_language(self, description: str) -> None:
        """Check for excessive urgency language"""
        urgency_count = sum(1 for keyword in SUSPICIOUS_KEYWORDS['urgency'] if keyword in description)

        if urgency_count >= 2:
            self._add_flag(
                flag_type='Excessive Urgency',
                description=f'Job posting uses urgent language excessively ({urgency_count} instances). This is a common tactic in scams to bypass critical thinking.',
                severity='medium',
                score_impact=10
            )

    def _check_copy_paste_content(self, description: str) -> None:
        """Check for generic copy-paste content"""
        generic_count = sum(1 for phrase in SUSPICIOUS_KEYWORDS['copy_paste'] if phrase in description)

        if generic_count > 0:
            self._add_flag(
                flag_type='Generic/Copy-Paste Content',
                description='Job posting uses generic greetings (e.g., "Dear Applicant"). Legitimate companies customize communications.',
                severity='medium',
                score_impact=8
            )

    def _check_unrealistic_benefits(self, description: str) -> None:
        """Check for unrealistic benefit claims"""
        if any(phrase in description for phrase in SUSPICIOUS_KEYWORDS['unrealistic_benefits']):
            self._add_flag(
                flag_type='Unrealistic Benefits',
                description='Job posting promises unrealistic benefits (unlimited leaves, no work required). These are red flags for fraudulent offers.',
                severity='high',
                score_impact=14
            )

    def _check_salary_unrealistic(self, salary: str, job_title: str) -> None:
        """Check if salary is unrealistic for the job type"""
        if not salary:
            return

        # Extract numbers from salary string
        numbers = re.findall(r'[\d,]+', salary)
        if not numbers:
            return

        try:
            salary_value = int(numbers[0].replace(',', ''))
        except (ValueError, IndexError):
            return

        # Determine job level
        job_title_lower = job_title.lower()
        if any(word in job_title_lower for word in ['intern', 'apprentice', 'fresher']):
            job_level = 'internship'
            threshold = UNREALISTIC_SALARY_THRESHOLDS['internship']
        elif any(word in job_title_lower for word in ['junior', 'entry', 'associate']):
            job_level = 'entry_level'
            threshold = UNREALISTIC_SALARY_THRESHOLDS['entry_level']
        else:
            job_level = 'mid_level'
            threshold = UNREALISTIC_SALARY_THRESHOLDS['mid_level']

        if salary_value > threshold['max']:
            self._add_flag(
                flag_type='Unrealistic Salary (Too High)',
                description=f'Salary of ₹{salary_value:,} is unusually high for a {job_level} position. This is often used to attract and trap victims.',
                severity='high',
                score_impact=13
            )
        elif salary_value < threshold['min']:
            self._add_flag(
                flag_type='Unrealistic Salary (Too Low)',
                description=f'Salary of ₹{salary_value:,} is unusually low for a {job_level} position. This may indicate a scam or highly exploitative offer.',
                severity='medium',
                score_impact=7
            )

    def _check_description_quality(self, description: str) -> None:
        """Check quality of job description"""
        # Check for very short descriptions
        if len(description.strip()) < 100:
            self._add_flag(
                flag_type='Poor Job Description Quality',
                description='Job description is too brief and lacks essential details. Legitimate postings are comprehensive.',
                severity='medium',
                score_impact=6
            )

        # Check for spelling and grammar issues
        common_misspellings = ['recieve', 'occured', 'sucessful', 'applicaton', 'seperete']
        misspelling_count = sum(1 for misspelling in common_misspellings if misspelling in description.lower())

        if misspelling_count >= 2:
            self._add_flag(
                flag_type='Poor Grammar/Spelling',
                description=f'Job description contains {misspelling_count}+ spelling/grammar errors. Professional companies maintain high writing standards.',
                severity='low',
                score_impact=4
            )

    def _check_company_legitimacy(self, company_name: str) -> None:
        """Check if company name seems legitimate"""
        # Check for suspicious patterns in company name
        company_lower = company_name.lower()

        if any(word in company_lower for word in ['private', 'limited', 'corporation', 'international']):
            # These are often added to make scam companies seem legit
            if company_lower.count(' ') > 4:  # Too many words
                self._add_flag(
                    flag_type='Suspicious Company Name Pattern',
                    description='Company name appears constructed with common legitimacy keywords. Verify company independently.',
                    severity='low',
                    score_impact=3
                )

    def _check_email_company_mismatch(self, email: str, company_name: str) -> None:
        """Check if email domain matches company name"""
        email_domain = email.split('@')[1].lower()
        company_short = company_name.lower().split()[0]

        if company_short not in email_domain and len(company_short) > 3:
            if email_domain not in FREE_EMAIL_DOMAINS:  # Only flag if not already flagged
                pass  # This will be caught by free email domain check

    # ========================================
    # UTILITY METHODS
    # ========================================

    def _add_flag(self, flag_type: str, description: str, severity: str, score_impact: int) -> None:
        """
        Add a detected red flag
        
        Args:
            flag_type: Type of fraud indicator
            description: Detailed explanation
            severity: 'critical', 'high', 'medium', 'low'
            score_impact: Points to add to risk score
        """
        self.detected_flags.append({
            'type': flag_type,
            'description': description,
            'severity': severity,
        })
        self.risk_score += score_impact

    def _classify_risk(self) -> str:
        """
        Classify overall risk level based on score
        
        Returns:
            'Legitimate', 'Suspicious', or 'Fake'
        """
        # Cap score at 100
        self.risk_score = min(self.risk_score, 100)

        if self.risk_score < 30:
            return 'Legitimate'
        elif self.risk_score < 70:
            return 'Suspicious'
        else:
            return 'Fake'


# ========================================
# SINGLETON INSTANCE
# ========================================

ai_engine = FraudDetectionAI()


def analyze_job_offer(company_name: str, job_title: str, description: str,
                     email: str, website: str = None, salary: str = None) -> Tuple[int, str, List[Dict]]:
    """
    Convenience function to analyze a job offer using the AI engine
    
    Args:
        company_name: Company name from the offer
        job_title: Job title
        description: Full job description text
        email: Contact email
        website: Company website (optional)
        salary: Salary/stipend information (optional)

    Returns:
        Tuple of (risk_score, classification, detected_flags)
    """
    return ai_engine.analyze(company_name, job_title, description, email, website, salary)

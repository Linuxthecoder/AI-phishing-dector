import re
import spacy
import numpy as np
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from urlextract import URLExtract
from tld import get_tld
import requests
from typing import Dict, List, Tuple

class PhishingDetector:
    def __init__(self):
        """Initialize the PhishingDetector with necessary tools and models"""
        self.nlp = spacy.load("en_core_web_sm")
        self.url_extractor = URLExtract()
        
        self.suspicious_keywords = [
            'urgent', 'account', 'suspended', 'verify', 'security',
            'update', 'banking', 'password', 'confirm', 'unauthorized',
            'access', 'login', 'unusual', 'activity', 'compromise'
        ]
        
       
        self.safe_domains = {
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'twitter.com', 'linkedin.com'
        }

    def analyze_email(self, subject: str, body: str) -> Dict:
        """
        Analyze an email for potential phishing indicators
        
        Args:
            subject (str): Email subject
            body (str): Email body text
            
        Returns:
            Dict: Analysis results with risk score and warnings
        """
        results = {
            'risk_score': 0,
            'warnings': [],
            'suspicious_urls': [],
            'risk_factors': []
        }
        
    
        subject_score = self._analyze_subject(subject)
        results['risk_score'] += subject_score
        
        
        body_score, body_warnings = self._analyze_body(body)
        results['risk_score'] += body_score
        results['warnings'].extend(body_warnings)
        
   
        url_score, suspicious_urls = self._analyze_urls(body)
        results['risk_score'] += url_score
        results['suspicious_urls'] = suspicious_urls
        
        # Normalize risk score to 0-100
        results['risk_score'] = min(100, max(0, results['risk_score']))
        
        # Add overall assessment
        results['risk_level'] = self._get_risk_level(results['risk_score'])
        
        return results

    def _analyze_subject(self, subject: str) -> float:
        """Analyze email subject for suspicious patterns"""
        score = 0
        
        urgency_patterns = r'\b(urgent|immediate|action required|asap|important)\b'
        if re.search(urgency_patterns, subject.lower()):
            score += 20
        
        for keyword in self.suspicious_keywords:
            if keyword in subject.lower():
                score += 10
       
       
        if len(re.findall(r'[!?]', subject)) > 2:
            score += 15
            
        return score

    def _analyze_body(self, body: str) -> Tuple[float, List[str]]:
        """Analyze email body for suspicious patterns"""
        score = 0
        warnings = []
        
     
        if '<' in body and '>' in body:
            soup = BeautifulSoup(body, 'html.parser')
            body = soup.get_text()
        
        
        doc = self.nlp(body)
        
        urgency_patterns = [
            r'\b(must|urgent|immediate|today|now)\b.*\b(verify|confirm|validate)\b',
            r'account.*\b(suspend|block|close)\b',
            r'security.*\b(breach|compromise|threat)\b'
        ]
        
        for pattern in urgency_patterns:
            if re.search(pattern, body.lower()):
                score += 15
                warnings.append(f"Detected urgency/pressure tactics: {pattern}")
        
        if len(doc.ents) < len(body.split()) / 50:  
            score += 10
            warnings.append("Possible poor grammar or unusual language patterns detected")
        
        sensitive_info_patterns = [
            r'\b(ssn|social security|credit card|password)\b',
            r'\b(bank account|routing number)\b'
        ]
        
        for pattern in sensitive_info_patterns:
            if re.search(pattern, body.lower()):
                score += 25
                warnings.append("Requesting sensitive personal information")
        
        return score, warnings

    def _analyze_urls(self, body: str) -> Tuple[float, List[str]]:
        """Analyze URLs in the email body"""
        score = 0
        suspicious_urls = []
        
       
        urls = self.url_extractor.find_urls(body)
        
        for url in urls:
            try:
                parsed_url = urlparse(url)
                domain = get_tld(url, as_object=True, fail_silently=True)
                
                if domain:
                    domain_name = domain.fld
                    
                    for safe_domain in self.safe_domains:
                        if safe_domain in domain_name and domain_name not in self.safe_domains:
                            score += 30
                            suspicious_urls.append(f"Suspicious URL: {url} (Possible imitation of {safe_domain})")
                    
                    suspicious_tlds = ['.xyz', '.tk', '.top', '.work', '.date']
                    if any(domain_name.endswith(tld) for tld in suspicious_tlds):
                        score += 15
                        suspicious_urls.append(f"Suspicious TLD in URL: {url}")
                    
                    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                        score += 25
                        suspicious_urls.append(f"IP address used in URL: {url}")
                    
            except Exception as e:
                score += 10
                suspicious_urls.append(f"Malformed URL detected: {url}")
        
        return score, suspicious_urls

    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level"""
        if risk_score >= 80:
            return "HIGH"
        elif risk_score >= 50:
            return "MEDIUM"
        elif risk_score >= 20:
            return "LOW"
        else:
            return "SAFE" 

# AI Phishing Email Detector

## Overview
This Python application analyzes email content to detect potential phishing attempts using natural language processing (NLP) and URL analysis. The system examines email subjects, body content, and embedded URLs to identify suspicious patterns commonly found in phishing attacks.

## Key Features
- **Subject Analysis**: Detects urgency indicators and suspicious keywords
- **Body Content Analysis**:
  - Identifies pressure tactics and urgency patterns
  - Flags requests for sensitive information
  - Detects poor grammar and spelling issues
- **URL Inspection**:
  - Identifies suspicious domains that imitate legitimate sites
  - Flags unusual top-level domains (TLDs)
  - Detects IP addresses in URLs
- **Risk Assessment**:
  - Generates a risk score (0-100)
  - Provides risk level categorization (SAFE, LOW, MEDIUM, HIGH)
  - Offers actionable recommendations

## How It Works
The detection system uses a multi-layered approach:
1. **Subject Analysis** - Checks for urgency patterns and suspicious keywords
2. **Body Processing**:
   - Converts HTML emails to plain text
   - Uses spaCy NLP for grammatical analysis
   - Detects sensitive information requests
3. **URL Examination**:
   - Extracts all URLs using URLExtract
   - Compares against known safe domains
   - Checks for suspicious TLDs and IP addresses
4. **Risk Calculation** - Combines scores from all components to determine overall risk

## Installation
1. Clone the repository:
```bash
git clone https://github.com/yourusername/phishing-detector.git
cd phishing-detector

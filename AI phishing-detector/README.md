# AI Phishing Email Detector

This tool uses AI and natural language processing to analyze emails for potential phishing attempts. It examines various aspects of an email including:

- Subject line analysis
- Body content analysis
- URL/link inspection
- Grammar and language patterns
- Urgency and pressure tactics
- Requests for sensitive information

## Features

- Comprehensive email analysis
- Risk score calculation (0-100)
- Risk level classification (SAFE, LOW, MEDIUM, HIGH)
- Detailed warnings and explanations
- Suspicious URL detection
- Recommendations based on risk level

## Installation

1. Clone this repository:
```bash
git clone [repository-url]
cd ai-phishing-detector
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

4. The first time you run the program, it will automatically download the required spaCy language model.

## Usage

Run the program:
```bash
python main.py
```

The program will prompt you to:
1. Enter the email subject
2. Enter the email body (paste the content and press Ctrl+D on Unix or Ctrl+Z on Windows when finished)

The analysis results will show:
- Overall risk level
- Risk score
- Specific warnings
- Suspicious URLs detected
- Recommendations

## Example

```
=== AI Phishing Email Detector ===
Enter the email details below:

Email Subject: Urgent: Your Account Has Been Suspended

Email Body:
Dear User,
Your account has been suspended due to suspicious activity. Click here to verify your identity: http://suspicious-site.xyz
Please provide your password and social security number for verification.
Regards,
Security Team

=== Analysis Results ===
Risk Level: HIGH
Risk Score: 85.00/100

Warnings:
- Detected urgency/pressure tactics
- Requesting sensitive personal information
- Suspicious URL detected
...
```

## Security Note

This tool is meant to assist in identifying potential phishing attempts but should not be the only method of verification. Always exercise caution with suspicious emails and follow your organization's security policies. 
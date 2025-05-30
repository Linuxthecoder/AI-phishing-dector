from phishing_detector import PhishingDetector
import spacy
import sys

def download_spacy_model():
    try:
        spacy.load("en_core_web_sm")
    except OSError:
        print("Downloading required language model...")
        spacy.cli.download("en_core_web_sm")
        print("Model downloaded successfully!")

def main():
    # Download spacy model if not already installed
    download_spacy_model()
    
    # Initialize the detector
    detector = PhishingDetector()
    
    print("=== AI Phishing Email Detector ===")
    print("Enter the email details below (press Ctrl+D or Ctrl+Z when finished):")
    
    # Get email subject
    subject = input("\nEmail Subject: ").strip()
    
    print("\nEmail Body (enter/paste the content and press Ctrl+D or Ctrl+Z when done):")
    body_lines = []
    
    try:
        while True:
            line = input()
            body_lines.append(line)
    except (EOFError, KeyboardInterrupt):
        body = "\n".join(body_lines)
    
    # Analyze the email
    results = detector.analyze_email(subject, body)
    
    # Display results
    print("\n=== Analysis Results ===")
    print(f"Risk Level: {results['risk_level']}")
    print(f"Risk Score: {results['risk_score']:.2f}/100")
    
    if results['warnings']:
        print("\nWarnings:")
        for warning in results['warnings']:
            print(f"- {warning}")
    
    if results['suspicious_urls']:
        print("\nSuspicious URLs detected:")
        for url in results['suspicious_urls']:
            print(f"- {url}")
    
    # Provide recommendations
    print("\nRecommendations:")
    if results['risk_level'] in ["HIGH", "MEDIUM"]:
        print("- Do NOT click on any links or download any attachments")
        print("- Do NOT respond to this email")
        print("- Report this email to your IT department or email provider")
        print("- If this appears to be from a legitimate company, contact them directly through their official website")
    elif results['risk_level'] == "LOW":
        print("- Proceed with caution")
        print("- Verify the sender's identity through alternative means if unsure")
    else:
        print("- This email appears to be safe, but always remain vigilant")

if __name__ == "__main__":
    main() 
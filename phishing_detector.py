import re
from urllib.parse import urlparse

def is_ip_address_in_url(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        if hostname and ip_pattern.match(hostname):
            return True
    except Exception:
        pass # Invalid URL format
    return False

def is_long_url(url, max_length=50):
    return len(url) > max_length

def has_at_symbol(url):
    """
    Checks for the '@' symbol in the URL, often used to embed credentials or confuse users.
    Example: http://legitimate.com@phishing.com/
    """
    return '@' in url

def count_subdomains(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname:
            # Split by dot and remove TLD and main domain
            parts = hostname.split('.')
            if len(parts) > 2:
                return len(parts) - 2
            elif len(parts) == 2: 
                return 0
    except Exception:
        pass
    return 0

def uses_https(url):
    """
    Checks if the URL uses HTTPS (secure protocol). Lack of HTTPS can be a red flag.
    """
    try:
        parsed_url = urlparse(url)
        return parsed_url.scheme == 'https'
    except Exception:
        return False 

def has_suspicious_keywords(url):
    """
    Checks for common keywords used in phishing URLs.
    """
    suspicious_keywords = ['login', 'signin', 'verify', 'account', 'secure', 'webscr', 'banking', 'confirm']
    normalized_url = url.lower()
    for keyword in suspicious_keywords:
        if keyword in normalized_url:
            return True
    return False

def assess_url_phishing_risk(url):
    risk_score = 0
    reasons = []
    status = "Legitimate"

    # IP Address in URL
    if is_ip_address_in_url(url):
        risk_score += 2
        reasons.append("Uses an IP address instead of a domain name.")

    if is_long_url(url, max_length=75): 
        risk_score += 1
        reasons.append(f"URL is excessively long (>{75} characters).")

    # Presence of '@' symbol
    if has_at_symbol(url):
        risk_score += 2
        reasons.append("Contains '@' symbol, which can be used to hide the true domain.")

    num_subdomains = count_subdomains(url)
    if num_subdomains > 3: 
        risk_score += 1
        reasons.append(f"Has a high number of subdomains ({num_subdomains}).")

    # Lack of HTTPS
    if not uses_https(url):
        risk_score += 1
        reasons.append("Does not use HTTPS (not a secure connection).")

    if has_suspicious_keywords(url):
        risk_score += 1
        reasons.append("Contains suspicious keywords commonly found in phishing URLs.")

    # Overall Status
    if risk_score >= 4:
        status = "High Risk (Likely Phishing)"
    elif risk_score >= 2:
        status = "Moderate Risk (Suspicious)"
    elif risk_score > 0:
        status = "Low Risk (Potentially Suspicious)"
    else:
        status = "Legitimate (No obvious phishing indicators)"

    return {
        "url": url,
        "status": status,
        "risk_score": risk_score,
        "reasons": reasons
    }

def main():
    print("\n--- Phishing Website Detection Tool (Rule-Based) ---")
    print("Enter a URL to assess its phishing risk. Type 'exit' to quit.")
    print("Disclaimer: This tool is for educational purposes and provides basic indicators. Always exercise caution online.")

    while True:
        url_input = input("\nEnter URL: ").strip()
        if url_input.lower() == 'exit':
            print("Exiting tool. Stay safe online!")
            break

        if not url_input:
            print("Please enter a URL.")
            continue
        if not url_input.startswith(('http://', 'https://')):
            url_input = 'http://' + url_input
            print(f"Prepending 'http://' to URL for analysis: {url_input}")


        result = assess_url_phishing_risk(url_input)

        print("\n--- Assessment Result ---")
        print(f"URL: {result['url']}")
        print(f"Risk Status: {result['status']}")
        print(f"Risk Score: {result['risk_score']}")

        if result['reasons']:
            print("Reasons for suspicion:")
            for reason in result['reasons']:
                print(f"- {reason}")
        else:
            print("No obvious phishing indicators found based on current rules.")

if __name__ == "__main__":
    main()
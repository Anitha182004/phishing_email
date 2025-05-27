Phishing Incident Report: GitHub OAuth Phishing Email
Date of Report: May 27, 2025
Reported by: Security Operations Center (SOC)
Incident ID: PHISH-2025-0527-GH
________________________________________
1. Summary
A phishing campaign targeting GitHub users was identified, attempting to trick recipients into authorizing a malicious OAuth application. The phishing email impersonates GitHub and leverages legitimate-looking links to gain elevated access to users' GitHub accounts and repositories.
_![image](https://github.com/user-attachments/assets/aef344a2-a0d9-480f-913e-36aa034d2086)
_______________________________________
2. Phishing Email Details
•	Subject Line: [GitHub] Action Required: Reauthorize OAuth Access
•	Sender Address: noreply@github-security.com (spoofed domain)
•	Timestamp: May 26, 2025, 10:34 AM UTC
•	Email Body Summary:
o	Claims there is an issue with an OAuth token that needs reauthorization.
o	Urges the user to click a link to “restore access.”
o	Includes GitHub-style branding and formatting to appear legitimate.
Example Body Excerpt:
“We've detected an issue with your OAuth token used for GitHub API access.
To prevent interruption, please reauthorize the application by visiting the link below:
[Authorize OAuth Access]”
•	Phishing Link (obfuscated):
https://github.com.login.security-check[.]app/authorize
![image](https://github.com/user-attachments/assets/687f41b8-ba75-416e-8e04-c90faca74801)

________________________________________
3. Malicious Behavior
Upon clicking the phishing link:
•	The user is redirected to a fake GitHub login page.
•	Credentials and OAuth authorization are captured.
•	The attacker uses the captured token to:
o	Access private repositories.
o	Clone or exfiltrate source code.
o	Modify repository content.
o	Create backdoor access (e.g., adding SSH keys or actions secrets).
![image](https://github.com/user-attachments/assets/bfab04d2-2d3e-4fa5-8f3f-9f588af77f62)

________________________________________
4. Indicators of Compromise (IOCs)
Type	Indicator
Domain	github-security-check[.]app
IP Address	185.213.211.12 (phishing host)
URL Path	/authorize
Email Address	noreply@github-security.com (spoofed)
________________________________________
5. Mitigation Actions Taken
•	Blocked the phishing domain on email gateway and proxy filters.
•	Reported the phishing page to hosting provider and GitHub.
•	Alerted affected users and reset compromised credentials.
•	Reviewed OAuth app authorizations on impacted accounts.
•	Conducted internal threat hunt for malicious commits or exfiltration.
•	Updated phishing detection rules and shared IOCs with threat intel partners.
________________________________________
6. Recommendations
•	User Awareness: Conduct targeted phishing training focusing on OAuth scams.
•	OAuth Hygiene: Regularly audit authorized third-party GitHub applications.
•	MFA Enforcement: Ensure multi-factor authentication is enabled for all users.
•	Email Security: Improve SPF, DKIM, and DMARC enforcement.
•	Incident Response: Enhance playbooks to cover OAuth abuse vectors.
________________________________________
7. Conclusion
This incident highlights the increasing sophistication of OAuth-based phishing attacks and
the need for vigilant user behavior and strong account hygiene on code-hosting platforms
like GitHub.Continuous monitoring and user education remain essential to prevent similar
threats.


# Email-Forensic-Analysis

## Executive Summary
On August 16, 2023, a suspicious email purporting to be a Microsoft account security notification was received and subjected to forensic analysis. The email, titled "Microsoft account unusual sign-in activity," was crafted to imitate legitimate Microsoft communications but failed critical authentication checks, indicating it was a phishing attempt. 
 
Analysis of the email headers revealed that the message originated from an IP address in Germany (89[.]144[.]44[.]41) associated with a hosting provider known for abuse and malicious activity. The domain used to send the email, access-accsecurity.com, is unaffiliated with Microsoft and showed no valid SPF, DKIM, or DMARC authentication, allowing for easy spoofing. Moreover, the "Reply-To" address directed responses to a free Gmail account, further highlighting the malicious intent behind the communication. 
 
The email’s structure included social engineering tactics designed to create urgency, including claims of a suspicious login from Russia, and embedded an invisible tracking pixel hosted on a non-Microsoft domain (thebandalisty[.]com). These elements indicate a high level of threat aimed at compromising user credentials or gathering reconnaissance information. 
 
Based on the findings, the email has been classified as phishing and spoofed. Immediate action has been recommended, including blocking the sender domain and IP address, alerting internal users, submitting the phishing email to Microsoft, enhancing email authentication checks, and monitoring for similar threats. These proactive measures will help mitigate risk, prevent further exposure, and strengthen the organization's resilience against future phishing campaigns.

# Objective
This Lab aimed to establish analyze the Phishing email. The primary focus was to analyze email headers, IP address, links, content, DKIM, SPF, and DMARC authentication. 

### Methodology
The email forensic analysis involved the following steps: 
 
1. Email Metadata Extraction: Retrieving and examining the email's metadata, including 
subject, sender, recipient, date, and reply-to information. 
2. IP Address Analysis and Mail Flow Tracing: Identifying the originating IP address, its 
geolocation and tracing the path of the email through various servers (received 
headers). 
3. Authentication Results Verification: Checking the email's SPF, DKIM, and DMARC 
records to determine its legitimacy and security. 
4. Exchange Authentication Headers Examination: Analyzing specific Exchange 
headers (e.g., X-MS-Exchange-Organization-AuthAs, X-MS-Exchange-Organization-
AuthSource) to understand how the email was authenticated within the Exchange 
environment. 
5. Sender and Domain Validation: Comparing the stated sender and reply-to addresses 
with official Microsoft domains and verifying A and MX records. 
6. Timestamp and Delivery Path Analysis: Examining timestamps within the email 
headers for inconsistencies and analyzing the delivery path for anomalies or 
manipulation. 
7. Extracted URL/Domain Analysis: Identifying and dissecting any embedded URLs or 
Domains within the email body. 
8. Overall Assessment and Recommendation: Consolidating the findings to determine 
the nature of the email (legitimate or phishing) and providing recommendations for 
mitigating future similar threats.

### Tools Used 
Below is the list of tools used in the analysis: 
● Phishtool: used to reverse engineer the email for analysis. 
 
● EML Analyzer: used to understand the details within the email, including attachments 
and links, to potentially identify malicious content or signs of a phishing attempt. 
 
● MXToolbox: used for checking domain records (MX/A) 
 
● Talos Intelligence: used for IP address and domain lookups 
 
● VirusTotal: used it to analyze URLs, domains, and IP addresses to identify potential 
threats

## Analysis
The image below shows the email received about an unusual sign-in activity on a Microsoft 
account [phishing@pot]. The sign-in occurred on August 16, 2023, from a Windows device in 
Moscow, Russia, with the IP address 103.225.77.255. 
 
![image](https://github.com/user-attachments/assets/a22d0528-df8b-4ff8-97f9-284abb1f571d)
                
*Image by phishtool*

 Email MetaData Overview

|      Field                                  | Value       |
|-----------------------------------------------|----------------------------|
|   Message ID       |<06550bd4-ce4e-4e8c-acf9-f8936085be09@MW2NAM04FT048.eop-NAM04.prod.protection.outlook.com>|
|Subject  |Microsoft account unusual sign in activity |
|From     | no-reply@access-accsecurity[.]com|
|Reply-To                |solutionteamrecognizd03@gmail.com|
| To|        phishing@pot|
|       Date Received                   | 12:15 am, Aug 16th, 2023|


# IP Address Analysis and Mail Flow
# a. Originating IP Address
●IP: 89[.]144[.]44[.]41 (atujpdfghher.co[.]uk)
●Geo-Location: Bad Homburg, Germany
●Does this match the sender's domain? It does not match the “sender “domain access-accsecurity[.]com or any Microsoft infrastructure.

Domain lookup was performed to gain additional information about the originating IP address
 
![image](https://github.com/user-attachments/assets/44fbd720-b1cf-479f-bbc6-a44b1e293726)

 *whois lookup by VirusTotal*

# Received Header Chain:
Below is the list of all servers (received headers) in order from origin to destination:
 
 ![image](https://github.com/user-attachments/assets/c82f02ca-c3c4-446c-bc5d-8f140651d3cf)

*Image by Phishtool*

Total hops = 4
Any anomalies? The message originated from a suspicious IP address in Germany and lacked SPF authorization. Additionally, the hostnames were spoofed or forged to resemble Outlook servers.

# Authentication Results
Email authentication results are important because they verify the legitimacy and integrity of email messages, enhancing security and improving deliverability. They help prevent phishing attacks, email spoofing, and spam, ensuring that legitimate emails reach the intended recipients and protecting both senders and recipients from malicious activity.

|      Security              | Status       | Explanation|
|---------------------------|----------------------------|------------------|
|   SPF   |Fail    |  atujpdfghher.co.uk has no SPF record, so the sender can't be verified|
|DKIM  |Fail |  The lack of a signature in the message implies the absence of DKIM protection.|
|DMARC  | Permerror| This indicates a misconfigured or absent DMARC record, allowing spoofing.|

# SPF (Sender Policy Framework)
SPF is an email authentication method that verifies if an email was sent from an authorized mail server. It checks if the sender's IP address is listed in the domain's SPF record. SPF helps prevent email spoofing by making it harder for spammers to send messages on behalf of your domain.

# DKIM (DomainKeys Identified Mail)
DKIM adds a digital signature to emails, which can be verified by the recipient's email server. This signature confirms that the email was sent by the domain owner and hasn't been altered during transit. DKIM ensures email integrity and authenticity.

# DMARC (Domain-based Message Authentication, Reporting & Conformance)
DMARC builds on SPF and DKIM. It tells the receiving email server what to do with messages that fail SPF and DKIM checks (e.g., quarantine or reject). DMARC also provides a reporting mechanism so domain owners can see who is sending emails on their behalf. DMARC helps protect against phishing and email spoofing by providing clear instructions on how to handle unauthenticated emails.

![image](https://github.com/user-attachments/assets/bbfadc0b-8d9d-44ab-b4a8-5d62c3182222)

*SPF, DKIM, DMARC checks (by phishtool)*

# Exchange Authentication Headers
|      Header              | Value       | Interpretation|
|---------------------------|----------------------------|------------------|
|   X-MS-Exchange-Organization-AuthAs |  Anonymous |  Message was unauthenticated on arrival|
| X-MS-Exchange-Organization-AuthSource | MW2NAM04FT048.eop-NAM04.prod.protection.outlook.com|  The message appeared to arrive via Outlook infrastructure, likely forged or relayed.|

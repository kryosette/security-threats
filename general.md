# The full range of cybersecurity threats: beyond vulnerabilities and attacks

In addition to vulnerabilities (weaknesses in systems) and attacks (methods of exploitation), there are many other important categories of threats and concepts in cybersecurity. Here is a comprehensive overview:

## 1. Tactics, Techniques and Procedures (TTPs)
- **Tactics**: High-level targets of intruders (intelligence, initial access, etc.)
- **Techniques**: Specific methods of achieving tactics (phishing, vulnerability exploitation)
- **Procedures**: Implementation of techniques by specific groups (for example, APT41 uses special scripts)

Example: The MITRE ATT&CK Framework classifies hundreds of TTPs in detail

## 2. Threat vectors
- **Physical**: Unauthorized access to data centers
- **Social**: Phishing, pretexting, quide proxying
- **Technical**: Exploiting software vulnerabilities
- **Environmental**: Power outages, natural disasters

##3. Threat Classes
- **Passive**: Traffic monitoring (sniffing)
- **Active**: Data modification (MITM, forgery)
- **Internal**: Insider Threats
- **External**: Remote attacks from the Internet

##4. Threats without exploiting vulnerabilities
- **Configuration errors**:
  - Open S3 buckets
  - Default credentials
- Unsecured cloud storage

- **Logical vulnerabilities**:
- Errors in the business logic of applications
- Incorrect access checks
  - Competitive access vulnerabilities (race conditions)

- **Abuse of functionality**:
- API abuse
- Unintended usage scenarios
- Excessive privileges of services

##5. Threats of the human factor
- **Social engineering**:
- Phishing (including spear-phishing and whaling)
- Baiting (planting infected media)
- Pretexting (creating false pretexts)
  
- **Staff errors**:
- Incorrect data processing
- Sending information to the wrong recipients
  - Loss of devices with data

## 6. Advanced Persistent Threats (APTs)
- **Long-term campaigns**:
- Operation Aurora (attack on Google)
- Stuxnet (industrial sabotage)
- SolarWinds (supply-chain attack)

- **APT techniques**:
- Living-off-the-land (using legitimate tools)
- Island hopping (attacking through partners)
- Watering hole (infecting visited sites)

##7. Supply Chain Threats
- **Types of attacks**:
- Dependency compromise (npm, pip packages)
  - Substitution of software updates
- Malicious hardware
  
- **Examples**:
- CodeCov attack (2021)
- Malicious event-stream package in npm
  - SolarWinds Orion compromise

## 8. Operational threats
- **Disadvantages of processes**:
- Lack of segregation of duties
  - Insufficient audit
  - Weak access control practices
  
- **Examples**:
- Unauthorized transactions
- Untraceable data changes
- Conflicts of interest

##9. Legal and regulatory risks
- **Inconsistencies**:
- GDPR, CCPA violations
- PCI DSS non-compliance
- HIPAA violations
  
- **Consequences**:
- Fines (up to 4% of global GDPR turnover)
- Loss of licenses
- Reputational damage

## 10. Emerging threats
- **Quantum Computing**:
- The threat of RSA and ECC cryptography
  - Post-quantum cryptography

- **AI threats**:
- Generation of phishing content
  - Circumvention of CAPTCHA
Attacks on ML systems

- **Metaverse risks**:
- Digital zombie avatars
  - NFT fraud
  - VR-social engineering

## 11. Threats to physical security
- **Devices**:
- Connection of malicious USB devices
- Attacks via peripheral devices
  
- **Leakage channels**:
  - Acoustic analysis (reading keystrokes by sound)
- TEMPEST (interception of electromagnetic radiation)
- Optical leaks (screen flicker analysis)

## 12. Organizational threats
- **Management risks**:
- Insufficient security budgeting
  - Incorrect risk assessment
- Conflicts between security and business objectives

- **Personnel risks**:
- Lack of qualified specialists
  - Burnout of security personnel
  - Inadequate employee training

## The complete threat model: practical application

For comprehensive protection, all these aspects must be taken into account.:

1. **Technical measures**:
- Intrusion detection Systems (IDS/IPS)
- SIEM systems
   - EDR/XDR solutions

2. **Organizational measures**:
- Security Policies
   - Awareness programs
   - Access control

3. **Physical measures**:
- Control of access to premises
   - Destruction of media
   - Protection from TEMPEST

4. **Legal measures**:
- Contracts with suppliers
- Cyber risk insurance
- Incident response plans

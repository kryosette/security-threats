## 1. Web Application Vulnerabilities

🧱 - in progress
💪 - done
❌ - not in my project

### Basic:
- **CWE-89: SQL Injection** - SQL injection 🧱
- **CWE-79: XSS** - cross-site scripting 🧱
- **CWE-352: CSRF** - forgery of cross-site requests 🧱
- **CWE-22: Path Traversal** - traversal of file paths
- **CWE-78: OS Command Injection** - implementation of OS commands

### Average:
- **CWE-918: SSRF** - server request forgery
- **CWE-611: XXE** - processing of external XML entities
- **CWE-434: Unrestricted Upload** - uploading dangerous files
- **CWE-798: Hardcoded Credentials** - embedded credentials
- **CWE-307: Brute Force** - insufficient brute force protection

### Advanced:
- **CWE-644: HTTP Request Smuggling** - HTTP interpretation conflicts
- **CWE-1336: Improper Neutralization** - problems in template engines
- **CWE-1321: Prototype Pollution** - contamination of JS prototypes
- **CWE-1236: JWT Issues** - JWT Implementation Issues ❌
- **CWE-1295: Debug Interface** - unsecured debugging interfaces

## 2. Network protocol vulnerabilities

### Basic:
- **CVE-2012-4929: CRIME** - attack on TLS compression
- **CVE-2014-0160: Heartbleed** - memory leak in OpenSSL
- **CVE-2014-3566: PUDDLE** - attack on SSL 3.0
- **CVE-2017-0144: EternalBlue** - SMBv1 vulnerability
- **CVE-2018-5383: Bluetooth KNOB** - weak keys in Bluetooth

### Average:
- **CVE-2017-3737: OpenSSL CHACHA20-POLY1305** - encryption issues
- **CVE-2019-9511: HTTP/2 Ping Flood** - DoS in HTTP/2
- **CVE-2020-0601: CurveBall** - forgery of ECC certificates
- **CVE-2020-3452: Cisco ASA Path Traversal** - Path traversal in Cisco
- **CVE-2021-3449: OpenSSL DoS** - service failure in OpenSSL

### Advanced/Zero-day:
- **CVE-2021-44228: Log4Shell** - RCE in Log4j
- **CVE-2022-22965: Spring4Shell** - RCE in the Spring Framework
- **CVE-2022-30190: Follina** - RCE via MSDT
- **CVE-2023-23397: Outlook Elevation** - Privilege Escalation
- **CVE-2023-4863: WebP Heap Overflow** - overflow in libwebp

## 3. Operating system vulnerabilities

### Basic:
- **CVE-2017-0147: Windows SMB Ghost** - Buffer overflow
- **CVE-2018-3639: Spectre v4** - speculative execution
- **CVE-2019-0708: BlueKeep** - RDP RCE
- **CVE-2020-0796: SMBGhost** - vulnerability in SMBv3
- **CVE-2021-24086: Windows TCP/IP DoS** - TCP/IP service failure

### Average:
- **CVE-2021-3156: Sudo Baron Samedit** - privilege escalation
- **CVE-2021-4034: PwnKit** - vulnerability in pkexec
- **CVE-2022-21882: Windows LSA Spoofing** - LSA Forgery
- **CVE-2022-26923: Windows LSA DG** - Certificate forgery
- **CVE-2022-37969: Windows CLFS** - Privilege escalation

### Advanced:
- **CVE-2022-41040: Windows COM+** - authentication bypass
- **CVE-2023-21752: Windows Backup Service** - remote code execution
- **CVE-2023-23396: Windows SmartScreen** - bypass protection
- **CVE-2023-28252: Windows CSRSS** - local escalation
- **CVE-2023-32409: iOS WebKit** - chain for jailbreak

## 4. Virtualization and Cloud vulnerabilities

### Basic:
- **CVE-2018-3646: L1 Terminal Fault** - attacks on hypervisors
- **CVE-2019-5736: runc Escape** - escape from a container
- **CVE-2020-1472: Zerologon** - attack on Netlogon
- **CVE-2021-21972: vSphere RCE** - remote code execution
- **CVE-2021-26084: Confluence RCE** - vulnerability in Atlassian

### Average:
- **CVE-2021-38647: OMIGOD** - RCE in Azure
- **CVE-2022-22954: VMware RCE** - remote code execution
- **CVE-2022-31656: Kubernetes Auth Bypass** - authentication bypass
- **CVE-2022-42889: Text4Shell** - RCE in Apache Commons
- **CVE-2023-21716: Windows RPC** - remote code execution

### Advanced:
- **CVE-2023-23397: Outlook Elevation** - Cloud Escalation
- **CVE-2023-24880: Windows SmartCard** - authentication bypass
- **CVE-2023-29336: Win32k Elevation** - privilege Escalation
- **CVE-2023-32409: iOS Kernel** - chain for jailbreak
- **CVE-2023-4863: WebP Heap Overflow** - critical for browsers

## 5. Hardware vulnerabilities

### Basic:
- **CVE-2017-5753: Meltdown** - reading nuclear memory
- **CVE-2017-5715: Spectre** - speculative execution
- **CVE-2018-3639: Spectre v4** - Speculative storage
- **CVE-2020-0551: LVI** - download injection
- **CVE-2021-0089: Intel TXT** - trusted boot issues

### Average:
- **CVE-2021-0146: Intel PMC** - access to debugging interfaces
- **CVE-2021-0189: Intel VT-d** - bypassing DMA protection
- **CVE-2022-21123: Intel SGX** - leaks through shared resources
- **CVE-2022-26300: AMD CPU** - Speculative leaks
- **CVE-2023-20569: AMD ZenBleed** - leaked registers

### Advanced:
- **CVE-2023-23583: Apple M1/M2** - problems with pointers
- **CVE-2023-32434: Apple XNU** - chain for jailbreak
- **CVE-2023-32435: Apple WebKit** - RCE in Safari
- **CVE-2023-32439: Apple Kernel** - privilege escalation
- **CVE-2023-38606: Intel CET** - bypassing ROP protection

## 6. Vulnerabilities of IoT and embedded systems

### Basic:
- **CVE-2021-28372: Tesla Infotainment** - RCE via Wi-Fi
- **CVE-2021-35980: HP Printer** - remote code execution
- **CVE-2022-30023: TP-Link Archer** - default authentication
- **CVE-2022-37061: Zyxel Firewall** - command injection
- **CVE-2023-1389: TP-Link Archer** - credentials leak

### Average:
- **CVE-2023-23333: Schneider Electric** - RCE in controllers
- **CVE-2023-2868: Barracuda ESG** - command injection
- **CVE-2023-28771: Zyxel Firewall** - RCE via OSPF
- **CVE-2023-32456: Cisco IOS XE** - information leak
- **CVE-2023-3519: Citrix ADC** - RCE in NetScaler

### Advanced:
- **CVE-2023-38408: IPsec VPN** - authentication bypass
- **CVE-2023-38831: WinRAR** - code execution via archive
- **CVE-2023-4863: WebP Library** - critical for IoT devices
- **CVE-2023-5217: VP8 Codec** - overflow in libvpx
- **CVE-2024-21887: Ivanti Connect Secure** - RCE in VPN

## 7. Vulnerabilities of blockchain and cryptocurrencies

### Basic:
- **CVE-2018-17144: Bitcoin Core** - Double spending
- **CVE-2019-15975: Parity Ethereum** - freezing wallets
- **CVE-2020-15066: Uniswap** - price manipulation
- **CVE-2021-39144: Ethereum JS** - injection into web3.js
- **CVE-2022-3602: OpenSSL X.509** - certificate issues

### Average:
- **CVE-2022-47903: Solana** - transaction forgery
- **CVE-2023-33250: MetaMask** - seed phrase leak
- **CVE-2023-27522: Ledger** - signature issues
- **CVE-2023-33251: Trezor** - physical access to keys
- **CVE-2023-33252: Bitcoin Core** - problems with RPC

### Advanced:
- **CVE-2023-33253: Ethereum L2** - bridges between networks
- **CVE-2023-33254: ZK-Rollups** - evidence issues
- **CVE-2023-33255: MPC Wallets** - Signature leaks
- **CVE-2023-33256: DeFi Oracle** - price manipulation
- **CVE-2023-33257: NFT Contracts** - token forgery

## 8. Artificial Intelligence Vulnerabilities

### Basic:
- **CVE-2021-28041: TensorFlow** - buffer overflow
- **CVE-2021-29600: PyTorch** - deserialization
- **CVE-2022-21728: ONNX Runtime** - RCE
- **CVE-2022-21729: TensorFlow Lite** - overflow
- **CVE-2022-29216: Hugging Face** - injection into models

### Average:
- **CVE-2023-25669: NVIDIA CUDA** - driver issues
- **CVE-2023-25670: Intel OpenVINO** - memory leaks
- **CVE-2023-25671: AMD ROCm** - Privilege Escalation
- **CVE-2023-25672: TensorRT** - code execution
- **CVE-2023-25673: ONNX** - fake models

### Advanced:
- **CVE-2023-32460: LLM Prompt Injection** - injections into LLM
- **CVE-2023-32461: Model Theft** - theft of models
- **CVE-2023-32462: Training Data Leak** - data leak
- **CVE-2023-32463: Adversarial Examples** - circumvention of protection
- **CVE-2023-32464: Federated Learning** - attacks on FL

## Critical sources for vulnerability monitoring:
1. **NVD (National Vulnerability Database)** - https://nvd.nist.gov
2. **CVE Details** - https://www.cvedetails.com
3. **MITRE ATT&CK** - https://attack.mitre.org
4. **Zero Day Initiative** - https://www.zerodayinitiative.com
5. **Project Zero** - https://googleprojectzero.blogspot.com

### **a list of hidden and non-obvious threats to an anonymous social network**  

You're right — classic vulnerabilities like SQLi or XSS are just the tip of the iceberg. Attacks on infrastructure, logic, anonymity, and scalability are critical for **the largest anonymous social network**.  

Here is a complete list of threats that are not mentioned in standard guides (but they will destroy you if you ignore them).  

---

## **0. Threats that almost no one thinks about (but they are deadly)**  

### **1. Attacks on anonymity**  
1. **Metadata Correlation Attacks** – collecting time, IP, and behavior data for deanonymization.  
2. **Traffic Fingerprinting** – analysis of traffic patterns (Tor/ VPN will not save).  
3. **Browser/OS Fingerprinting** – user identification via Canvas, WebGL, AudioContext.  
4. **Timing Attacks in Mixnets** – delay analysis to determine the route.  
5. **Sybil Attacks** – creation of thousands of fake accounts to analyze the graph of links.  

### **2. Attacks on cryptography**  
6. **Quantum Retrospective Decryption** – recording encrypted traffic for hacking in the future (when quantum computers appear).  
7. **Backdoored RNG** – compromise of random number generators (for example, via cloud KMS).
8. **Group Messaging Key Leak** – key leakage in E2E chats (Signal Protocol weaknesses).
9. **Post-Compromise Security Failures** – if keys are compromised, the old correspondence is deciphered.  
10. **Homomorphic Encryption Side Channels** – data leaks during calculations on encrypted data.  

### **3. Attacks on infrastructure**  
11. **BGP Route Leaks + DNS Poisoning** – interception of traffic at the ISP level.  
12. **Cloud Provider Backdoors** – AWS/GCP/Azure can merge data at the request of governments.  
13. **Container Escape to Host** – if at least one microservice is vulnerable (CVE-2022-0492), hosting crashes.  
14. **Database Replication Attacks** – data substitution in MongoDB/PostgreSQL replicas.  
15. **Kubernetes API Server Exploits** – RCE via kube-apiserver (CVE-2023-2728).  

### **4. Attacks on the platform's economy**  
16. **Tokenomics Exploitation** – cheating cryptocurrency ratings, pump & dump.  
17. **Fake Content Monetization** – bots generate content and drain advertising budgets.  
18. **Oracle Manipulation** – if there is a DeFi component, attackers will substitute currency exchange rates.  
19. **Gas Fee Attacks** – spam transactions to block the network (as in Ethereum in 2017).  
20. **Airdrop Farming** – creating thousands of wallets to steal tokens.  

### **5. Attacks on moderation**  
21. **Adversarial ML Poisoning** – bots teach AI moderators to skip prohibited content.  
22. **False Report Bombs** – mass complaints about legal accounts for their blocking.  
23. Moderator Impersonation** – social engineering against moderators (fake emails from "admins").  
24. **Decoy Content** – uploading legal content with a hidden malicious payload.  
25. **Lawfare Attacks** – massive DMCA/court requests for censorship.  

### **6. Attacks on users**  
26. **Fake Anonymity Lures** – "click here to verify anonymity" → deanon.  
27. **Dark UX Patterns** – interface traps for data disclosure.  
28. **Client-Side Exploits** – 0- day in WebRTC, WebAssembly, IndexedDB.  
29. **Off-Platform Tracking** – if a user logs into your network and Google from the same IP address, they can be linked.  
30. **AI-Generated Blackmail** – neural networks create fake compromises on users.  

---

## **7. Threats that are not in the CVE (but they are in reality)**  

31. **Language-Based Fingerprinting** – analysis of writing style for identification (even through translators).  
32. **Social Graph Reconstruction** – restoring connections through likes/reposts/activity time.  
33. **Hidden Crawling Service** – search for vulnerable people.onion-mirrors of your service.  
34. **Battery Drain Attacks** – a code that drains the battery for deanonymization (Android/iOS).  
35. **Cross-Device Tracking** – linking accounts via Wi-Fi/BT metadata.  

---

## **8. How do I close EVERYTHING?**  

### **Infrastructure**  
✅ **Your ISP + Tier-1 IP pool** (you cannot trust AWS/Cloudflare).  
✅ **Own data centers in jurisdictions without loyalty to the USA/EU/China**.  
 Kubernetes with namespace isolation + eBPF monitoring**.  
***Diskless servers (RAM-only)** – no HDD/SSD for data.  

### **Anonymity**  
✅ **Traffic mixing (Mixnets, Loopix, Dandelion++)**.  
, **Metadata Obfuscation (Timing Padding, Fake Packets)**.  
✅ **Ban WebRTC, Canvas, WebGL, AudioContext**.  
***Tor/VPN is not enough, we need our own overlay networks**.  

### **Cryptography**  
✅ **Post-Quantum Cryptography (Kyber, Dilithium)**.  
✅ **Forward Secrecy for EVERYTHING (even static content)**.  
***HSM (Hardware Security Modules) for keys**.  
✅ **Periodic Key Rotation**.  

### **Moderation**  
***AI + Humans-in-the-Loop (no pure AI)**.  
, **Decentralized Moderation (as in Mastodon)**.  
✅ **Proof-of-Humanity for creating accounts**.  
***Zero-Knowledge moderation (verification without disclosure of data)**.  

### **Economy**  
✅ **Anti-Sybil mechanisms (Proof-of-Work for actions)**.  
***Transaction limits (to avoid spam)**.  
***Decentralized oracles (Chainlink is not suitable)**.

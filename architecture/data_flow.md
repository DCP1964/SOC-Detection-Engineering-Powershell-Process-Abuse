# Data Flow Architecture

## Overview

This project uses a centralized logging architecture to collect, forward, and analyze endpoint telemetry for PowerShell attack detection. The architecture is designed to simulate a real-world Security Operations Center (SOC) environment.

---

## Architecture Components

### 1. Windows 10 Endpoint

The Windows 10 virtual machine acts as the monitored endpoint where telemetry is generated.

Configured components:

- Sysmon with SwiftOnSecurity configuration
- PowerShell Script Block Logging enabled
- Windows Event Logging

---

### 2. Sysmon (System Monitor)

Sysmon provides enhanced visibility into system activity beyond default Windows logging.

Key events collected:

- Event ID 1: Process Creation
- Event ID 3: Network Connections
- Event ID 13: Registry Modifications
- Event ID 22: DNS Queries

Purpose:

- Capture detailed process execution data
- Track network activity initiated by PowerShell
- Detect persistence mechanisms via registry changes

---

### 3. PowerShell Logging

PowerShell Script Block Logging (Event ID 4104) is enabled via Group Policy.

Purpose:

- Capture full PowerShell command execution
- Detect encoded and obfuscated commands
- Provide visibility into attacker techniques

---

### 4. Splunk Universal Forwarder

Installed on the Windows endpoint to collect and forward logs to the Splunk server.

Configured inputs:

- Sysmon Operational Logs
- PowerShell Operational Logs
- Windows Security Logs
- System Logs

Purpose:

- Lightweight log forwarding
- Near real-time data transmission to SIEM

---

### 5. Splunk Enterprise (Ubuntu Server)

Splunk is deployed on an Ubuntu virtual machine and acts as the central SIEM.

Responsibilities:

- Log ingestion and indexing
- Search and correlation
- Detection rule execution
- Data enrichment and analysis

---

## Data Flow

1. PowerShell and system activities occur on the Windows endpoint  
2. Sysmon and PowerShell logging generate event data  
3. Logs are written to Windows Event Logs  
4. Splunk Universal Forwarder collects these logs  
5. Logs are forwarded to Splunk Enterprise  
6. Splunk indexes the data in `index=main`  
7. Detection queries analyze the data for suspicious behavior  

---

## Data Sources Summary

| Source | Log Type | Purpose |
|------|--------|--------|
| Sysmon | Process Creation (Event ID 1) | Detect PowerShell execution |
| Sysmon | Network Connections (Event ID 3) | Detect external communication |
| Sysmon | Registry Events (Event ID 13) | Detect persistence |
| Sysmon | DNS Queries (Event ID 22) | Detect suspicious domains |
| PowerShell | Script Block Logging (4104) | Detect encoded/obfuscated commands |
| Windows Security | Authentication Events | Support correlation logic |

---

## Design Considerations

- Avoid use of broad searches such as `index=*`
- Use high-fidelity telemetry (Sysmon + PowerShell logs)
- Ensure proper log ingestion before detection development
- Enable detailed logging to support behavioral detection

---

## Limitations

- Single endpoint simulation (not enterprise-scale)
- No centralized log management beyond Splunk instance
- Threat intelligence is simulated using static datasets
- Detection accuracy depends on logging completeness

---

## Future Improvements

- Multi-endpoint architecture for lateral movement detection
- Integration with Active Directory logs
- Automated threat intelligence ingestion via APIs
- Integration with SOAR for automated response
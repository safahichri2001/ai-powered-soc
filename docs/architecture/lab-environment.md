# Security Lab Environment

## 1. Host Machine

- OS: Windows 11
- CPU: Intel Core i7-13620H
- RAM: 32 GB
- GPU: NVIDIA RTX 2050 4 GB
- Hypervisor: VMware Workstation 17 Pro

## 2. Virtual Machines

### 2.1 SOC-Ubuntu

- OS: Ubuntu Server 24.04 LTS
- RAM: 8 GB
- CPU: 4 vCPU
- Disk: 50 GB
- Network 1: VMnet8 (NAT)
- Network 2: VMnet3 (Host-only)
- Lab IP: `10.0.0.10`
- Role: SOC server

### 2.2 Kali Linux

- OS: Kali Linux
- Lab IP: `10.0.0.20`
- Network: VMnet3 (Host-only)
- Role: Security testing and monitored endpoint
- Wazuh Agent: `4.14.7`
- Wazuh Manager: `10.0.0.10`
- Agent communication: TCP `1514`
- Agent enrollment: TCP `1515`

## 3. Network Architecture

- VMnet8: Internet/NAT
- VMnet3: Isolated cybersecurity laboratory network
- SOC-Ubuntu: `10.0.0.10`
- Kali Linux: `10.0.0.20`

```text
                    Windows Host
                         |
                 VMware Workstation
                         |
              ┌──────────┴──────────┐
              │                     │
         VMnet8 (NAT)        VMnet3 (Host-only)
         Internet            10.0.0.0/24
                                   |
                         ┌─────────┴─────────┐
                         │                   │
                    SOC-Ubuntu           Kali Linux
                    10.0.0.10            10.0.0.20
                         │                   │
                  ┌──────┼──────┐            │
                  │      │      │            │
                Wazuh  Indexer Dashboard   Agent
                Manager  :9200   :443      :1514
                  :1514
```

## 4. Current SOC Components

The SOC-Ubuntu server currently hosts:

- Wazuh Manager
- Wazuh Indexer
- Wazuh Dashboard

The Kali Linux virtual machine is registered as a Wazuh agent.

Current agent status:

```text
ID: 001
Name: Kali
IP: any
Status: Active
```

The Wazuh agent successfully authenticates with the Wazuh Manager and communicates over the isolated laboratory network.

## 5. Wazuh Services

The following Wazuh services have been successfully deployed and verified on SOC-Ubuntu:

- Wazuh Manager
- Wazuh Indexer
- Wazuh Dashboard

Current service state:

```text
wazuh-indexer    active (running)
wazuh-manager    active (running)
wazuh-dashboard  active (running)
```

## 6. Wazuh Agent Deployment

The Wazuh Agent `4.14.7` has been successfully installed on the Kali Linux virtual machine.

The agent was enrolled with the Wazuh Manager using:

```text
Manager IP: 10.0.0.10
Agent name: Kali
```

The enrollment was successful and a valid authentication key was received from the Wazuh Manager.

The agent service is configured to start automatically and is currently running:

```text
wazuh-agent: active (running)
```

## 7. Agent Communication

The Wazuh Agent communicates with the Wazuh Manager through the isolated laboratory network.

```text
Kali Linux
10.0.0.20
    |
    | TCP 1514
    v
SOC-Ubuntu
10.0.0.10
    |
    +-- Wazuh Manager
```

Agent enrollment is performed through TCP port `1515`.

Connectivity tests confirmed:

```text
TCP 1514: open
TCP 1515: open
```

## 8. Monitoring Capabilities

The Kali agent currently has the following Wazuh modules active:

- File Integrity Monitoring (FIM / Syscheck)
- Security Configuration Assessment (SCA)
- System inventory / Syscollector
- Log collection
- Rootcheck

## 9. File Integrity Monitoring

FIM is enabled on the Kali Linux agent.

Current configuration:

```text
<syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
</syscheck>
```

The following directories are monitored:

```text
/etc
/usr/bin
/usr/sbin
/bin
/sbin
/boot
```

The agent successfully performed FIM scans.

Example validation from the Wazuh agent logs:

```
wazuh-syscheckd: INFO: File integrity monitoring scan started.
wazuh-syscheckd: INFO: File integrity monitoring scan ended.
```

## 10. Security Configuration Assessment

Security Configuration Assessment (SCA) is enabled on the Kali Linux agent.

The agent successfully performed SCA evaluations.

Example:

```
sca: INFO: Starting Security Configuration Assessment scan.
sca: INFO: Starting evaluation of policy: '/var/ossec/ruleset/sca/sca_distro_independent_linux.yml'
sca: INFO: Evaluation finished for policy: '/var/ossec/ruleset/sca/sca_distro_independent_linux.yml'
sca: INFO: Security Configuration Assessment scan finished.
```

## 11. System Inventory

The Wazuh Syscollector module is active on the Kali Linux agent.

The module successfully started its system evaluation:

```
wazuh-modulesd:syscollector: INFO: Module started.
wazuh-modulesd:syscollector: INFO: Starting evaluation.
wazuh-modulesd:syscollector: INFO: Evaluation finished.
```

## 12. Log Collection

The Wazuh Logcollector module is active on the Kali Linux agent.

The agent successfully monitors system journal entries:

```
wazuh-logcollector: INFO: Monitoring journal entries.
```

This allows the Wazuh Manager to receive and analyze authentication and system activity from the monitored endpoint.

## 13. Rootcheck

The Rootcheck module is active on the Kali Linux agent.

A rootcheck scan was successfully executed:

```
rootcheck: INFO: Starting rootcheck scan.
rootcheck: INFO: Ending rootcheck scan.
```

## 14. Wazuh Alert Generation

The Wazuh Manager successfully generated security alerts from system activity.

Validated events include:

- SSH authentication
- PAM login session creation
- Successful sudo execution

Example alert:

```
Rule: 5501 (level 3)
PAM: Login session opened.
```

Another validated event:

```
Rule: 5402 (level 3)
Successful sudo to ROOT executed.
```

These alerts confirm that the Wazuh Manager is successfully receiving and analyzing security events.

## 15. Agent Status

The Wazuh Manager currently recognizes the Kali Linux agent:

```
Wazuh agent_control

ID: 000
Name: soc-ubuntu
IP: 127.0.0.1
Status: Active/Local

ID: 001
Name: Kali
IP: any
Status: Active
```

Therefore, the Kali endpoint is successfully enrolled and connected to the Wazuh Manager.

## 16. Network Validation

The laboratory network has been successfully validated.

### Kali → SOC-Ubuntu

```
Source:      10.0.0.20
Destination: 10.0.0.10
Network:     VMnet3
```

Connectivity to the Wazuh Manager was successfully established.

### Internet Connectivity

The Kali Linux VM uses VMnet8 for Internet/NAT connectivity.

The following tests were successfully performed:

```
Ping gateway:    successful
Ping 8.8.8.8:    successful
DNS resolution:  successful
HTTPS access:    successful
```

The Kali VM can therefore access external resources through VMnet8 while communicating with the SOC server through VMnet3.

## 17. Current SOC Architecture

```
                           Windows 11 Host
                                 |
                         VMware Workstation
                                 |
                    +------------+------------+
                    |                         |
                 VMnet8                    VMnet3
                  NAT                   Host-only Network
                Internet                  10.0.0.0/24
                                             |
                              +--------------+--------------+
                              |                             |
                         SOC-Ubuntu                     Kali Linux
                         10.0.0.10                     10.0.0.20
                              |                             |
                    +---------+---------+                   |
                    |         |         |                   |
                 Wazuh     Wazuh     Wazuh              Wazuh
                 Manager   Indexer   Dashboard            Agent
                 :1514      :9200      :443
                              |
                              |
                         Security Alerts
                              ^
                              |
                         Monitored Events
                              |
                           Kali Linux
```

## 18. Current Project Status

The initial SOC laboratory infrastructure is operational.

Completed milestones:

- [x] VMware laboratory network configured
- [x] SOC-Ubuntu deployed
- [x] Kali Linux deployed
- [x] VMnet8 NAT connectivity configured
- [x] VMnet3 isolated laboratory network configured
- [x] Wazuh Manager installed
- [x] Wazuh Indexer installed
- [x] Wazuh Dashboard installed
- [x] Wazuh services verified
- [x] Wazuh Agent installed on Kali Linux
- [x] Kali agent enrolled with Wazuh Manager
- [x] TCP 1514 communication validated
- [x] TCP 1515 enrollment validated
- [x] FIM validated
- [x] SCA validated
- [x] Syscollector validated
- [x] Log collection validated
- [x] Rootcheck validated
- [x] Security alerts validated

## 19. Next Steps

The following components are planned for the next stages of development:

1. Zeek network monitoring
2. Security event collection and normalization
3. Machine Learning pipeline
4. RAG knowledge base
5. AI-powered SOC agent
6. Automated security alert analysis
7. SOC dashboard integration
8. Evaluation of the AI-powered SOC architecture

## 20. Project Objective

The final objective is to develop an AI-powered Security Operations Center capable of:

- Collecting security events
- Monitoring endpoints and network activity
- Detecting suspicious behavior
- Enriching security alerts using a RAG knowledge base
- Reasoning over security events using an AI agent
- Assisting analysts in security investigation
- Supporting automated alert analysis and response

The current Wazuh-based laboratory provides the foundational security monitoring infrastructure required for the implementation of these components.
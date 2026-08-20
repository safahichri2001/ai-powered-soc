# Security Lab Environment

## Host Machine

- OS: Windows 11
- CPU: Intel Core i7-13620H
- RAM: 32 GB
- GPU: NVIDIA RTX 2050 4 GB
- Hypervisor: VMware Workstation 17 Pro

## Virtual Machines

### SOC-Ubuntu

- OS: Ubuntu Server 24.04 LTS
- RAM: 8 GB
- CPU: 4 vCPU
- Disk: 50 GB
- Network 1: VMnet8 (NAT)
- Network 2: VMnet3 (Host-only)
- Lab IP: `10.0.0.10`

## Network Architecture

- VMnet8: Internet/NAT
- VMnet3: Isolated cybersecurity laboratory network

## Purpose

The Ubuntu server will host the main SOC components, including:

- Wazuh SIEM
- Zeek network monitoring
- Machine Learning pipeline
- RAG system
- AI agent
- SOC dashboard
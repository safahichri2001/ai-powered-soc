# AI-Powered SOC

AI-powered Security Operations Center for security monitoring, alert analysis, knowledge retrieval, and intelligent investigation.

## Project Overview

This project aims to develop an AI-powered Security Operations Center combining:

* Cybersecurity monitoring
* Security event normalization
* Retrieval-Augmented Generation (RAG)
* Machine Learning
* Agentic AI
* Automated alert analysis
* Incident investigation assistance

The system is developed and evaluated in a controlled virtualized cybersecurity laboratory.

## Current Architecture

```text
                         Windows 11 Host
                              |
                     VMware Workstation
                              |
              +---------------+---------------+
              |                               |
         VMnet8 (NAT)                    VMnet3
          Internet                  10.0.0.0/24
                                              |
                              +---------------+---------------+
                              |                               |
                         SOC-Ubuntu                       Kali Linux
                         10.0.0.10                       10.0.0.20
                              |                               |
                    +---------+---------+                     |
                    |         |         |                     |
                  Wazuh     Indexer   Dashboard           Wazuh Agent
                 Manager     :9200      :443                 |
                    |                                      |
                    +--------------- Alerts ---------------+
```

## Laboratory Environment

### Host Machine

* OS: Windows 11
* CPU: Intel Core i7-13620H
* RAM: 32 GB
* GPU: NVIDIA RTX 2050 4 GB
* Hypervisor: VMware Workstation 17 Pro

### SOC-Ubuntu

* OS: Ubuntu Server 24.04 LTS
* RAM: 8 GB
* CPU: 4 vCPU
* Disk: 50 GB
* Lab IP: `10.0.0.10`
* Role: SOC server

### Kali Linux

* OS: Kali Linux
* Lab IP: `10.0.0.20`
* Role: Security testing and monitored endpoint
* Wazuh Agent: `4.14.7`

## Implemented Components

### Wazuh SOC Infrastructure

The following Wazuh components are currently deployed and operational:

* Wazuh Manager
* Wazuh Indexer
* Wazuh Dashboard
* Wazuh Agent on Kali Linux

The Kali endpoint is successfully enrolled in the Wazuh Manager and is currently active.

### Security Monitoring

The Kali agent currently supports:

* File Integrity Monitoring (FIM / Syscheck)
* Security Configuration Assessment (SCA)
* System inventory / Syscollector
* Log collection
* Rootcheck

The Wazuh Manager successfully generates security alerts from monitored activity, including authentication and sudo-related events.

## AI Data Processing Layer

A normalized internal representation of security alerts has been implemented to decouple the AI pipeline from the native Wazuh JSON format.

### Security Alert Model

Implemented in:

```text
agent/models/security_alert.py
```

The `SecurityAlert` model represents normalized security events using Pydantic.

### Alert Normalization

Implemented in:

```text
agent/preprocessing/normalizer.py
```

The normalizer converts raw Wazuh alerts into the internal `SecurityAlert` representation.

### AI Alert Formatting

Implemented in:

```text
agent/preprocessing/formatter.py
```

The formatter converts normalized security alerts into a structured textual representation suitable for future AI processing and retrieval.

## RAG Pipeline

The first stage of the RAG pipeline is currently implemented.

### Knowledge Base

Security knowledge documents are stored in:

```text
rag/knowledge/documents/
```

Current documents include:

* `ssh.md`
* `sudo.md`
* `wazuh_alerts.md`

These documents provide security context for interpreting authentication, privilege, and Wazuh-related events.

### Document Ingestion

Implemented in:

```text
rag/ingestion/loader.py
```

The loader reads Markdown knowledge documents and converts them into structured `KnowledgeDocument` objects.

### Document Chunking

Implemented in:

```text
rag/ingestion/chunker.py
```

The chunker splits knowledge documents into smaller `DocumentChunk` objects that can later be embedded and indexed.

## Current Development Status

### Completed

* [x] Project repository initialized
* [x] Virtualized cybersecurity laboratory configured
* [x] SOC-Ubuntu deployed
* [x] Kali Linux deployed
* [x] VMnet8 NAT connectivity configured
* [x] VMnet3 isolated laboratory network configured
* [x] Wazuh Manager deployed
* [x] Wazuh Indexer deployed
* [x] Wazuh Dashboard deployed
* [x] Wazuh Agent installed on Kali
* [x] Kali agent enrolled and active
* [x] Security monitoring validated
* [x] Security alerts validated
* [x] SecurityAlert data model implemented
* [x] Wazuh alert normalization implemented
* [x] AI alert formatting implemented
* [x] RAG knowledge base initialized
* [x] Knowledge document loader implemented
* [x] Document chunking implemented
* [x] Unit tests implemented for the current components

### In Progress

* [ ] Embedding generation
* [ ] Vector database integration
* [ ] Semantic retrieval
* [ ] Complete RAG pipeline
* [ ] LLM integration
* [ ] AI SOC analyst
* [ ] Agentic workflow
* [ ] Alert investigation and reasoning
* [ ] Wazuh API integration
* [ ] Security event correlation
* [ ] Machine Learning pipeline
* [ ] Evaluation framework
* [ ] SOC dashboard integration

## Planned AI Architecture

```text
Wazuh / Zeek
      |
      v
Security Event Ingestion
      |
      v
Normalization
      |
      v
SecurityAlert
      |
      +----------------------+
      |                      |
      v                      v
Machine Learning             RAG
                              |
                       Knowledge Base
                              |
                       Embeddings
                              |
                       Vector Database
                              |
                         Retrieval
                              |
                              v
                           LLM
                              |
                              v
                        AI SOC Analyst
                              |
                       Investigation
                              |
                       Recommendation
```

## RAG Roadmap

The RAG implementation is being developed progressively:

```text
Knowledge Documents        [DONE]
        |
        v
Document Loading           [DONE]
        |
        v
Document Chunking          [DONE]
        |
        v
Embeddings                 [TODO]
        |
        v
Vector Database            [TODO]
        |
        v
Semantic Retrieval         [TODO]
        |
        v
Context Construction       [TODO]
        |
        v
LLM Integration            [TODO]
```

## AI Agent Roadmap

The future agentic layer will use retrieved security knowledge and structured security alerts to assist with:

* Alert interpretation
* Context enrichment
* Incident investigation
* Attack hypothesis generation
* Security reasoning
* Recommended response actions

The agentic workflow will be implemented after the core RAG pipeline is validated.

## Technologies

### Current

* Python
* Pydantic
* Pytest
* Wazuh
* VMware Workstation

### Planned

* LangGraph
* LangChain
* Ollama
* Qdrant
* Hugging Face
* Scikit-learn
* PyTorch
* FastAPI
* Docker

## Project Structure

```text
ai-powered-soc/
|
├── agent/
│   ├── graph/
│   ├── models/
│   │   └── security_alert.py
│   ├── preprocessing/
│   │   ├── formatter.py
│   │   └── normalizer.py
│   ├── prompts/
│   └── tools/
|
├── api/
|
├── configs/
|
├── dashboard/
|
├── data/
│   ├── processed/
│   └── raw/
|
├── docker/
|
├── docs/
│   ├── architecture/
│   │   └── lab-environment.md
│   └── screenshots/
|
├── ml/
│   ├── evaluation/
│   ├── models/
│   ├── preprocessing/
│   └── training/
|
├── notebooks/
|
├── rag/
│   ├── embeddings/
│   │   └── embedder.py
│   ├── ingestion/
│   │   ├── chunker.py
│   │   └── loader.py
│   ├── knowledge/
│   │   └── documents/
│   │       ├── ssh.md
│   │       ├── sudo.md
│   │       └── wazuh_alerts.md
│   └── retrieval/
│       └── retriever.py
|
├── tests/
│   ├── test_alert_formatter.py
│   ├── test_alert_normalizer.py
│   ├── test_chunker.py
│   └── test_knowledge_loader.py
|
├── .env.example
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
└──
```

## Testing

The project currently includes unit tests for:

* Security alert normalization
* AI alert formatting
* Knowledge document loading
* Document chunking

Run the tests with:

```powershell
python -m pytest -q
```

## Security Considerations

The project is developed in a controlled laboratory environment.

Sensitive information must never be committed to the repository, including:

* Passwords
* API tokens
* API keys
* Private keys
* Wazuh agent authentication keys
* `.env` files containing secrets
* Raw sensitive logs

Local secrets should be stored outside version control.

## Project Objective

The final objective is to build an AI-powered SOC capable of combining:

1. Real-time security monitoring
2. Security event normalization
3. Machine Learning
4. Security knowledge retrieval
5. RAG-based contextual enrichment
6. Agentic reasoning
7. Automated alert investigation
8. Analyst assistance
9. Security event correlation
10. Explainable recommendations

The current implementation provides the operational SOC foundation and the initial AI/RAG data-processing layer required for the next development stages.

# 🤖 Agentic AI SOC Analyst

> **Python | LLM API | Security Automation | Guardrails | Prompt Engineering**

---

## 📌 Overview

This project implements a modular **Agentic AI SOC Analyst** built using Python and OpenAI's API.

The agent simulates a Tier 1 SOC workflow and explores how AI-driven systems can:

- 🔎 Interpret investigation prompts  
- 📂 Search structured log datasets  
- 🧠 Perform simulated threat hunting  
- ⚙️ Apply reasoning workflows  
- 📄 Generate structured SOC-style reports  
- 🛡 Operate within guardrails to prevent unsafe behavior  

---

## 🧠 Core Concepts Explored

| Area | Focus |
|------|-------|
| AI Architecture | Agent workflow orchestration |
| Prompt Engineering | Structured LLM control |
| Guardrails | Output validation & safety constraints |
| SOC Modeling | Detection logic simulation |
| Automation | Python modular design |

---

## 🏗️ High-Level Architecture

---

## 📂 Project Structure

```bash
Agentic-AI-SOC-Analyst/
├── prompt_engineering/
│   ├── PROMPT_MANAGEMENT.py
│   ├── MODEL_MANAGEMENT.py
│   ├── EXECUTOR.py
│   ├── UTILITIES.py
│   └── __main__.py
├── guardrails/
│   ├── GUARDRAILS.py
│   ├── PROMPT_MANAGEMENT.py
│   ├── EXECUTOR.py
│   ├── MODEL_MANAGEMENT.py
│   ├── UTILITIES.py
│   └── threats.jsonl
├── requirements.txt
├── .gitignore
└── README.md
```
---
## 🛡️ Guardrails Layer

- The Guardrails module enforces:

- Output format validation

- Threat classification boundaries

- Controlled decision-making

- Mitigation recommendation structure

- Prompt injection resistance

This models how production AI security systems must be constrained to avoid hallucination or unsafe actions.

---

## 🎯 Skills Demonstrated

- AI agent design

- LLM prompt structuring

- Security workflow orchestration

- Guardrail implementation

- Modular Python engineering

- Threat modeling logic

- SOC simulation

- Purple Team automation thinking

---

## 🚀 Future Enhancements

- Real EDR log ingestion (Defender/CrowdStrike APIs)

- MITRE ATT&CK auto-mapping

- IOC enrichment APIs

- Multi-agent orchestration (Hunter + Responder)

- Persistent memory system

- Red team simulation harness

⚠️ Security Note

API keys are stored using environment variables and are not included in this repository.

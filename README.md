# 🤖 Agentic AI SOC Analyst  
> **Python | LLM API | Azure Log Analytics | Security Automation | Guardrails**

---

## 📌 Overview

This project implements a modular **Agentic AI SOC Analyst** built in Python using:

- OpenAI’s LLM API  
- Azure Log Analytics  
- Structured prompt engineering  
- Guardrail enforcement logic  

The system simulates a Tier 1 SOC investigation workflow by:

- Interpreting investigation prompts  
- Querying structured log data (Azure Log Analytics)  
- Performing threat evaluation  
- Applying constrained AI reasoning  
- Generating structured SOC-style reports  
- Enforcing guardrails to prevent unsafe output  

This project explores how AI agents can support modern SOC operations while maintaining deterministic and secure behavior.

---

## 🧠 Core Concepts Explored

| Domain | Implementation |
|--------|---------------|
| AI Agent Architecture | Modular workflow orchestration |
| Prompt Engineering | Structured SOC report generation |
| Guardrails | Output validation & boundary enforcement |
| Log Analytics | Azure Monitor Query integration |
| Security Automation | Python-based orchestration |

---

## 🏗️ High-Level Architecture

```text
User Prompt
      ↓
Prompt Engineering Layer
      ↓
Azure Log Query
      ↓
Threat Evaluation Logic
      ↓
Guardrails Enforcement
      ↓
LLM Reasoning
      ↓
Structured SOC Report
```

The system separates:

- Prompt control  
- Execution logic  
- Model interaction  
- Guardrail enforcement  
- Utility functions  

This modularity supports future expansion into multi-agent or production-grade automation systems.

---

## 📂 Project Structure

```bash
Agentic_Soc_AI/
├── README.md
├── requirements.txt
├── .gitignore
├── .env.example
├── prompt_engineering/
│   ├── README.md
│   ├── __main__.py
│   ├── EXECUTOR.py
│   ├── MODEL_MANAGEMENT.py
│   ├── PROMPT_MANAGEMENT.py
│   ├── UTILITIES.py
│   └── config.py
└── guardrails/
    ├── README.md
    ├── __main__.py
    ├── EXECUTOR.py
    ├── MODEL_MANAGEMENT.py
    ├── PROMPT_MANAGEMENT.py
    ├── GUARDRAILS.py
    ├── UTILITIES.py
    ├── config.py
    └── threats.jsonl
```

---

## 🛡️ Guardrails Layer

The Guardrails module enforces:

- Structured SOC report formatting  
- Threat classification boundaries  
- Controlled mitigation recommendations  
- Deterministic output structure  
- Basic prompt manipulation resistance  

This models how AI systems must be constrained in real-world security operations to avoid hallucination or unsafe automation.

---

## ⚙️ How to Run

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/nigeltho12/Agentic_Soc_AI.git
cd Agentic_Soc_AI
```

---

### 2️⃣ Create a Virtual Environment (Recommended)

```bash
python -m venv venv
source venv/bin/activate   # macOS/Linux
venv\Scripts\activate      # Windows
```

---

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 4️⃣ Configure Environment Variables

Copy the example file:

```bash
cp .env.example .env
```

Then edit `.env` and add your values:

```
OPENAI_API_KEY=your_openai_key_here
LOG_ANALYTICS_WORKSPACE_ID=your_workspace_id_here
```

---

### 5️⃣ Run a Module

Run the prompt engineering module:

```bash
python -m prompt_engineering
```

Run the guardrails module:

```bash
python -m guardrails
```

---

## 🔐 Security Note

- API keys are stored in environment variables.
- `.env` is excluded via `.gitignore`.
- No secrets are committed to this repository.

---

## 🎯 Skills Demonstrated

- AI agent architecture design  
- LLM prompt engineering  
- Guardrail enforcement patterns  
- Azure Log Analytics integration  
- Security workflow orchestration  
- Threat modeling logic  
- Modular Python system design  
- Purple team automation mindset  

---

## 🚀 Future Enhancements

- MITRE ATT&CK auto-tagging  
- IOC enrichment APIs  
- Multi-agent orchestration (Hunter + Responder)  
- Severity scoring normalization  
- Persistent investigation memory  
- Red team simulation harness  
- Detection engineering rule export  

---

## 👤 Author

Nigel Thompson  
Security Engineer (Purple Team Focus)  
Aspiring Red Team Operator / Security Researcher  

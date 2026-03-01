# 🧠 Prompt Engineering Module

> Structured LLM Control for SOC Workflow Simulation

---

## 📌 Purpose

This module focuses on **prompt design** and **output structure** for an AI-assisted SOC workflow.

It explores how to:

- Control model behavior
- Reduce hallucination risk
- Enforce SOC-style reporting formats
- Keep responses deterministic and scannable

---

## 🧩 What's Here

- `PROMPT_MANAGEMENT.py` — system prompts + formatting templates  
- `MODEL_MANAGEMENT.py` — LLM client + request construction  
- `EXECUTOR.py` — orchestration of the workflow  
- `UTILITIES.py` — helper functions  
- `GUARDRAILS.py` — basic constraints/validation
- `threats.jsonl` — reference dataset used by the workflow  
- `config.py` — loads secrets from environment

---

## ▶️ Run

```bash
python prompt_engineering/__main__.py
```

---

## 🔐 Notes

- Configure secrets using `.env` at repo root.
- See `.env.example` for the required variables.

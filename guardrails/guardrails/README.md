# 🛡 Guardrails Module

> Constrained AI Decision Enforcement for Security Automation

---

## 📌 Purpose

This module focuses on **guardrails** for AI outputs in a security context.

It explores patterns used to:

- Enforce output structure
- Bound threat classification
- Reduce unsafe recommendations
- Mitigate prompt injection attempts
- Keep SOC outputs consistent

---

## 🧩 What's Here

- `GUARDRAILS.py` — enforcement/validation logic  
- `PROMPT_MANAGEMENT.py` — controlled prompt templates  
- `MODEL_MANAGEMENT.py` — model invocation helpers  
- `EXECUTOR.py` — execution flow control  
- `UTILITIES.py` — shared helpers  
- `threats.jsonl` — reference dataset  
- `config.py` — loads secrets from environment

---

## ▶️ Run

```bash
python guardrails/__main__.py
```

---

## 🔐 Notes

- Configure secrets using `.env` at repo root.
- See `.env.example` for the required variables.

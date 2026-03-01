# 🧠 Prompt Engineering Module

> Structured LLM Control for SOC Workflow Simulation

---

## 📌 Purpose

This module defines how the AI agent interprets investigation prompts and generates structured, deterministic security analysis.

The focus is on:

- Controlling LLM behavior
- Reducing hallucination
- Enforcing SOC-style report formatting
- Maintaining reasoning boundaries
- Simulating analyst thought processes

---

## 🏗️ Role in the System
User Prompt
→
Prompt Management
→
Model Invocation
→
Structured Output


This layer acts as the translation engine between:

- Human-style investigation requests  
- Structured security analysis  
- Deterministic LLM responses  

---

## 📂 Components

| File | Responsibility |
|------|---------------|
| `PROMPT_MANAGEMENT.py` | Defines system prompts and structured formatting |
| `MODEL_MANAGEMENT.py` | Handles OpenAI API interaction |
| `EXECUTOR.py` | Orchestrates execution logic |
| `UTILITIES.py` | Shared helper functions |
| `__main__.py` | Entry point for local testing |

---

## 🔐 Security Considerations

- System prompts restrict unsafe or non-SOC outputs
- Structured formatting reduces ambiguous responses
- Temperature settings minimize variability
- Response templates enforce deterministic output

---

## 🎯 Engineering Focus

This module demonstrates:

- Controlled prompt design
- Role separation (System / User context)
- Structured output enforcement
- LLM workflow orchestration
- Applied detection engineering logic

---

## 🚀 Future Enhancements

- Structured JSON output enforcement
- Confidence scoring logic
- Automated MITRE ATT&CK tagging
- Threat severity normalization
- Injection pattern detection pre-filtering

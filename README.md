# 🔐 Password Strength Checker (Python CLI)

A **command-line tool** developed in Python to evaluate password strength, demonstrate **real-world cracking risks**, and educate users on **secure password creation practices**.

This project combines **human-centric scoring (zxcvbn)**, **regex-based validation**, **wordlist checks**, and **attack simulation using John the Ripper** to show why weak passwords fail — and how to create strong ones.

---

## 🧭 Project Purpose

Passwords remain the **first line of defense** for most systems — yet they are often the weakest.

This project was built to:
- Visually and practically demonstrate **why weak passwords are dangerous**
- Show how attackers crack passwords using real tools
- Help users understand **what makes a password strong**
- Promote **preventive password hygiene**, not just rules

---

## 🛠️ Tool Overview

The tool is a **Python-based CLI application** that analyzes passwords based on:

- Length requirements
- Character complexity
- Human-based entropy estimation
- Known weak / banned password detection
- Practical cracking feasibility

It provides **clear feedback and actionable suggestions** rather than just a numeric score.

---

## ✨ Key Features

- ✅ CLI-based interactive password evaluation  
- ✅ Length enforcement (≥ 12 characters)  
- ✅ Regex validation for:
  - Uppercase letters
  - Lowercase letters
  - Digits
  - Special characters  
- ✅ Integration with **zxcvbn** for:
  - Entropy calculation
  - Time-to-crack estimation  
- ✅ Detection of weak or banned passwords using local wordlists  
- ✅ Detailed feedback and improvement suggestions  
- ✅ JSON export support for analysis or reporting  

---

## 🔍 Validation & Scoring Logic

### 1️⃣ Regex-Based Validation
Regex checks ensure the presence of required character classes and minimum length.

This catches:
- Simple structural weaknesses
- Missing complexity patterns
- Predictable formats

---

### 2️⃣ zxcvbn Scoring Engine

The **zxcvbn** library evaluates passwords using real-world attack models, including:
- Common words
- Keyboard patterns
- Repetitions
- Known password structures

It provides:
- Strength score (0–4)
- Estimated crack time
- Context-aware feedback

---

### 3️⃣ Weak & Banned Password Detection

Passwords are compared against:
- Weak password lists
- Banned/common password wordlists

This prevents:
- Use of known compromised passwords
- Dictionary-based attack success

---

## 🧪 Example CLI Outputs

### ❌ Weak Password Example
- Short length
- Predictable pattern
- Found in wordlist
- Cracked quickly using dictionary attack

### ✅ Strong Password Example
- Long passphrase
- Mixed character sets
- High entropy
- Extremely high time-to-crack estimate

---

## 🔓 Attack Simulation (Educational Demonstration)

To reinforce learning, **offline password cracking** was demonstrated using:

- **John the Ripper**
- Dictionary attacks
- Brute-force techniques

### Key Observation:
> Short and common passwords are cracked **within seconds or minutes** using publicly available tools.

This highlights how **offline attacks bypass rate limits and lockout protections**.

---

## 🚨 Risks of Weak Passwords

Weak passwords enable:
- Dictionary and brute-force attacks
- Credential stuffing across multiple services
- Account compromise
- Identity theft
- Data breaches

Attackers routinely use leaked databases such as `rockyou.txt` to crack passwords at scale.

---

## 🛡️ How to Create Strong Passwords

Best practices demonstrated in this project:

- Use **12–16+ characters**
- Combine uppercase, lowercase, digits, and symbols
- Avoid names, dates, and personal information
- Prefer **passphrases**, e.g.: Blue$River*Train@Sunset
- Never reuse passwords across accounts
- Use a **password manager**
- Enable **Multi-Factor Authentication (MFA)** wherever possible

---

## 🧠 Educational Insights

- Users often underestimate modern cracking speed
- Offline cracking tools can perform **billions of guesses per second**
- Visual feedback improves security awareness
- Preventive hygiene is more effective than reactive controls

This project emphasizes **education through demonstration**, not fear.

---

## ⚖️ Ethical & Legal Notice

- All cracking demonstrations were performed in a **controlled lab environment**
- Only self-created accounts and test data were used
- No real systems or user data were accessed

Tools like John the Ripper must be used **only for educational or authorized testing**.

---

## 🚀 Future Enhancements

- Integrate **Have I Been Pwned API** for breach detection
- Add color-coded strength visualization
- Introduce analytics (average strength trends)
- Add password generation support
- Extend for corporate audit use cases

---

## 📌 Final Note

This project demonstrates how **simple mistakes in password creation lead to real-world compromise**, and how awareness, tooling, and education can dramatically improve security posture.

---

*This project is part of my cybersecurity internship portfolio and focuses on password security awareness, attack simulation, and preventive defense.*


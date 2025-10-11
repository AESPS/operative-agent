# 🎯 Operative Agentic AI 

<div align="center">
    
![Operative](./assets/operative_header.svg)

**Built for those late-night CTF arcs when caffeine hits harder than rate limits — stay locked in keep mewing** 🔥

Operative’s got fresh guardrails, clearer flows, and yes... extra rizz. → [See Persona List](#-persona-modes)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Anthropic Claude](https://img.shields.io/badge/Anthropic-Claude-orange.svg)](https://www.anthropic.com/)
[![OpenAI GPT](https://img.shields.io/badge/OpenAI-GPT-purple.svg)](https://openai.com/)


[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Tools](#-agent-managed-toolset) • [Examples](#-attack-chain-examples)

</div>

---

## 📋 Features

### ⚡ Now support GPT-5 API

- 🐧 **Kali-ready** — built for chaos labs you actually own (don't let bot touch prod, unc 💀)  
- 🤖 **Multi-Model Flow** — swap between Claude & GPT mid-run when you need that GOAT clarity  
- 🧰 **All-in-One Toolkit** — nmap · ffuf · binwalk · exiftool · stegseek · strings · http utils · and more  
- 💾 **Auto-Save** — no more "where did that dump go," it's chillin' in `/tmp/`  
- ⚙️ **Execution Control** — full-auto when you're in flow, manual when you're crashing out  
- 📦 **Session Recall** — Keeps track of your messy lab so you don't lose your loot no cap og.  
- 💸 **Reality Check** — APIs cost slaps 💀 RIP $5 credits — that's five nasi katok meals gone 😭
- 🚧 **Beta energy** — expect some bugs — that's just ✨ a feature ✨
- ++ (New feature 11/10/2025) 💰 Added estimate token consumption: E.g Claude with heavy model (opus)
  
        e.g 🎉 Flag detected in assistant response. Halting further automated steps.
        --- Done (requests: 10, tools: 9, tokens: 68,948 ($0.26)) ---


---

## 🤘 Quick Vibes: Why You'll Love It

- Moves like a GOAT teammate — heals, supports, never KSes  
- Runs full-lock-in mode when you're too cooked to think  
- Never ghosts mid-debug — this agent's based fr  
- Sometimes just finds the flag — call it **mythical pull** energy ✨  
- Probably a helpful tool that makes the grind a bit easier. 🔥  

---

## 🎥 Demo

https://github.com/user-attachments/assets/f3b18c96-5f24-4a58-a6ef-a39aba65f633

> **Operative** clearing a real malware challenge in ~2 minutes (4× speed).  
> Patch Tuesday mogged, unc. Main-character moment locked in. 💅  

---

## 🚀 Installation

### 🧩 Prerequisites
```bash
# Kali/ParrotOS/Ubuntu setup (kali reccomended alot of preinstalled tools)
sudo apt update && sudo apt install -y \
    python3 python3-pip nmap binutils \
    exiftool binwalk stegseek ffuf whatweb
```

### ⚡ Quick Start
```bash
# Clone repo
git clone https://github.com/AESPS/operative-agent.git
cd operative-agent

# Create and activate virtual environment
python3 -m venv venv && source venv/bin/activate
pip install anthropic openai requests

# Set keys (temporary like your situationship 💀)
export ANTHROPIC_API_KEY="..."
export OPENAI_API_KEY="..."

# Launch the agent (locked in 🔥)
python3 operatives.py
```

<details>
<summary><b>🔐 Persistent API Setup (so you don't keep typing like an NPC)</b></summary>

```bash
# For ~/.zshrc or ~/.bashrc — run this OUTSIDE the virtualenv
echo 'export ANTHROPIC_API_KEY="sk-ant-0a1b2c3d4e5f6a7b8c9d0e1f-2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d-sike-you-thought-💀💀💀"' >> ~/.zshrc
echo 'export OPENAI_API_KEY="sk-opn-abcdef1234567890abcdef1234567890-fedcba0987654321fedcba0987654321-sike-you-thought-💀💀💀"' >> ~/.zshrc
source ~/.zshrc

```
</details>

---

## 💻 Usage

### ⚠️ **Heads up — Auto-Execute is ON by default!**  
> If things start acting sus 😂 hit the brakes anytime:
>
> - **Ctrl + C** → cancel current command (Windows/Linux)  
> - **Cmd + C** → cancel on macOS  
> - **Ctrl + Z** → pause process (Linux/Windows)  
> - **Cmd + Z** → same deal for macOS users  
>
> Pro tip: mash Ctrl + C like you're dodging a boss ult 🕹️

### Basic Commands

```bash
# Start with Claude (default)
python3 operatives.py

# Start with OpenAI (different flow)
python3 operatives.py --api=openai

# Disable auto-execute (safety first)
python3 operatives.py --auto-execute=false

# Increase context depth (big brain mode)
python3 operatives.py --max-history=40

# Limit reasoning steps (speedrun mode)
python3 operatives.py --max-steps=25
```

## In-Session Controls

| Command | Description | Aliases |
|---------|-------------|---------|
| `:reset` | Clear convo memory | `reset`, `clear-history` |
| `:files` | List session artifacts | `:ls`, `ls` |
| `:paste` | Multi-line paste mode | `paste` |
| `:reference` | Show CTF cheatsheet | `:ctf`, `:cheatsheet` |
| `:help` | Display help | `help`, `-h`, `--help` |
| `quit` | Exit agent | `exit`, `q` |

## 🎭 Persona Modes

**Switch up the vibe on the fly to match your workflow.**
```bash
>persona <name>      # switch energy instantly e.g >persona genz
>persona list        # see who's available (shows active persona)
>persona reset       # return to neutral mode
```
### Available Personas

| Persona | Description |
|---------|-------------|
| 🎯 **default** | Straight-faced analyst energy; zero fluff, just execution. |
| 🔥 **genz** | Chaotic neutral; occasionally unhinged and might roast you, drops slang, emojis, and pure hype in every reply. |
| 🧙 **mentor** | Calm senior dev; reassures you, double-checks risks, logs the mission. |
| ⚡ **speedrun** | Straight to the point; optimized for terminal goblins on a timer. |
| 👾 **retro** | Old-school hacker aesthetic; leetspeak, ANSI vibes, CRT glow in text form. |
| 🚀 **ops** | Mission control precision; numbered checklists, contingencies, fallback protocols. |
| 📚 **teacher** | Patient instructor; breaks it down, shows the math, drops optional homework. |

> 💡 **Pro tip:** Toggle personas mid-session to keep the flow matching your headspace.

---

## 🤖 Model Arsenal

| Tier | Claude | OpenAI | Performance | Cost |
|------|--------|--------|-------------|------|
| **Heavy** | Opus 4.1 | GPT-5 (New) | 🔥 Big brain energy | $$$ |
| **Medium** | Sonnet 4.5 | GPT-4o | 💪 Balanced GOAT tier | $$ |
| **Light** | Haiku 3.5 | GPT-4o Mini | ⚡ Zoomies mode | $ |

<details>
<summary><b>📊 When to Use Each Tier</b></summary>

**Heavy** — when you're deep in reversing hell, clocked with coffee.  
**Medium** — the daily driver for general recon and web hunts.  
**Light** — broke mode, but fast. Based if you're speedrunning flags.
</details>

---

## 🛠️ Agent-Managed Toolset

> Just describe what you need — Operative decides which tool to deploy.  
> It's like having an partner who actually helps instead of judging your commands. 💀

### 🔍 Recon (Main-Character Flow)
| Tool | Description | Key Features |
|------|-------------|--------------|
| `nmap_scan` | Network scanner | Quick/full/version scans |
| `whatweb_scan` | Web fingerprinting | Plugin-based tech detection |
| `ffuf_scan` | Directory fuzzing | Wordlists, filters, stealth options |
| `http_fetch` | HTTP client | Headers, cookies, JSON, params |

### 📁 File Operations (Organization Arc)
| Tool | Description | Key Features |
|------|-------------|--------------|
| `read_file` | Reads files | Text/hex/binary modes |
| `write_file` | Saves outputs | Auto-tracked in `/tmp/` |
| `list_directory` | Lists directories | Recursive, hidden files |
| `search_files` | Regex file search | Ripgrep integration |
| `extract_archive` | Archive extraction | zip/tar/gz support |

### 🔬 Binary Analysis (Locked-In Ops)
| Tool | Description | Key Features |
|------|-------------|--------------|
| `strings_extract` | Extracts strings | Configurable min length |
| `hexdump_file` | Hex viewer | Adjustable width |
| `file_info` | Metadata inspector | Size, perms, MIME |
| `checksec_analyze` | Binary security check | PIE, RELRO, NX, Canary |
| `binwalk_scan` | Firmware analysis | Auto-extraction |

### 🎭 Forensics & Crypto (Detective Arc)
| Tool | Description | Key Features |
|------|-------------|--------------|
| `exiftool_scan` | Metadata scan | Images, docs, media |
| `stegseek_crack` | Stego cracker | Wordlist-based attack |
| `decode_base64` | Base64 decoder | UTF-8/hex detection |
| `compute_hash` | Hash calculator | MD5/SHA variants |

### ⚙️ System Ops (Under the Hood)
| Tool | Description | Key Features |
|------|-------------|--------------|
| `execute_command` | Shell runner | cwd/env/timeout |
| `list_session_files` | Lists session artifacts | Tracks created files |

---

## 🎯 Attack Chain Examples

### Example 1: Recon
```bash
👾 Operator [root]: Scan 10.10.10.5 --model=light

🤖 Claude [haiku 3.5]: Running a quick scan, locked in.

🔧 Tool: [nmap_scan] 10.10.10.5
✅ 22/tcp   open  ssh
✅ 80/tcp   open  http
✅ 443/tcp  open  https
```

### Example 2: Binary Check
```bash
👾 Operator [root]: Analyze /tmp/suspicious.bin

🤖 Claude [sonnet 4.5]: Let's see whats in here.

🔧 Tool: [checksec_analyze]
✅ RELRO:    Partial RELRO
✅ NX:       NX enabled
✅ PIE:      No PIE
```

### Example 3: Web Fuzz
```bash
👾 Operator [root]: Fuzz http://target.com/FUZZ

🤖 Claude [sonnet 4.5]: Running ffuf like a main character.

✅ admin    [Status: 200]
✅ backup   [Status: 200]
✅ .git     [Status: 301]
```

---

## 🎨 Multi-Line Paste Mode

```bash
Operator [root]: :paste
📋 Paste below, then type END
<paste your content here>
END

✓ Captured 47 lines as single message.
```

No more crashing out from newline pain. 🧠

---

## 🔒 Security & OPSEC

> ⚠️ **WARNING**: Direct shell access — only use in labs you control, no cap.

### Best Practices

✅ **DO:**
- Use isolated VMs
- Disable auto-execute when testing sus inputs
- Reset often to save tokens
- Review commands before letting them cook

❌ **DON'T:**
- Touch prod (please unc we're begging 🙏)
- Expose keys or session files
- Run wild — stay based

---

## 🐛 Troubleshooting

<details>
<summary><b>❌ API Key Missing (rookie move)</b></summary>

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
```
</details>

<details>
<summary><b>❌ Module Not Found (Python meltdown)</b></summary>

```bash
source venv/bin/activate
pip install anthropic openai requests
```
</details>

<details>
<summary><b>❌ Tools Missing (L moment)</b></summary>

```bash
sudo apt install -y exiftool binwalk stegseek ffuf whatweb
```
</details>

---

## 💰 Cost Optimization

| Strategy | Savings | Use Case |
|----------|---------|----------|
| `--model=light` | ~90% | Quick scans |
| `--model=medium` | ~70% | Balanced runs |
| `:reset` often | ~50% | New sessions |
| `--max-steps` limit | Variable | When AI starts rambling |

---

## ⚠️ Disclaimer

This project is for **authorized labs and CTF** — we're not villains, no cap.

- ✅ Training and education
- ✅ CTF comps, security demos
- ❌ Unlawful access or mischief
- ❌ Using this on prod (that's mid behavior)

---

## ⚠️ Important Notes and 💭 Real Talk

This AI-powered CTF agent slaps, but let's keep it 💯 about limitations:

### AI Limitations (The Reality Check)
- **Not perfect**: AI can cap or hallucinate. Always verify outputs before trusting them, unc.
- **Sidekick, not carry**: Handles boring tasks but won't replace your skills. You're still the main character.
- **Performance varies**: Goes crazy on forensics, crypto, and basic web. Complex pwn or reversing? It might crash out.
- **Misses obvious Ls**: Sometimes overlooks flags that are right there. Human oversight mandatory.

### Technical Limitations
- **Access restrictions**: Some sites block automated tools. Might need proper headers/cookies — respect site policies.
- **Input handling**: Multi-line pastes = separate commands. Use `:paste` mode for big data blocks.

### Model Performance (Picking Your Fighter)
- **Current GOAT**: Claude Opus brings strongest reasoning but costs more. Worth it for hard challenges.
- **Future vibes**: Tool improves as AI models advance. Current models have reasoning gaps.
- **No magic bullets**: This sidekick handles grunt work, not a carry to first place.

**Bottom line:** Work *with* the AI, verify outputs, keep leveling up. The tool handles tedious stuff so you stay locked in on real problem-solving. 🔥
---

<div align="center">

**Built by Ong Gedek Gedek**🔥

**If it saved you some brain cells, drop a ⭐.**  
API's still expensive, no cap 😭

[⬆ Back to Top](#-operative-agentic-ai)

</div>

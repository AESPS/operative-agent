# 🎯 Operative Agentic AI

<div align="center">

![Operative](./assets/operative_header.svg)

**Autonomous, chaos-tolerant, AI-powered CTF sidekick with 20+ built-in security tools.**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Anthropic Claude](https://img.shields.io/badge/Anthropic-Claude-orange.svg)](https://www.anthropic.com/)
[![OpenAI GPT](https://img.shields.io/badge/OpenAI-GPT-purple.svg)](https://openai.com/)

*For those late-night CTF grinds when caffeine hits harder than rate limits.*  
*Operative is your AI teammate that doesn’t sleep, forget, or ghost you mid-debug.*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Tools](#-agent-managed-toolset) • [Examples](#-attack-chain-examples)

</div>

---

## 📋 Features

- 🐧 **Lab-only / Kali-friendly** — Built for chaos labs and VMs you actually own (don’t let the bot touch prod 💀)  
- 🤖 **Multi-Model Flow** — Claude ↔ GPT on command. Swap brains mid-session when you vibe different.  
- 🧰 **All-in-One Toolkit** — nmap · ffuf · binwalk · exiftool · stegseek · strings · http utils · and more.  
- 📂 **Auto-Save Everything** — Decodes, dumps, and outputs go straight to `/tmp/` — no “where did that go” moment.  
- 🎯 **CTF Core Memory** — Knows flags, binaries, and shellcode like it’s been playing CTF since 2015.  
- ⚙️ **Execution Control** — Go full auto or manual approve when you’re feeling extra cautious.  
- 📦 **Session Recall** — Keeps track of your messy lab so you don’t lose your loot.  
- 💸 **Reality Check** — APIs cost money 💀 RIP $5 credits — that’s five nasi katok meals gone 😭  

---

## 🌈 Quick Vibes: Why You’ll Love It

- Feels like having a hacker buddy that *actually listens.*  
- Doesn’t ask “did you try nmap yet?” — it just does it.  
- Never complains about your spaghetti payloads.  
- Built to handle chaos, caffeine, and CTF pressure all at once.  

---

## 🎥 Demo

https://github.com/user-attachments/assets/f3b18c96-5f24-4a58-a6ef-a39aba65f633

> **Operative** tackling a real malware CTF challenge in ~2 minutes (shown at 4× speed).  
> Because waiting is for patch Tuesday.

---

## 🚀 Installation

### 🧩 Prerequisites
```bash
# Kali/ParrotOS/Ubuntu setup
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

# Set your API keys
export ANTHROPIC_API_KEY="..."
export OPENAI_API_KEY="..."

# Launch the agent
python3 operatives.py
```

<details>
<summary><b>🔐 Persistent API Setup (so you don’t keep typing them)</b></summary>

```bash
# For ~/.zshrc or ~/.bashrc
echo 'export ANTHROPIC_API_KEY="..."' >> ~/.zshrc
echo 'export OPENAI_API_KEY="..."' >> ~/.zshrc
source ~/.zshrc
```
</details>

---

## 💻 Usage

### Basic Commands

```bash
# Start with Claude (default)
python3 operatives.py

# Start with OpenAI
python3 operatives.py --api=openai

# Disable auto-execute (safety mode)
python3 operatives.py --auto-execute=false

# Increase context depth
python3 operatives.py --max-history=40

# Limit reasoning steps
python3 operatives.py --max-steps=25
```

### In-Session Controls

| Command | Description | Aliases |
|---------|-------------|---------|
| `:reset` | Clear convo memory | `reset`, `clear-history` |
| `:files` | List session artifacts | `:ls`, `ls` |
| `:paste` | Multi-line paste mode | `paste` |
| `:reference` | Show CTF cheatsheet | `:ctf`, `:cheatsheet` |
| `:help` | Display help | `help`, `-h`, `--help` |
| `quit` | Exit agent | `exit`, `q` |

---

## 🤖 Model Arsenal

| Tier | Claude | OpenAI | Performance | Cost |
|------|--------|--------|-------------|------|
| **Heavy** | Opus 4.1 | GPT-4 | 🔥 Big brain energy | $$$ |
| **Medium** | Sonnet 4.5 | GPT-4o Mini | 💪 Reliable middle ground | $$ |
| **Light** | Haiku 3.5 | GPT-3.5 Turbo | ⚡ Zoomies mode | $ |

<details>
<summary><b>📊 When to Use Each Tier</b></summary>

**Heavy** — for hardcore reversing, exploit dev, or anything cursed.  
**Medium** — best daily driver: recon, crypto, web fuzzing, general CTF flow.  
**Light** — for when you’re broke or speedrunning easy points.  
</details>

---

## 🛠️ Agent-Managed Toolset

> Just describe what you need — the agent decides which tool to deploy.  
> It’s like having an intern who actually gets things done.

### 🔍 Recon
| Tool | Description | Key Features |
|------|-------------|--------------|
| `nmap_scan` | Network scanner | Quick/full/version scans |
| `whatweb_scan` | Web tech fingerprinting | Aggressive mode, plugin support |
| `ffuf_scan` | Directory fuzzing | Wordlists, filters, stealth options |
| `http_fetch` | HTTP client | Headers, cookies, JSON, params |

### 📁 File Operations
| Tool | Description | Key Features |
|------|-------------|--------------|
| `read_file` | Reads files | Text/hex/binary modes |
| `write_file` | Saves outputs | Auto-tracked in `/tmp/` |
| `list_directory` | Lists dirs | Recursive, hidden files |
| `search_files` | Regex file search | Ripgrep integration |
| `extract_archive` | Extracts archives | zip/tar/gz support |

### 🔬 Binary Analysis
| Tool | Description | Key Features |
|------|-------------|--------------|
| `strings_extract` | Pulls strings | Configurable min length |
| `hexdump_file` | Hex view | Adjustable width |
| `file_info` | File metadata | Size, perms, MIME |
| `checksec_analyze` | Binary security check | PIE, RELRO, NX, Canary |
| `binwalk_scan` | Firmware analysis | Auto-extraction |

### 🎭 Forensics & Crypto
| Tool | Description | Key Features |
|------|-------------|--------------|
| `exiftool_scan` | Metadata scan | Images, docs, media |
| `stegseek_crack` | Stego cracker | Wordlist-based attack |
| `decode_base64` | Base64 decoder | UTF-8/hex detection |
| `compute_hash` | Hash calculator | MD5/SHA variants |

### ⚙️ System
| Tool | Description | Key Features |
|------|-------------|--------------|
| `execute_command` | Shell runner | cwd/env/timeout |
| `list_session_files` | Lists artifacts | Tracks everything created |

---

## 🎯 Attack Chain Examples

### Example 1: Basic Recon
```bash
👾 Operator [root]: Scan 10.10.10.5 --model=light

🤖 Claude [haiku 3.5]: I'll perform a quick port scan on the target.

🔧 Tool: [nmap_scan] 10.10.10.5 (quick)
✅ Result:
  PORT     STATE SERVICE
  22/tcp   open  ssh
  80/tcp   open  http
  443/tcp  open  https
```

### Example 2: Binary Analysis
```bash
👾 Operator [root]: Analyze /tmp/suspicious.bin

🤖 Claude [sonnet 4.5]: I'll examine this binary systematically.
  1. Check file type and metadata
  2. Extract readable strings
  3. Look for embedded data

🔧 Tool: [file_info] /tmp/suspicious.bin
✅ Result:
  Size: 8432 bytes
  ELF 64-bit LSB executable, x86-64

🔧 Tool: [checksec_analyze] /tmp/suspicious.bin
✅ Result:
  RELRO:    Partial RELRO
  Stack:    No canary found
  NX:       NX enabled
  PIE:      No PIE
```

### Example 3: Web Fuzzing
```bash
👾 Operator [root]: Fuzz http://target.com/FUZZ for hidden directories

🤖 Claude [sonnet 4.5]: I'll use ffuf to discover hidden paths.

🔧 Tool: [ffuf_scan] http://target.com/FUZZ
✅ Result:
  admin                   [Status: 200, Size: 1234]
  backup                  [Status: 200, Size: 567]
  .git                    [Status: 301, Size: 89]
```

### Example 4: Steganography
```bash
👾 Operator [root]: Check if there's hidden data in image.jpg

🤖 Claude [sonnet 4.5]: I'll analyze the image metadata and attempt stego extraction.

🔧 Tool: [exiftool_scan] image.jpg
✅ Result:
  File Type: JPEG
  Comment: Something hidden here...

🔧 Tool: [stegseek_crack] image.jpg
✅ Result:
  [i] Found passphrase: "password123"
  Recovered data saved to: image.jpg.out

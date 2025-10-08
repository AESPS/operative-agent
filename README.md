# 🎯 Operative Agentic AI

<div align="center">

![Operative](./assets/operative_header.svg)

**Autonomous, chaos-tolerant, AI-powered CTF sidekick that's here to help you aura farm.**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Anthropic Claude](https://img.shields.io/badge/Anthropic-Claude-orange.svg)](https://www.anthropic.com/)
[![OpenAI GPT](https://img.shields.io/badge/OpenAI-GPT-purple.svg)](https://openai.com/)

*For those late-night CTF grinds when caffeine hits harder than rate limits.*  
*Operative is your AI teammate that doesn't sleep, forget, or ghost you mid-debug.*  
*A helpful tool that makes CTF challenges a bit less painful fr fr.* 🔥

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Tools](#-agent-managed-toolset) • [Examples](#-attack-chain-examples)

</div>

---

## 📋 Features

- 🐧 **Kali-friendly** — Built for chaos labs and VMs you actually own (don't let the bot touch prod 💀)  
- 🤖 **Multi-Model Flow** — Claude ↔ GPT on command. Swap brains mid-session when you vibe different fr.  
- 🧰 **All-in-One Toolkit** — nmap · ffuf · binwalk · exiftool · stegseek · strings · http utils · and more.  
- 📂 **Auto-Save** — Decodes, dumps, and outputs go straight to `/tmp/` — no "where did that go" moment.  
- 🎯 **CTF Core Memory** — Knows flags, binaries, and shellcode. It's been around the block fr.  
- ⚙️ **Execution Control** — Go full auto or manual approve when you're feeling extra cautious.  
- 📦 **Session Recall** — Keeps track of your messy lab so you don't lose your loot no cap og.  
- 💸 **Reality Check** — APIs cost money 💀 RIP $5 credits — that's five nasi katok meals gone 😭
- This is currently in beta, work in progress, expect some bugs but thats just feature ✨

---

## 🤘 Quick Vibes: Why You'll Love It

- Feels like having a hacker buddy that *actually listens* rare find fr.  
- Doesn't ask "did you try nmap yet?" — it just does it.  
- Never complains about your spaghetti payloads.  
- Built to handle chaos, caffeine, and CTF pressure all at once.  
- A genuinely helpful tool that makes the grind a bit easier. 🔥  

---

## 🎥 Demo

https://github.com/user-attachments/assets/f3b18c96-5f24-4a58-a6ef-a39aba65f633

> **Operative** tackling a real malware CTF challenge in ~2 minutes (shown at 4× speed).  
> Because waiting is for patch Tuesday. Pretty efficient ngl. 💯
  
## 🚀 Installation

### 🧩 Prerequisites
```bash
# Kali/ParrotOS/Ubuntu setup (respectfully requesting you run these commands)
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

# Set your API keys (fr fr don't skip this)
export ANTHROPIC_API_KEY="..."
export OPENAI_API_KEY="..."

# Launch the agent (time to start aura farming 🔥)
python3 operatives.py
```

<details>
<summary><b>🔐 Persistent API Setup (so you don't keep typing them like a bot)</b></summary>

```bash
# For ~/.zshrc or ~/.bashrc
echo 'export ANTHROPIC_API_KEY="..."' >> ~/.zshrc
echo 'export OPENAI_API_KEY="..."' >> ~/.zshrc
source ~/.zshrc
```
</details>

---

## 💻 Usage

# NOTE: By Default AUTO-EXECUTE IS ON! cancel any ruuning process with control + C or CMD + C

### Basic Commands

```bash
# Start with Claude (default)
python3 operatives.py

# Start with OpenAI (different vibe)
python3 operatives.py --api=openai

# Disable auto-execute (safety first, we respect boundaries)
python3 operatives.py --auto-execute=false

# Increase context depth (big brain mode activated)
python3 operatives.py --max-history=40

# Limit reasoning steps (speed run mode no cap)
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
| **Heavy** | Opus 4.1 | GPT-4o | 🔥 Big brain energy | $$ |
| **Medium** | Sonnet 4.5 | GPT-4o Mini | 💪 Reliable middle ground | $ |
| **Light** | Haiku 3.5 | GPT-3.5 Turbo | ⚡ Zoomies mode | $ |

<details>
<summary><b>📊 When to Use Each Tier</b></summary>

**Heavy** — for hardcore reversing, exploit dev, or anything cursed fr fr. Best for the really tough challenges.  
**Medium** — best daily driver: recon, crypto, web fuzzing, general CTF flow. Good balance of speed and smarts. 💯  
**Light** — for when you're broke or speedrunning easy points.  
</details>

---

## 🛠️ Agent-Managed Toolset

> Just describe what you need — the agent decides which tool to deploy.  
> It's like having a helpful assistant who actually gets things done (no cap, pretty efficient).  
> This toolset covers handful CTF scenarios you'll run into. 🔥

### 🔍 Recon (Aura Farming Essentials)
| Tool | Description | Key Features |
|------|-------------|--------------|
| `nmap_scan` | Network scanner | Quick/full/version scans |
| `whatweb_scan` | Web tech fingerprinting | Aggressive mode, plugin support |
| `ffuf_scan` | Directory fuzzing | Wordlists, filters, stealth options |
| `http_fetch` | HTTP client | Headers, cookies, JSON, params |

### 📁 File Operations (Organization Aura 💯)
| Tool | Description | Key Features |
|------|-------------|--------------|
| `read_file` | Reads files | Text/hex/binary modes |
| `write_file` | Saves outputs (auto-tracked in `/tmp/` fr fr) | Session management on point |
| `list_directory` | Lists dirs | Recursive, hidden files |
| `search_files` | Regex file search | Ripgrep integration |
| `extract_archive` | Extracts archives | zip/tar/gz support |

### 🔬 Binary Analysis (Big Brain Territory)
| Tool | Description | Key Features |
|------|-------------|--------------|
| `strings_extract` | Pulls strings | Configurable min length |
| `hexdump_file` | Hex view | Adjustable width |
| `file_info` | File metadata | Size, perms, MIME |
| `checksec_analyze` | Binary security check | PIE, RELRO, NX, Canary |
| `binwalk_scan` | Firmware analysis | Auto-extraction |

### 🎭 Forensics & Crypto (Detective Aura Farming)
| Tool | Description | Key Features |
|------|-------------|--------------|
| `exiftool_scan` | Metadata scan | Images, docs, media |
| `stegseek_crack` | Stego cracker | Wordlist-based attack |
| `decode_base64` | Base64 decoder | UTF-8/hex detection |
| `compute_hash` | Hash calculator | MD5/SHA variants |

### ⚙️ System (Under the Hood Vibes)
| Tool | Description | Key Features |
|------|-------------|--------------|
| `execute_command` | Shell runner (terminal access fr fr) | cwd/env/timeout |
| `list_session_files` | Lists artifacts (showing your aura farm progress) | Tracks everything created |

---

## 🎯 Attack Chain Examples (Peak Aura Farming Moments)

### Example 1: Basic Recon (Respectful Port Knocking)
```bash
👾 Operator [root]: Scan 10.10.10.5 --model=light

🤖 Claude [haiku 3.5]: I'll perform a quick port scan on the target fr fr.

🔧 Tool: [nmap_scan] 10.10.10.5 (quick)
✅ Result:
  PORT     STATE SERVICE
  22/tcp   open  ssh      (respectfully found)
  80/tcp   open  http     (web server vibes)
  443/tcp  open  https    (secure og approved)
```

### Example 2: Binary Analysis (Deep Dive Mode)
```bash
👾 Operator [root]: Analyze /tmp/suspicious.bin

🤖 Claude [sonnet 4.5]: I'll examine this binary systematically.
  1. Check file type and metadata
  2. Extract readable strings
  3. Look for embedded data (deep dive mode)

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

### Example 3: Web Fuzzing (Finding Hidden Paths 🔥)
```bash
👾 Operator [root]: Fuzz http://target.com/FUZZ for hidden directories

🤖 Claude [sonnet 4.5]: I'll use ffuf to discover hidden paths. Let's see what we can find fr fr.

🔧 Tool: [ffuf_scan] http://target.com/FUZZ
✅ Result:
  admin                   [Status: 200, Size: 1234] (found the admin panel bestie 💯)
  backup                  [Status: 200, Size: 567] (backup files exposed fr)
  .git                    [Status: 301, Size: 89] (git leak detected, nice find)
```

---

## 🎨 Multi-Line Paste Mode

For pasting code, payloads, or large data blocks (because sometimes you gotta spam bestie):

```bash
Operator [root]: :paste
📋 Multi-line paste mode activated.
   Paste your content below, then type 'END' on a new line to finish.
   All newlines will be converted to spaces.

<paste your content here>
END

✓ Captured 47 lines as single message.
```

This prevents the terminal from treating each line as a separate command. Fr fr, this saves you from so much pain.

---

### 📦 **Smart Archive Handling**
Auto-detects and extracts: `.zip`, `.tar`, `.tar.gz`, `.tgz`, `.gz` (unboxing moment every time)

---

## 🔒 Security & OPSEC (Respectfully Speaking)

> ⚠️ **WARNING**: This tool provides direct shell access. Only use in controlled lab environments. Fr fr, don't be that person who breaks prod.

### Best Practices (Real Talk Bestie)

✅ **DO:**
- Use in isolated VMs/containers (keep it contained fr)
- Disable auto-execute for unknown targets (`--auto-execute=false`) (trust issues are valid)
- Review tool calls before execution in high-risk scenarios (double checking is not a L)
- Keep conversation history short with `:reset` to save tokens (your wallet will thank you)

❌ **DON'T:**
- Use on production systems (please bestie, we're begging)
- Run with auto-execute on untrusted targets (that's how you catch a case fr)
- Store API keys in scripts or repos (GitHub gonna expose you 💀)
- Share session files without sanitizing (OPSEC is not optional)

### Data Privacy (We Respect Your Privacy Fr Fr)
- All file artifacts saved to `/tmp/operative_<session_id>_*`
- Conversation history stored in `~/.operativeagent_history`
- No data sent to external servers except API providers (we're not sus like that)

---

## 🐛 Troubleshooting (When Things Get Messy)

<details>
<summary><b>❌ API Key Not Found (Bestie You Forgot Something)</b></summary>

```bash
# Verify keys are set
echo $ANTHROPIC_API_KEY
echo $OPENAI_API_KEY

# If empty, set them (respectfully requesting you add these):
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
```
</details>

<details>
<summary><b>❌ Module Not Found (Python Drama Fr)</b></summary>

```bash
# Ensure you're in the virtual environment (are you even activated bestie?)
source venv/bin/activate

# Reinstall dependencies (turn it off and on again vibes)
pip install anthropic openai requests
```
</details>

<details>
<summary><b>❌ Tool Not Available (Missing Dependencies Caught Lacking)</b></summary>

```bash
# Install optional CTF tools (time to complete the build)
sudo apt install -y exiftool binwalk stegseek ffuf whatweb

# Or the agent will use Python fallbacks where possible (adaptable king behavior)
```
</details>

<details>
<summary><b>❌ Prompt Line Overlap (Visual Glitch Era)</b></summary>

Fixed in latest version. Update if you're seeing overlapping text on long inputs (we mogged that bug).
```bash
git pull origin main
```
</details>

<details>
<summary><b>⌨️ Multi-Line Paste Issues (The Newline Struggle Is Real)</b></summary>

Use `:paste` mode to handle multi-line input properly (this is the way bestie):
```bash
Operator [root]: :paste
<paste content>
END
```
</details>

---

## 💰 Cost Optimization (Because APIs Are Expensive Fr Fr 😭)

| Strategy | Savings | When to Use |
|----------|---------|-------------|
| Use `--model=light` | ~90% | Quick scans, simple queries (broke king mode) |
| Use `--model=medium` | ~70% | General CTF work (recommended for peak aura farming) |
| `:reset` history often | ~50% | Between unrelated challenges (clean slate vibes) |
| Limit `--max-steps` | Variable | Prevent runaway loops (when AI gets too excited) |

---

## ⚠️ Disclaimer (Legal Stuff, Respectfully)

This tool is designed for **authorized security testing and CTF competitions only**. 

- ✅ Educational purposes in controlled environments (learning is based)
- ✅ CTF competitions and wargames (aura farming territory)
- ❌ Unauthorized access to systems (don't be that person fr)
- ❌ Malicious activities (we don't condone chaos in the wild)

## ⚠️ Important Notes and 💭 Thoughts

This AI-powered CTF agent is helpful, but understanding its limitations is crucial:

### AI Limitations
- **Not perfect**: AI can make mistakes or hallucinate answers. Always verify suggestions before trusting them.
- **Assistant, not autopilot**: Speeds up workflow and handles repetitive tasks, but won't replace your CTF skills. You're still solving the challenge.
- **Performance varies**: Excels at forensics, crypto, and basic web challenges. Struggles with complex pwn or reverse engineering that requires creative problem-solving.
- **Misses obvious things**: Sometimes overlooks easy flags that humans spot instantly. Human oversight is essential.

### Technical Limitations
- **Access restrictions**: Some services block automated tools (robots.txt). May require proper headers/cookies to bypass—respect site policies.
- **Input handling**: Multi-line pastes are treated as separate commands. Use `:paste` mode or save to file for large data blocks.

### Model Performance
- **Current best**: Claude Opus offers strongest reasoning for CTF tasks, but costs more. Worth it for difficult challenges.
- **Future outlook**: Tool will improve as AI models advance. Current models have reasoning gaps that limit capabilities.
- **No magic bullets**: Don't expect instant solutions. This is a sidekick that reduces tedious work, not a skill replacement.

**Bottom line:** Work *with* the AI, verify outputs, and keep developing your skills. The tool handles grunt work so you can focus on actual problem-solving.


If it saved you some brain cells, give it a ⭐ 😭

No cap, this project is absolutely mogging the CTF automation game. Stay humble, stay hungry, keep grinding. 🔥

[⬆ Back to Top](#-operative-agentic-ai)


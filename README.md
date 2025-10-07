# 🎯 Operative Agentic AI

<div align="center">

![Operative](./assets/operative_header.svg)

**AI-Powered CTF & Security Analysis Agent**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Anthropic Claude](https://img.shields.io/badge/Anthropic-Claude-orange.svg)](https://www.anthropic.com/)
[![OpenAI GPT](https://img.shields.io/badge/OpenAI-GPT-purple.svg)](https://openai.com/)

*Autonomous security testing agent with 20+ built-in CTF tools*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Tools](#-weaponized-toolset) • [Examples](#-attack-chain-examples)

</div>

---

## 📋 Features

- 🐧 **Lab-only / Kali friendly** — CTF-first tooling; run in isolated labs or VMs you own.
- 🤖 **Multi-model** — Claude ↔ OpenAI switching with sensible defaults.
- 🧰 **Tools included** — nmap · ffuf · binwalk · exiftool · stegseek · strings · http clients · more.
- 📂 **Auto artifact save** — decoded/extracted results auto-saved to `/tmp/` (session indexed).
- 🎯 **CTF helpers** — flag heuristics, binary checks, shellcode inspection helpers.
- ⚙️ **Execution control** — automatic or manual confirmation; inline flag overrides per command.
- 📦 **Session file tracking** — list, read, and purge session artifacts.
- 💸 **Cost note** — api mahal :')  bali kridit $5 inda batah tu. Nasi katok dapat 5 kanyang makan awo 


---

## 🎥 Demo

https://github.com/user-attachments/assets/f3b18c96-5f24-4a58-a6ef-a39aba65f633

> **Operative** solving a real malware CTF challenge in ~2 minutes (shown at 4× speed)

---

## 🚀 Installation

### Prerequisites
```bash
# Kali/ParrotOS/Ubuntu
sudo apt update && sudo apt install -y \
    python3 python3-pip nmap binutils \
    exiftool binwalk stegseek ffuf whatweb
```

### Quick Start
```bash
# Clone repository
git clone https://github.com/AESPS/operative-agent.git
cd operative-agent

# Setup environment
python3 -m venv venv && source venv/bin/activate
pip install anthropic openai requests

# Configure API keys
export ANTHROPIC_API_KEY="sk-ant-api03-..."
export OPENAI_API_KEY="sk-..."

# Launch
python3 operatives.py
```

<details>
<summary><b>🔐 Persistent API Key Setup</b></summary>

```bash
# For Zsh
echo 'export ANTHROPIC_API_KEY="sk-ant-api03-..."' >> ~/.zshrc
echo 'export OPENAI_API_KEY="sk-..."' >> ~/.zshrc
source ~/.zshrc

# For Bash
echo 'export ANTHROPIC_API_KEY="sk-ant-api03-..."' >> ~/.bashrc
echo 'export OPENAI_API_KEY="sk-..."' >> ~/.bashrc
source ~/.bashrc
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

# Disable auto-execute (safe mode)
python3 operatives.py --auto-execute=false

# Increase context depth
python3 operatives.py --max-history=40

# Limit steps per query
python3 operatives.py --max-steps=25
```

### In-Session Controls

| Command | Description | Aliases |
|---------|-------------|---------|
| `:reset` | Clear conversation history | `reset`, `clear-history` |
| `:files` | List session artifacts | `:ls`, `ls` |
| `:paste` | Multi-line paste mode | `paste` |
| `:reference` | Show CTF cheatsheet | `:ctf`, `:cheatsheet` |
| `:help` | Display help | `help`, `-h`, `--help` |
| `quit` | Exit agent | `exit`, `q` |

### Inline Flags

Override settings per-message:

```bash
# Model selection
Operator [root]: scan target --model=heavy
Operator [root]: quick recon --model=light

# Execution control  
Operator [root]: download payload --auto-execute=false

# Step limiting
Operator [root]: deep analysis --max-steps=50
```

---

## 🤖 Model Arsenal

| Tier | Claude | OpenAI | Performance | Cost |
|------|--------|--------|-------------|------|
| **Heavy** | Opus 4.1 | GPT-4 | 🔥 Maximum reasoning | $$$ |
| **Medium** | Sonnet 4.5 | GPT-4o Mini | 💪 Balanced | $$ |
| **Light** | Haiku 3.5 | GPT-3.5 Turbo | ⚡ Fast responses | $ |

<details>
<summary><b>📊 When to Use Each Tier</b></summary>

**Heavy** - Complex reverse engineering, exploit development, multi-step attacks  
**Medium** - General CTF work, web recon, crypto challenges (recommended default)  
**Light** - Quick scans, simple file operations, fast iteration
</details>

---

## 🛠️ Agent-Managed Toolset
*(Automatically invoked by Operative-agent; users just describe what they need)*
“Agent triggers these tools after you ask for a specific task.”

### 🔍 **Reconnaissance**
| Tool | Description | Key Features |
|------|-------------|--------------|
| `nmap_scan` | Network port scanning | Quick/full/version scans |
| `whatweb_scan` | Web technology fingerprinting | Aggressive mode, plugin support |
| `ffuf_scan` | Content discovery fuzzing | Custom wordlists, filter options |
| `http_fetch` | HTTP client with session mgmt | Headers, cookies, JSON, params |

### 📁 **File Operations**

| Tool | Description | Key Features |
|------|-------------|--------------|
| `read_file` | File content reader | Text/hex/binary modes |
| `write_file` | Save to `/tmp/` with tracking | Auto-tracked session files |
| `list_directory` | Directory inspector | Recursive, hidden files |
| `search_files` | Regex file search | Ripgrep integration, glob patterns |
| `extract_archive` | Archive extractor | zip/tar/gz/gzip support |

### 🔬 **Binary Analysis**

| Tool | Description | Key Features |
|------|-------------|--------------|
| `strings_extract` | Extract readable strings | Configurable min length |
| `hexdump_file` | Hex viewer | Adjustable width, byte limits |
| `file_info` | File metadata inspector | Size, perms, MIME type |
| `checksec_analyze` | Binary security analysis | PIE, RELRO, Canary, NX checks |
| `binwalk_scan` | Firmware scanner | Auto-extraction option |

### 🎭 **Forensics & Crypto**

| Tool | Description | Key Features |
|------|-------------|--------------|
| `exiftool_scan` | Metadata extractor | Images, docs, media files |
| `stegseek_crack` | Steganography cracker | Wordlist-based attacks |
| `decode_base64` | Base64 decoder | Auto UTF-8/hex detection |
| `compute_hash` | Hash calculator | MD5/SHA1/SHA256/SHA512 |

### ⚙️ **System**

| Tool | Description | Key Features |
|------|-------------|--------------|
| `execute_command` | Shell command runner | cwd/env/timeout support |
| `list_session_files` | Session artifact viewer | Track all created files |

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
  
👾 Operator [root]: Check what's running on port 80

🤖 Claude [haiku 3.5]: I'll fingerprint the web server.

🔧 Tool: [whatweb_scan] http://10.10.10.5
✅ Result:
  Apache[2.4.41], PHP[7.4.3], jQuery[3.5.1]
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

🔧 Tool: [strings_extract] /tmp/suspicious.bin
✅ Result:
  /lib64/ld-linux-x86-64.so.2
  flag{r3v3rs3_m3_1f_y0u_c4n}
  admin_backdoor_enabled
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

👾 Operator [root]: Fetch http://target.com/.git/config with custom headers

🔧 Tool: [http_fetch] http://target.com/.git/config
✅ Result:
  Status: 200
  [core]
    repositoryformatversion = 0
    filemode = true
    bare = false
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

🔧 Tool: [read_file] image.jpg.out (mode: text)
✅ Result:
  flag{st3g0_m4st3r_2024}
```

---

## 🎨 Multi-Line Paste Mode

For pasting code, payloads, or large data blocks:

```bash
Operator [root]: :paste
📋 Multi-line paste mode activated.
   Paste your content below, then type 'END' on a new line to finish.
   All newlines will be converted to spaces.

<paste your content here>
END

✓ Captured 47 lines as single message.
```

This prevents the terminal from treating each line as a separate command.

---

## 🔥 Advanced Features

### 🧠 **Intelligent System Prompts**
- Specialized CTF reasoning built-in
- Auto-suggests next investigation steps
- Prefers helper scripts over brittle one-liners

### 🐍 **Auto Python Script Wrapping**
Automatically converts fragile `python -c` commands into temporary scripts:
```python
# Before: python -c "long\nmultiline\ncode"  ❌ Breaks
# After: python /tmp/operative_xxx.py  ✅ Works
```

### 🌐 **HTTP Session Management**
- Persistent cookies across requests
- Automatic redirect following
- JSON/form data support
- Response body auto-saving

### 📦 **Smart Archive Handling**
Auto-detects and extracts: `.zip`, `.tar`, `.tar.gz`, `.tgz`, `.gz`

---

## 🔒 Security & OPSEC

> ⚠️ **WARNING**: This tool provides direct shell access. Only use in controlled lab environments.

### Best Practices

✅ **DO:**
- Use in isolated VMs/containers
- Disable auto-execute for unknown targets (`--auto-execute=false`)
- Review tool calls before execution in high-risk scenarios
- Keep conversation history short with `:reset` to save tokens

❌ **DON'T:**
- Use on production systems
- Run with auto-execute on untrusted targets
- Store API keys in scripts or repos
- Share session files without sanitizing

### Data Privacy
- All file artifacts saved to `/tmp/operative_<session_id>_*`
- Conversation history stored in `~/.operativeagent_history`
- No data sent to external servers except API providers

---

## 🐛 Troubleshooting

<details>
<summary><b>❌ API Key Not Found</b></summary>

```bash
# Verify keys are set
echo $ANTHROPIC_API_KEY
echo $OPENAI_API_KEY

# If empty, set them:
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
```
</details>

<details>
<summary><b>❌ Module Not Found</b></summary>

```bash
# Ensure you're in the virtual environment
source venv/bin/activate

# Reinstall dependencies
pip install anthropic openai requests
```
</details>

<details>
<summary><b>❌ Tool Not Available</b></summary>

```bash
# Install optional CTF tools
sudo apt install -y exiftool binwalk stegseek ffuf whatweb

# Or the agent will use Python fallbacks where possible
```
</details>

<details>
<summary><b>❌ Prompt Line Overlap</b></summary>

Fixed in latest version. Update if you're seeing overlapping text on long inputs.
```bash
git pull origin main
```
</details>

<details>
<summary><b>⌨️ Multi-Line Paste Issues</b></summary>

Use `:paste` mode to handle multi-line input properly:
```bash
Operator [root]: :paste
<paste content>
END
```
</details>

---

## 💰 Cost Optimization

| Strategy | Savings | When to Use |
|----------|---------|-------------|
| Use `--model=light` | ~90% | Quick scans, simple queries |
| Use `--model=medium` | ~70% | General CTF work (recommended) |
| `:reset` history often | ~50% | Between unrelated challenges |
| Limit `--max-steps` | Variable | Prevent runaway loops |

**Example costs** (approximate):
- Light model: $0.50 per 1M input tokens
- Medium model: $2-5 per 1M input tokens  
- Heavy model: $15-30 per 1M input tokens

---

## 🤝 Contributing

Contributions welcome! Areas of interest:
- Additional CTF tools integration
- Model provider support (Gemini, Mistral, etc.)
- Enhanced stealth/evasion techniques
- Web UI frontend

---

## 📜 License

MIT License - See [LICENSE](LICENSE) for details

---

## ⚠️ Disclaimer

This tool is designed for **authorized security testing and CTF competitions only**. 

- ✅ Educational purposes in controlled environments
- ✅ CTF competitions and wargames
- ✅ Penetration testing with explicit permission
- ❌ Unauthorized access to systems
- ❌ Malicious activities

## ⚠️ Note
-  This AI-powered CTF agent can be really helpful in your cybersecurity journey, but keep these points in mind:
-  AI isn't perfect: It can make mistakes or "hallucinate" answers. Always double-check what it suggests.
-  Not a replacement for skill: This tool is here to help you, not play the game for you. It can speed up your work, handle boring tasks, and give you ideas — but real CTF skills still come from you.
-  Mixed results: It does great with simple challenges like forensics, crypto, and basic web tasks. But for harder ones (like pwn or reversing), you'll still need to dig in yourself.
-  Beware of hosted services like web that may block AI from accessing (usually in robots.txt). In some cases can be bypassed by using proper headers and cookies.
-  **Input Limitations**: When pasting multi-line content, each newline is treated as a separate command. For large data blocks, either remove newlines or save to a file first.


**You are responsible for your actions.** The authors assume no liability for misuse.

---

## 🙏 Acknowledgments

- Anthropic for Claude AI
- OpenAI for GPT models
- The CTF community for inspiration
- Kali Linux team for the tooling ecosystem

---

<div align="center">

**Built with 🔥 by Ong Gedek Gedek**

*Kalau kan membantu, star saja repo ani. API mahal bah! 😅*

[⬆ Back to Top](#-operative-agentic-ai)

</div>

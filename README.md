# 🎯 Operative Agentic AI

<div align="center">

![Operative](./assets/operative_header.svg)

**AI-Powered CTF & Security Analysis Agent**

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Anthropic](https://img.shields.io/badge/Anthropic-Claude-orange.svg)](https://www.anthropic.com/)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT-purple.svg)](https://openai.com/)

*Autonomous security testing agent with 20+ built-in CTF tools*

</div>

---

## ✨ Features

### 🤖 **Multi-Model AI**
- Claude Opus/Sonnet/Haiku
- GPT-4/GPT-4o/GPT-3.5
- Smart model switching
- Cost optimization

### 🛠️ **20+ Security Tools**
- Network reconnaissance
- Binary analysis  
- Web fuzzing
- Forensics & steganography

### 🎯 **CTF Optimized**
- Flag pattern detection
- Auto-save artifacts to `/tmp/`
- Session file tracking
- Multi-step reasoning

### ⚡ **Flexible Control**
- Auto-execute or manual approve
- Inline model switching
- Step limit controls
- History depth management

---

## 🎥 Demo

<div align="center">
<img src="https://github.com/user-attachments/assets/demo-placeholder.gif" alt="Operative Demo" width="80%">

> **Operative** solving a real malware CTF challenge in ~2 minutes (shown at 4× speed)
</div>

---

## 🚀 Quick Start

```bash
# Clone & setup
git clone https://github.com/AESPS/operative-agent.git
cd operative-agent
python3 -m venv venv && source venv/bin/activate
pip install anthropic openai requests

# Configure API keys
export ANTHROPIC_API_KEY="sk-ant-api03-..."
export OPENAI_API_KEY="sk-..."

# Launch
python3 operatives.py
```

<details>
<summary><b>📋 Full Installation Guide</b></summary>

### Prerequisites
```bash
# Kali/ParrotOS/Ubuntu
sudo apt update && sudo apt install -y \
    python3 python3-pip nmap binutils \
    exiftool binwalk stegseek ffuf whatweb
```

### Persistent API Key Setup
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

### Command Line Options
```bash
# Start with Claude (default)
python3 operatives.py

# Start with OpenAI  
python3 operatives.py --api=openai

# Disable auto-execute (safe mode)
python3 operatives.py --auto-execute=false

# Custom settings
python3 operatives.py --max-history=40 --max-steps=25
```

### In-Session Commands
| Command | Description | Aliases |
|---------|-------------|---------|
| `:reset` | Clear conversation history | `reset`, `clear-history` |
| `:files` | List session artifacts | `:ls`, `ls` |
| `:paste` | Multi-line paste mode | `paste` |
| `:reference` | Show CTF cheatsheet | `:ctf`, `:cheatsheet` |
| `:help` | Display help | `help`, `-h` |
| `quit` | Exit agent | `exit`, `q` |

### Inline Flags
```bash
# Model selection
scan target --model=heavy
quick recon --model=light

# Execution control
download payload --auto-execute=false

# Step limiting
deep analysis --max-steps=50
```

---

## 🤖 Model Tiers

| Tier | Claude | OpenAI | Performance | Cost |
|------|--------|--------|-------------|------|
| **Heavy** | Opus 4.1 | GPT-4 | 🔥 Maximum reasoning | $$$ |
| **Medium** | Sonnet 4.5 | GPT-4o Mini | 💪 Balanced | $$ |
| **Light** | Haiku 3.5 | GPT-3.5 Turbo | ⚡ Fast responses | $ |

---

## 🛠️ Available Tools

<details>
<summary><b>🔍 Reconnaissance</b></summary>

- `nmap_scan` - Network port scanning
- `whatweb_scan` - Web technology fingerprinting  
- `ffuf_scan` - Content discovery fuzzing
- `http_fetch` - HTTP client with session management
</details>

<details>
<summary><b>📁 File Operations</b></summary>

- `read_file` - File content reader (text/hex/binary)
- `write_file` - Save to `/tmp/` with tracking
- `list_directory` - Directory inspector
- `search_files` - Regex file search
- `extract_archive` - Archive extractor
</details>

<details>
<summary><b>🔬 Binary Analysis</b></summary>

- `strings_extract` - Extract readable strings
- `hexdump_file` - Hex viewer
- `file_info` - File metadata inspector
- `checksec_analyze` - Binary security analysis
- `binwalk_scan` - Firmware scanner
</details>

<details>
<summary><b>🎭 Forensics & Crypto</b></summary>

- `exiftool_scan` - Metadata extractor
- `stegseek_crack` - Steganography cracker
- `decode_base64` - Base64 decoder
- `compute_hash` - Hash calculator (MD5/SHA)
</details>

---

## 🎯 Example Sessions

### Basic Recon
```bash
👾 Operator: Scan 10.10.10.5 --model=light
🤖 Claude: I'll perform a quick port scan on the target.
🔧 Tool: [nmap_scan] 10.10.10.5 (quick)
✅ Result: Ports 22, 80, 443 open
```

### Binary Analysis
```bash
👾 Operator: Analyze /tmp/suspicious.bin
🤖 Claude: I'll examine this binary systematically.
🔧 Tool: [checksec_analyze] /tmp/suspicious.bin
✅ Result: NX enabled, No PIE, flag{r3v3rs3_m3}
```

### Web Fuzzing
```bash
👾 Operator: Fuzz http://target.com/FUZZ
🔧 Tool: [ffuf_scan] http://target.com/FUZZ
✅ Result: Found /admin, /backup, /.git
```

---

## 💰 Cost Optimization

| Strategy | Savings | When to Use |
|----------|---------|-------------|
| Use `--model=light` | ~90% | Quick scans, simple queries |
| Use `--model=medium` | ~70% | General CTF work |
| `:reset` history often | ~50% | Between challenges |
| Limit `--max-steps` | Variable | Prevent runaway loops |

---

## 🐛 Troubleshooting

<details>
<summary><b>Common Issues & Solutions</b></summary>

### API Key Not Found
```bash
# Verify keys are set
echo $ANTHROPIC_API_KEY
echo $OPENAI_API_KEY

# If empty, set them:
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
```

### Module Not Found
```bash
# Ensure virtual environment is active
source venv/bin/activate

# Reinstall dependencies
pip install anthropic openai requests
```

### Tool Not Available
```bash
# Install optional CTF tools
sudo apt install -y exiftool binwalk stegseek ffuf whatweb
```

### Multi-Line Paste Issues
Use `:paste` mode to handle multi-line input:
```bash
Operator: :paste
<paste content>
END
```
</details>

---

## 🤝 Contributing

Contributions welcome! Areas of interest:
- Additional CTF tools integration
- Model provider support (Gemini, Mistral, etc.)
- Enhanced stealth/evasion techniques
- Web UI frontend

---

## ⚠️ Disclaimer

This tool is designed for **authorized security testing and CTF competitions only**.

- ✅ Educational purposes in controlled environments
- ✅ CTF competitions and wargames  
- ✅ Penetration testing with explicit permission
- ❌ Unauthorized access to systems
- ❌ Malicious activities

**You are responsible for your actions.** The authors assume no liability for misuse.

---

## 📜 License

MIT License - See [LICENSE](LICENSE) for details

---

<div align="center">

**Built with 🔥 by [@AESPS](https://github.com/AESPS)**

*Kalau kan membantu, star saja repo ani. API mahal bah! 😅*

[⬆ Back to Top](#-operative-agentic-ai)

</div>

# 🎯 OperativeAgent
![Operative](./assets/operative_header.svg)
AI-powered security tool combining Claude (Anthropic) and ChatGPT (OpenAI) with automated CTF solving capabilities.

## 🚀 Quick Start

```bash
# Clone & Setup
git clone https://github.com/yourusername/operative.git
cd operative
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install
pip install anthropic openai

# Configure API Keys
export ANTHROPIC_API_KEY="..."  # For Claude
export OPENAI_API_KEY="..."     # For ChatGPT

Add to `~/.bashrc` or `~/.zshrc` for permanent setup:
echo 'export ANTHROPIC_API_KEY="..."' >> ~/.zshrc
echo 'export OPENAI_API_KEY="..."' >> ~/.zshrc
source ~/.zshrc


# Run
python3 operatives.py
```

## ⚙️ Configuration


Add to `~/.bashrc` or `~/.zshrc` for permanent setup:
```bash
echo 'export ANTHROPIC_API_KEY="..."' >> ~/.zshrc
echo 'export OPENAI_API_KEY="..."' >> ~/.zshrc
source ~/.zshrc
```

### Flag Prefixes (`flag_prefixes.txt`)
```text
# CTF flag patterns (one per line)
flag
htb
ctf
thm
picoctf
root
pwn
```

## 💡 Usage

⚠️ **Warning**: By default, runs with **Claude** and **auto-execute enabled** (commands run automatically)

### Starting Options
```bash
python3 operatives.py                      # Claude (default)
python3 operatives.py --api=openai        # ChatGPT
python3 operatives.py --auto-execute=false # Manual mode (safer)
python3 operatives.py --max-steps=25      # Custom steps
```

### Inline Flags (During Chat)
```bash
Scan target --model=heavy              # Force model weight
Scan target --model=claude             # Force Claude API
Scan target --model=openai             # Force OpenAI API
Read file --auto-execute=false         # Override auto-exec
Analyze --model=opus --max-steps=30    # Multiple flags
```

### Session Commands
- `:reset` - Clear history
- `:files` - List session files
- `:help` - Show help
- `quit` - Exit

## 🛠️ Tools

| Tool | Purpose |
|------|---------|
| `execute_command` | Shell commands |
| `read_file` | Read text/hex/binary |
| `write_file` | Save to `/tmp/` |
| `nmap_scan` | Port scanning |
| `strings_extract` | Binary analysis |
| `decode_base64` | Base64 decode |
| `compute_hash` | MD5/SHA hashes |

## 🤖 Models

| Alias | Claude | OpenAI |
|-------|--------|--------|
| `light` | Haiku 3.5 | GPT-3.5 |
| `medium` | Sonnet 4.5 | GPT-4 |
| `heavy` | Opus 4.1 | GPT-4 Turbo |

Use aliases: `--model=light` or specific: `--model=opus`

## 📝 Example Workflow

```bash
# Quick recon with light model
👾 Operator: Scan 10.10.10.5 --model=light

🤖 Claude [haiku 3.5]: I'll perform a quick port scan on that target.

🔧 Tool: [nmap_scan] 10.10.10.5 (quick)
✅ Result:
  PORT     STATE SERVICE
  22/tcp   open  ssh
  80/tcp   open  http
  443/tcp  open  https

# Binary analysis
👾 Operator: Extract strings from /tmp/binary

🤖 Claude [sonnet 4.5]: I'll extract readable strings from that binary file.

🔧 Tool: [strings_extract] /tmp/binary
✅ Result:
  /lib64/ld-linux-x86-64.so.2
  flag{found_the_hidden_string}
  admin_password_123

# Decode data
👾 Operator: Decode the base64: ZmxhZ3tiYXNlNjRfZGVjb2RlZH0=

🤖 Claude [sonnet 4.5]: Let me decode that base64 string for you.

🔧 Tool: [decode_base64] ZmxhZ3tiYXNlNjRfZGVjb2RlZH0=
✅ Result: flag{base64_decoded}

# List created files
👾 Operator: :files
📁 Session Files:
  • /tmp/operative_abc123_decoded.txt (txt)
  • /tmp/operative_abc123_extracted.bin (bin)

# Complex analysis with heavy model
👾 Operator: Analyze this binary for vulnerabilities --model=heavy --max-steps=30

🤖 Claude [opus 4.1]: I'll perform a comprehensive vulnerability analysis on the binary...
```

## 🔧 System Requirements

```bash
# Kali/Ubuntu
sudo apt update
sudo apt install python3 python3-pip nmap binutils -y
```

## ⚠️ Security

- **Lab environments only** - Full shell access
- Use `--auto-execute=false` for safety
- Files saved to `/tmp/` with unique IDs
- Review commands before execution

## 🐛 Troubleshooting

```bash
# Missing SDK
pip install anthropic openai

# Check API keys
echo $ANTHROPIC_API_KEY
echo $OPENAI_API_KEY

# Rate limits? Switch provider or use --model=light
```

## 💰 Cost Tips

- Use `light` models for simple tasks
- Use `heavy` models only when needed
- Monitor API usage in provider dashboards

---

**Built for CTFs and authorized security testing only** 🎯

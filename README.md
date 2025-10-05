# 🎯 Operative Agent

AI-Powered CTF & Security Analysis Agent with Multi-Model Support

```
 ██████╗ ██████╗ ███████╗██████╗  █████╗ ████████╗██╗██╗   ██╗███████╗
██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██║██║   ██║██╔════╝
██║   ██║██████╔╝█████╗  ██████╔╝███████║   ██║   ██║██║   ██║█████╗  
██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗██╔══██║   ██║   ██║╚██╗ ██╔╝██╔══╝  
╚██████╔╝██║     ███████╗██║  ██║██║  ██║   ██║   ██║ ╚████╔╝ ███████╗
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝  ╚══════╝
```

**Operative AI** is an intelligent agent that combines Claude and ChatGPT APIs with local Kali Linux security tools for automated CTF challenges, penetration testing, and security research.

---

## 📋 Features

- 🤖 **Multi-Model Support**: Switch between Claude (Opus, Sonnet, Haiku) and OpenAI (GPT-4, GPT-3.5)
- 🛠️ **Built-in Security Tools**: nmap, strings, file operations, encoding/decoding
- 💾 **Smart File Management**: Automatically saves decoded/generated files to `/tmp/`
- 🎯 **CTF Optimized**: Flag detection, shellcode analysis, binary inspection
- ⚡ **Flexible Execution**: Auto-execute or manual approval for each tool
- 🔧 **Inline Flags**: Override settings per-message (model, auto-execute, max-steps)
- 📁 **Session Tracking**: Remember files created during conversation
- 🎨 **Beautiful CLI**: Colorful output with animated thinking indicator

---

## 🚀 Installation

### Clone Repository

```bash
git clone https://github.com/yourusername/operative-ai.git
cd operative-ai
```

### Requirements

**System Requirements:**
- Python 3.8+
- Kali Linux or Ubuntu (recommended for security tools)
- nmap, strings, and other standard Unix utilities

**For Kali Linux:**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv nmap binutils -y
```

**For Ubuntu:**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv nmap binutils -y
```

### Setup Python Environment

```bash
# Create virtual environment
python3 -m venv env

# Activate virtual environment
source env/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Set API Keys

You need at least one API key (Claude OR OpenAI):

```bash
# For Claude (Anthropic)
export ANTHROPIC_API_KEY="..."

# For OpenAI (ChatGPT)
export OPENAI_API_KEY="..."

# Make it persistent (add to ~/.bashrc or ~/.zshrc)
echo 'export ANTHROPIC_API_KEY="..."' >> ~/.zshrc
echo 'export OPENAI_API_KEY="sk-..."' >> ~/.zshrc
source ~/.zshrc
```

---

## 🎮 Usage

### Basic Commands

**Start with Claude (default):**
```bash
python3 operatives.py
```

**Start with OpenAI:**
```bash
python3 operatives.py --api=openai
```

**Disable auto-execute for safety:**
```bash
python3 operatives.py --auto-execute=false
```

**Custom max steps:**
```bash
python3 operatives.py --max-steps=25
```

**Get help:**
```bash
python3 operatives.py -h
```

---

## 💡 Inline Flags

Use these flags **during conversation** to override settings per-message:

### `--model=MODEL`
Force a specific model for the current message.

**Examples:**
```
Scan target --model=light
Deep analysis --model=heavy
Quick check --model=gpt4
```

**Available models:**
- Generic: `light`, `medium`, `heavy`
- Claude: `haiku`, `sonnet`, `opus`
- OpenAI: `gpt3`, `gpt4`, `gpt4-turbo`

### `--auto-execute=BOOL`
Override auto-execute setting for this message.

**Examples:**
```
Read /etc/passwd --auto-execute=false
Scan network --auto-execute=true
```

### `--max-steps=N`
Limit conversation steps for this request.

**Example:**
```
Complex analysis --max-steps=30
```

---

## ⌨️ Session Commands

Type these commands during your session:

| Command | Description |
|---------|-------------|
| `:reset` | Clear conversation history (fresh context) |
| `:files` | List all files created in this session |
| `:cancel` | Kill currently running tool/process |
| `:help` | Show inline flags and examples |
| `quit` | Exit the agent |

---

## 🛠️ Available Tools

The AI can automatically use these tools:

| Tool | Description |
|------|-------------|
| `execute_command` | Run shell commands on the system |
| `read_file` | Read files in text, hex, or binary mode |
| `write_file` | Save content to `/tmp/` (auto-tracked) |
| `list_session_files` | Show files created this session |
| `decode_base64` | Decode base64 encoded data |
| `compute_hash` | Calculate MD5/SHA1/SHA256/SHA512 |
| `nmap_scan` | Port scanning (quick/full/version) |
| `strings_extract` | Extract printable strings from binaries |

---

## 📝 Example Workflows

### Basic CTF Challenge

```bash
👾 Operator [root]: Read the challenge file /tmp/challenge.txt

🤖 Claude [sonnet]: I'll read that file for you.
🔧 Tool: read_file
✅ Result: [challenge description]

👾 Operator [root]: Decode this base64: SGVsbG8gV29ybGQh

🤖 Claude [sonnet]: Decoding...
🔧 Tool: decode_base64
✅ Result: Hello World!

👾 Operator [root]: Scan 10.10.10.50 --model=light

⠹ thinking...
🤖 Claude [haiku]: Running quick nmap scan...
🔧 Tool: nmap_scan
✅ Result: [scan results]
```

### Binary Analysis

```bash
👾 Operator [root]: Extract strings from /tmp/malware.bin

🤖 ChatGPT [gpt-4]: Extracting printable strings...
🔧 Tool: strings_extract
✅ Result: [extracted strings with potential flags]

👾 Operator [root]: I see some encoded data, can you decode it?

🤖 ChatGPT [gpt-4]: I'll decode and save it.
🔧 Tool: write_file
✅ Result: ✓ File saved to: /tmp/operative_abc123_456.bin

👾 Operator [root]: :files

📁 Session Files:
  • /tmp/operative_abc123_456.bin (bin)
```

### Using Different Models

```bash
# Quick reconnaissance with light model
👾 Operator [root]: Check open ports --model=light

# Deep analysis with heavy model
👾 Operator [root]: Analyze exploit chain --model=heavy --max-steps=30

# Switch APIs mid-workflow
# (requires restarting with different --api flag)
```

---

## 🎨 Banner Reference

When you start the agent, you'll see:

```
╭─────────────────────────────────────────────────────────────────────────────╮
│ ⚙️  Configuration
├─────────────────────────────────────────────────────────────────────────────┤
│ 🤖 Provider: CLAUDE          │ ⚡ Auto-Execute: ✓ Enabled
│ 📊 Max Steps: 15             │
╰─────────────────────────────────────────────────────────────────────────────╯

📋 Available Models:
  • Claude Opus 4.1 (Heavy)
  • Claude Sonnet 4.5 (Medium)
  • Claude Haiku 3.5 (Light)

💡 Quick Help:
  Type natural language commands to interact with the agent
  Use python3 operatives.py -h for detailed help
  In-session: type :help or --help to see inline flags and examples
  Commands: :reset (clear) | :files (list files) | :cancel (kill) | quit (exit)
```

---

## 🔒 Security Notes

⚠️ **WARNING**: This tool has full shell access!

- **Only use in isolated lab environments**
- Never expose to untrusted networks
- Use `--auto-execute=false` for unknown systems
- Review tool execution before running
- All files saved to `/tmp/` by default

---

## 🐛 Troubleshooting

### "Anthropic SDK not installed"
```bash
pip install anthropic
```

### "OpenAI SDK not installed"
```bash
pip install openai
```

### "Missing API key"
```bash
# Check environment variables
echo $ANTHROPIC_API_KEY
echo $OPENAI_API_KEY

# Re-export if needed
export ANTHROPIC_API_KEY="your-key-here"
```

### API Rate Limits
If you hit rate limits:
1. Wait a few minutes
2. Switch to the other API provider
3. Use lighter models (`--model=light`)
4. Reduce `--max-steps`

### Tools Not Found (nmap, strings, etc.)
```bash
# Kali/Ubuntu
sudo apt install nmap binutils -y
```

---

## 📦 Requirements.txt

The `requirements.txt` includes:

```
anthropic>=0.39.0
openai>=1.54.0
```

Install with:
```bash
pip install -r requirements.txt
```

---

## 💰 Cost Considerations

Can be quite expensive :)

💡 **Tip**: Use `light` models for simple tasks, `heavy` models only for complex analysis.

---

## 🤝 Contributing

Contributions welcome! Feel free to:
- Report bugs
- Suggest features
- Submit pull requests
- Improve documentation

---

## 📄 License

MIT License - See LICENSE file for details

---

## 🙏 Acknowledgments

- Anthropic for Claude API
- OpenAI for ChatGPT API
- Kali Linux community
- CTF community

---

## 📧 Contact

For questions or issues, open an issue on GitHub or contact [your-email@example.com]

---

**Happy Hacking! 🎯**

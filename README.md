# 🎯 Operative - AI CTF & Security Agent
![Operative](./assets/operative_header.svg)
**AI-Powered CTF & Security Analysis Agent with Multi-Model Support**

## 📋 Features
- 🐧 Built for Kali Linux: Optimized for CTF and ~~pentesting~~ must only be use in lab and isolated that you own! 
- 🤖 **Multi-Model Support**: Switch between Claude (Opus, Sonnet, Haiku) and OpenAI (GPT-4, GPT-3.5)
- 🛠️ **Built-in Security Tools**: nmap, strings, file operations, encoding/decoding
- 💾 **Smart File Management**: Automatically saves decoded/generated files to `/tmp/`
- 🎯 **CTF Optimized**: Flag detection, shellcode analysis, binary inspection
- ⚡ **Flexible Execution**: Auto-execute or manual approval for each tool
- 🔧 **Inline Flags**: Override settings per-message (model, auto-execute, max-steps)
- 📁 **Session Tracking**: Remember files created during conversation

---

## 🚀 Installation

### Clone Repository


```bash
# Clone the arsenal
git clone https://github.com/yourusername/operative.git && cd operative

# Initialize environment
python3 -m venv venv && source venv/bin/activate

# Load dependencies
pip install anthropic openai
pip install requirements.txt

# Configure access keys (choose your method)

## [Method 1] Session-only injection
export ANTHROPIC_API_KEY="..."  # Claude access
export OPENAI_API_KEY="..."     # GPT access

## [Method 2] Persistent configuration
echo 'export ANTHROPIC_API_KEY="..."' >> ~/.zshrc && \
echo 'export OPENAI_API_KEY="..."' >> ~/.zshrc && \
source ~/.zshrc

# Execute
python3 operatives.py
```

---

## ⚙️ System Configuration

### Flag Patterns (`flag_prefixes.txt`)
```text
# CTF flag signatures
flag
htb
ctf
thm
picoctf
root
pwn
```

### Requirements
```bash
# Kali/ParrotOS/Ubuntu
sudo apt update && sudo apt install -y python3 python3-pip nmap binutils
```

---

## 💀 Usage & Exploitation

⚠️ **DEFAULT MODE**: Claude API + **AUTO-EXECUTE ENABLED** (runs commands without confirmation)

### Launch Configurations
```bash
python3 operatives.py                      # Default: Claude + auto-pwn
python3 operatives.py --api=openai        # Switch to GPT backend
python3 operatives.py --auto-execute=false # Manual approval mode (paranoid)
python3 operatives.py --max-steps=25      # Extended operation limit
```

### Runtime Overrides (Hot-Swap During Session)
```bash
[>] Scan target --model=heavy              # Maximum firepower
[>] Scan target --model=claude             # Force Claude backend
[>] Scan target --model=openai             # Force GPT backend
[>] Extract data --auto-execute=false      # Selective safety
[>] Pwn box --model=opus --max-steps=50    # Full send mode
```

### Control Sequences
```
:reset  → Wipe conversation memory
:files  → List session artifacts
:help   → Display attack vectors
:cancel → Kill running process (SIGTERM)
quit    → Terminate session
```

---

## 🛠️ Weaponized Toolset

| Vector | Function | Description |
|--------|----------|-------------|
| `execute_command` | Shell execution | Direct system access |
| `read_file` | File exfiltration | Text/hex/binary extraction |
| `write_file` | Payload deployment | Auto-tracked `/tmp/` drops |
| `nmap_scan` | Network recon | Port enumeration |
| `strings_extract` | Binary analysis | Memory dump inspection |
| `decode_base64` | Encoding ops | Data transformation |
| `compute_hash` | Crypto operations | MD5/SHA calculations |

---

## 🤖 Model Arsenal

| Alias | Claude | OpenAI | Power |
|-------|--------|--------|-------|
| `light` | Haiku 3.5 | GPT-3.5 | ⚡ Fast recon |
| `medium` | Sonnet 4.5 | GPT-4 | 💪 Balanced |
| `heavy` | Opus 4.1 | GPT-4 Turbo | 🔥 Maximum |

---

## 📝 Attack Chain Example

```bash
# Initial reconnaissance
👾 Operator [root]: Scan 10.10.10.5 --model=light

🤖 Claude [haiku 3.5]: Initiating port scan on target...

🔧 Tool: [nmap_scan] 10.10.10.5 (quick)
✅ Result:
  PORT     STATE SERVICE
  22/tcp   open  ssh
  80/tcp   open  http
  443/tcp  open  https

# Binary exploitation
👾 Operator [root]: Extract strings from /tmp/suspicious.bin

🤖 Claude [sonnet 4.5]: Extracting readable strings from binary...

🔧 Tool: [strings_extract] /tmp/suspicious.bin
✅ Result:
  /lib64/ld-linux-x86-64.so.2
  flag{pwn3d_th3_b1n4ry}
  admin_backdoor_enabled

# Data exfiltration
👾 Operator [root]: Decode: ZmxhZ3twMG5lZF90aDNfYmFzZTY0fQ==

🤖 Claude [sonnet 4.5]: Decoding base64 payload...

🔧 Tool: [decode_base64]
✅ Result: flag{p0ned_th3_base64}

# Artifact tracking
👾 Operator [root]: :files
📁 Session Files:
  • /tmp/operative_a8f2c1_payload.sh (sh)
  • /tmp/operative_a8f2c1_exfil.txt (txt)
  • /tmp/operative_a8f2c1_exploit.bin (bin)

# Heavy analysis mode
👾 Operator [root]: Analyze binary for ROP chains --model=heavy --max-steps=50

🤖 Claude [opus 4.1]: Initiating deep binary analysis for ROP gadgets...
```

---

## 🔒 OPSEC Notes

- **Lab environments ONLY** - Full shell access = full compromise
- **Auto-execute = dangerous** - Disable for unknown targets
- **Session isolation** - Each run gets unique identifiers
- **Artifact tracking** - All drops saved to `/tmp/operative_*`

---

## 🐛 Troubleshooting

```bash
# Missing modules
pip install anthropic openai

# Verify keys loaded
echo $ANTHROPIC_API_KEY && echo $OPENAI_API_KEY

# Rate limited? Switch providers
python3 operatives.py --api=openai  # Failover to GPT

# Missing tools (nmap/strings)
sudo apt install -y nmap binutils
```

---

## 💰 Resource Management

- **Recon**: Use `--model=light` (cheapest)
- **Analysis**: Use `--model=medium` (balanced)
- **Complex exploits**: Use `--model=heavy` (expensive but powerful)

---

**⚡ For authorized testing only. You are responsible for your actions.**

```
[EOF]
```

# 🎯 Operative Agentic AI with Multi Support API
![Operative](./assets/operative_header.svg)
**AI-Powered CTF & Security Analysis Agent with Multi-Model Support**

## 📋 Features
- 🐧 Built for Kali Linux: Optimized for CTF and ~~pentesting~~ must only be use in lab and isolated that you own! 
- 🤖 **Multi-Model Support**: Switch between Claude and OpenAI 
- 🛠️ **Built-in Security Tools**: nmap, strings, file operations, encoding/decoding
- 💾 **Smart File Management**: Automatically saves decoded/generated files to `/tmp/`
- 🎯 **CTF Optimized**: Flag detection, shellcode analysis, binary inspection
- ⚡ **Flexible Execution**: Auto-execute or manual approval for each tool
- 🔧 **Inline Flags**: Override settings per-message (model, auto-execute, max-steps)
- 📁 **Session Tracking**: Remember files created during conversation
- 💰 **Cons** - api mahal :')  bali kridit $5 inda batah tu. Nasi katok dapat 5 kanyang makan awo

---

https://github.com/user-attachments/assets/f3b18c96-5f24-4a58-a6ef-a39aba65f633

## 🧩 Demo: Operative Agent Solving a Malware CTF

Watch **Operative** engage a real CTF malware challenge.  
🎥 **30-second showcase**, running at **4× speed**.  
⏱️ **Real execution time:** ~2 minutes from the first prompt to completion.

---
## 🚀 Installation

### Clone Repository


```bash
# Clone the arsenal
git clone https://github.com/AESPS/operative-agent.git && cd operative-agent

# Initialize environment
python3 -m venv venv && source venv/bin/activate

# Load dependencies
pip install anthropic openai
pip install -r requirements.txt

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
    
   **TOKEN**:   Ia cani tu kalau heavy model nya capat makan token. Mahal tia jadi nya. Save duit pakai --model=light sja awo
   
### Launch Configurations
```bash
python3 operatives.py                      # Default: Claude + auto-pwn
python3 operatives.py --api=openai        # Switch to GPT backend
python3 operatives.py --auto-execute=false # Manual approval mode (paranoid)
python3 operatives.py --max-steps=25      # Extended operation limit
```

### Runtime Overrides (Hot-Swap During Session)
```bash
# Generic Model Selection
[>] Scan target --model=heavy              # Maximum firepower
[>] Scan target --model=medium             # Balanced approach
[>] Scan target --model=light              # Fast recon

# Execution Control
[>] Extract data --auto-execute=false      # Selective safety
[>] Pwn box --model=opus --max-steps=50    # Full send mode
```
---

## 🤖 Model Arsenal

| Alias | Claude | OpenAI | Power | Cost |
|-------|--------|--------|-------|------|
| `light` | Haiku 3.5 | GPT-3.5 Turbo | ⚡ Fast | $ |
| `medium` | Sonnet 4.5 | GPT-4o Mini | 💪 Balanced | $ |
| `heavy` | Opus 4.1 | GPT-4o | 🔥 Maximum | $$ |

---

## 🛠️ Weaponized Toolset

| Vector | Function | Description |
|--------|----------|-------------|
| `execute_command` | Shell execution | Direct system access |
| `read_file` | File exfiltration | Text/hex/binary extraction |
| `write_file` | Payload deployment | Auto-tracked `/tmp/` drops |
| `list_session_files` | Artifact enumeration | Show all created files |
| `nmap_scan` | Network recon | Port enumeration (quick/full/version) |
| `strings_extract` | Binary analysis | Memory dump inspection |
| `decode_base64` | Encoding ops | Data transformation |
| `compute_hash` | Crypto operations | MD5/SHA1/SHA256/SHA512 |

---

### Control Sequences
```
:reset     → Wipe conversation memory (reset, clear-history)
:files     → List session artifacts (:ls, ls)
:paste     → Multi-line paste mode - Type :paste, paste content, type END to finish
:help      → Display attack vectors (help, -h, --help)
:cancel    → Kill running process (SIGTERM)
:reference → Show CTF cheatsheet (:ctf, :cheatsheet)
quit       → Terminate session (exit, q)
```
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
- **Auto-execute = dangerous** - Disable for unknown targets (`--auto-execute=false`)
- **Session isolation** - Each run gets unique identifiers
- **Artifact tracking** - All drops saved to `/tmp/operative_*`
- **Multi-line paste limitation** - `input()` treats newlines as separate commands. For large multi-line data, remove newlines first or save to file and reference the path.

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

# Prompt overlapping on long input?
# Fixed in latest version - readline now properly handles ANSI colors

# Can't interrupt thinking animation?
# Press Ctrl+C during API call - improved responsiveness in latest version
```

---

## 💰 Resource Management

- **Recon**: Use `--model=light` (cheapest)
- **Analysis**: Use `--model=medium` (balanced)
- **Complex exploits**: Use `--model=heavy` (expensive but powerful)

**Token Cost Tips:**
- Heavy models consume tokens faster
- Use light models for simple tasks
- Switch to medium/heavy only when needed
- Reset conversation history with `:reset` to save context tokens

---

**⚡ For authorized testing only. You are responsible for your actions.**

## ⚠️ Note
-  This AI-powered CTF agent can be really helpful in your cybersecurity journey, but keep these points in mind:
-  AI isn't perfect: It can make mistakes or "hallucinate" answers. Always double-check what it suggests.
-  Not a replacement for skill: This tool is here to help you, not play the game for you. It can speed up your work, handle boring tasks, and give you ideas — but real CTF skills still come from you.
-  Mixed results: It does great with simple challenges like forensics, crypto, and basic web tasks. But for harder ones (like pwn or reversing), you'll still need to dig in yourself.
-  Beware of hosted services like web that may block AI from accessing (usually in robots.txt). In some cases can be bypassed by using proper headers and cookies.
-  **Input Limitations**: When pasting multi-line content, each newline is treated as a separate command. For large data blocks, either remove newlines or save to a file first.

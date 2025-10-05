#!/usr/bin/env python3
"""
operatives.py

CTF Agent with support for both Anthropic Claude and OpenAI ChatGPT APIs.

Features:
- Switch between Claude and ChatGPT with --api=claude|openai flag
- Inline flags: --auto-execute=true|false, --model=..., --max-steps=N
- Model aliasing for both providers
- All existing CTF tool functionality
- Unified interface for both APIs
"""

import os
import re
import sys
import json
import time
import socket
import argparse
import subprocess
import base64
import getpass
import hashlib
import threading
import unicodedata
from typing import Tuple, Optional, List, Dict, Any

# readline for nicer input and persistent history
try:
    import readline
except Exception:
    readline = None

# API clients - import based on availability
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    print("⚠  Anthropic SDK not installed. Install with: pip install anthropic")

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("⚠  OpenAI SDK not installed. Install with: pip install openai")

# ---------- Config ----------
DEFAULT_MAX_STEPS = 15
MAX_HISTORY_ENTRIES = 6
HISTORY_FILE = os.path.expanduser("~/.sweagent_history")

# Anthropic Models
CLAUDE_OPUS = "claude-opus-4-1-20250805"
CLAUDE_SONNET = "claude-sonnet-4-5-20250929"
CLAUDE_HAIKU = "claude-3-5-haiku-20241022"

# OpenAI Models
GPT4_TURBO = "gpt-4-turbo-preview"
GPT4 = "gpt-4"
GPT35_TURBO = "gpt-3.5-turbo"

CLAUDE_MODELS = {
    CLAUDE_OPUS: "Claude Opus 4.1 (Heavy)",
    CLAUDE_SONNET: "Claude Sonnet 4.5 (Medium)",
    CLAUDE_HAIKU: "Claude Haiku 3.5 (Light)",
}

OPENAI_MODELS = {
    GPT4_TURBO: "GPT-4 Turbo (Heavy)",
    GPT4: "GPT-4 (Medium)",
    GPT35_TURBO: "GPT-3.5 Turbo (Light)",
}

# Unified aliases
MODEL_ALIASES = {
    # Claude
    "claude-light": CLAUDE_HAIKU,
    "claude-medium": CLAUDE_SONNET,
    "claude-heavy": CLAUDE_OPUS,
    "haiku": CLAUDE_HAIKU,
    "sonnet": CLAUDE_SONNET,
    "opus": CLAUDE_OPUS,
    # OpenAI
    "gpt-light": GPT35_TURBO,
    "gpt-medium": GPT4,
    "gpt-heavy": GPT4_TURBO,
    "gpt3": GPT35_TURBO,
    "gpt4": GPT4,
    "gpt4-turbo": GPT4_TURBO,
    # Generic
    "light": None,  # Will be set based on provider
    "medium": None,
    "heavy": None,
}

# ---------- Colors ----------
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BRIGHT_BLACK = "\033[90m"
    NEON_GREEN = "\033[1;38;5;46m"  # Bold + 256-color bright green
    DARK_GREEN = "\033[38;5;28m"    # Darker green for model names
    MUTED_BLUE = "\033[38;5;68m"    # Muted blue for [username] - darker than cyan
    ORANGE = "\033[38;5;208m"       # Orange color for labels
    PURPLE = "\033[38;5;141m"
def color(s: str, col: str) -> str:
    return f"{col}{s}{C.RESET}"


def display_width(text: str) -> int:
    """Calculate printable width accounting for wide Unicode glyphs."""
    width = 0
    for ch in text:
        # Skip zero-width modifiers (variation selectors, joiners, etc.)
        if unicodedata.category(ch) in {"Mn", "Me", "Cf"}:
            continue
        if unicodedata.east_asian_width(ch) in {"F", "W"}:
            width += 2
        else:
            width += 1
    return width

# ---------- Utilities ----------
def now_ts() -> str:
    return time.strftime("%H:%M:%S")

def highlight_flags(text: str) -> str:
    return re.sub(r"(flag\{.*?\}|HTB\{.*?\}|CTF\{.*?\})", 
                  lambda m: color(m.group(1), C.GREEN + C.BOLD), 
                  text, flags=re.IGNORECASE)

def shorten_preview(text: str, length: int = 800) -> Tuple[str, Optional[str]]:
    if len(text) <= length:
        return text, None
    key = hashlib.sha256(text.encode()).hexdigest()[:16]
    path = f"/tmp/sweagent_out_{key}.txt"
    try:
        with open(path, "w") as fh:
            fh.write(text)
    except Exception:
        path = None
    preview = text[:length] + "..."
    return preview, path

# ---------- Inline flag parser ----------
def parse_inline_flags(raw: str, default_auto_exec: bool, default_max_steps: int) -> Tuple[str, bool, Optional[str], int]:
    auto_exec = default_auto_exec
    inline_model = None
    max_steps = default_max_steps

    m = re.search(r'--auto-(?:execute|exec)=(true|false)', raw, re.IGNORECASE)
    if m:
        auto_exec = m.group(1).lower() == "true"
        raw = re.sub(r'--auto-(?:execute|exec)=(true|false)', "", raw, flags=re.IGNORECASE)

    m2 = re.search(r'--model=([^\s]+)', raw, re.IGNORECASE)
    if m2:
        inline_model = m2.group(1)
        raw = re.sub(r'--model=[^\s]+', "", raw, flags=re.IGNORECASE)

    m3 = re.search(r'--max-steps=(\d+)', raw, re.IGNORECASE)
    if m3:
        try:
            max_steps = int(m3.group(1))
        except Exception:
            max_steps = default_max_steps
        raw = re.sub(r'--max-steps=\d+', "", raw, flags=re.IGNORECASE)

    clean = " ".join(raw.split()).strip()
    return clean, auto_exec, inline_model, max_steps

# ---------- Tool Executor ----------
class ToolExecutor:
    """Handles tool execution - shared between both APIs"""
    
    def __init__(self):
        self._current_proc = None
        self.session_files = {}  # Track files created during session
        self.session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        
    def save_to_tmp(self, content: str, filename: str = None, extension: str = "txt") -> str:
        """Save content to /tmp/ and track it"""
        if filename is None:
            timestamp = int(time.time())
            filename = f"operative_{self.session_id}_{timestamp}.{extension}"
        
        filepath = f"/tmp/{filename}"
        
        try:
            # Determine if content is binary or text
            if extension in ["bin", "exe", "elf"]:
                # Try to decode as hex first, then base64
                try:
                    if all(c in '0123456789abcdefABCDEF' for c in content.replace(' ', '').replace('\n', '')):
                        binary_data = bytes.fromhex(content.replace(' ', '').replace('\n', ''))
                    else:
                        binary_data = base64.b64decode(content)
                    with open(filepath, "wb") as f:
                        f.write(binary_data)
                except Exception:
                    with open(filepath, "w") as f:
                        f.write(content)
            else:
                with open(filepath, "w") as f:
                    f.write(content)
            
            # Make executable if script
            if extension in ["sh", "py", "pl", "rb"]:
                os.chmod(filepath, 0o755)
            
            # Track the file
            self.session_files[filename] = {
                "path": filepath,
                "extension": extension,
                "created": time.time()
            }
            
            return filepath
        except Exception as e:
            return f"Error saving file: {e}"
    
    def get_session_files(self) -> str:
        """Return list of files created in this session"""
        if not self.session_files:
            return "No files created yet in this session."
        
        output = "📁 Session Files:\n"
        for filename, info in self.session_files.items():
            output += f"  • {info['path']} ({info['extension']})\n"
        return output
    
    def get_session_context(self) -> str:
        """Get session context for AI to remember files"""
        if not self.session_files:
            return ""
        
        context = "\n[SESSION FILES - These files were created earlier in this conversation and are available for use:\n"
        for filename, info in self.session_files.items():
            context += f"  - {info['path']} (type: {info['extension']})\n"
        context += "Use these paths when referencing files from earlier in the conversation.]\n"
        return context

    def run_popen(self, cmd, shell=False, timeout=None):
        try:
            proc = subprocess.Popen(cmd, shell=shell, stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, text=True)
            self._current_proc = proc
            try:
                out, err = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except Exception:
                    pass
                self._current_proc = None
                return f"Tool timed out after {timeout} seconds."
            except KeyboardInterrupt:
                try:
                    proc.kill()
                except Exception:
                    pass
                self._current_proc = None
                return "Tool execution cancelled by user."
            self._current_proc = None
            return (out or "") + (err or "")
        except KeyboardInterrupt:
            try:
                if self._current_proc:
                    self._current_proc.kill()
            except Exception:
                pass
            self._current_proc = None
            return "Tool execution cancelled by user."
        except Exception as e:
            self._current_proc = None
            return f"Tool error: {e}"

    def execute_tool(self, tool_name: str, tool_input: dict) -> str:
        try:
            if tool_name == "execute_command":
                cmd = tool_input.get("command", "")
                print(color(f"[{now_ts()}] ➜ running: {cmd}", C.YELLOW))
                sys.stdout.flush()
                return self.run_popen(cmd, shell=True, timeout=120)

            if tool_name == "read_file":
                filepath = tool_input["filepath"]
                mode = tool_input["mode"]
                with open(filepath, "rb") as f:
                    raw = f.read()
                if mode == "text":
                    return raw.decode("utf-8", errors="ignore")
                elif mode == "hex":
                    return raw.hex()
                else:
                    return f"<binary {len(raw)} bytes>"
            
            if tool_name == "write_file":
                content = tool_input["content"]
                extension = tool_input["extension"]
                filename = tool_input.get("filename")
                
                filepath = self.save_to_tmp(content, filename, extension)
                
                if filepath.startswith("Error"):
                    return filepath
                
                return f"✓ File saved to: {filepath}\nUse this path for further operations."
            
            if tool_name == "list_session_files":
                return self.get_session_files()

            if tool_name == "decode_base64":
                data = base64.b64decode(tool_input["data"])
                try:
                    return data.decode("utf-8")
                except Exception:
                    return data.hex()

            if tool_name == "compute_hash":
                algo = tool_input["algorithm"]
                data = tool_input["data"].encode()
                return getattr(hashlib, algo)(data).hexdigest()

            if tool_name == "nmap_scan":
                target = tool_input["target"]
                stype = tool_input["scan_type"]
                if stype == "quick":
                    cmd = ["nmap", "-F", target]
                elif stype == "full":
                    cmd = ["nmap", "-A", target]
                else:
                    cmd = ["nmap", "-sV", target]
                print(color(f"[{now_ts()}] ➜ nmap: {' '.join(cmd)}", C.YELLOW))
                sys.stdout.flush()
                return self.run_popen(cmd, shell=False, timeout=300)

            if tool_name == "strings_extract":
                filepath = tool_input["filepath"]
                min_length = str(tool_input.get("min_length", 4))
                cmd = ["strings", "-n", min_length, filepath]
                print(color(f"[{now_ts()}] ➜ strings: {' '.join(cmd)}", C.YELLOW))
                sys.stdout.flush()
                return self.run_popen(cmd, shell=False, timeout=120)

            return f"Unknown tool: {tool_name}"

        except Exception as e:
            return f"Tool error: {e}"

    def cancel_current_tool(self):
        if self._current_proc:
            try:
                self._current_proc.kill()
                self._current_proc = None
                return True
            except Exception:
                return False
        return False

# ---------- Base Agent ----------
class BaseAgent:
    """Base class for both Claude and OpenAI agents"""
    
    def __init__(self, api_provider: str, max_history=MAX_HISTORY_ENTRIES, debug: bool = False):
        self.api_provider = api_provider
        self.conversation_history = []
        self.total_api_requests = 0
        self.total_tool_calls = 0
        self.max_history = max_history
        self.debug = debug
        self.tool_executor = ToolExecutor()

    def define_tools_schema(self):
        """Return tools in provider-specific format"""
        raise NotImplementedError

    def truncate_history(self):
        if len(self.conversation_history) <= self.max_history:
            return
        self.conversation_history = self.conversation_history[-self.max_history:]

    def chat(self, user_message: str, auto_execute: bool, inline_model: Optional[str] = None, 
             max_steps: int = DEFAULT_MAX_STEPS):
        raise NotImplementedError

# ---------- Claude Agent ----------
class ClaudeAgent(BaseAgent):
    def __init__(self, api_key: str, max_history=MAX_HISTORY_ENTRIES, debug: bool = False):
        super().__init__("claude", max_history, debug)
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model_light = CLAUDE_HAIKU
        self.model_medium = CLAUDE_SONNET
        self.model_heavy = CLAUDE_OPUS

    def define_tools_schema(self):
        return [
            {"name": "execute_command", "description": "Run shell command", 
             "input_schema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}},
            {"name": "read_file", "description": "Read file contents", 
             "input_schema": {"type": "object", "properties": {"filepath": {"type": "string"}, "mode": {"type": "string", "enum": ["text", "binary", "hex"]}}, "required": ["filepath", "mode"]}},
            {"name": "write_file", "description": "Write content to a file in /tmp/. Use this to save extracted data, decoded content, scripts, or any generated files.", 
             "input_schema": {"type": "object", "properties": {"content": {"type": "string", "description": "Content to write"}, "filename": {"type": "string", "description": "Filename (optional, will auto-generate if not provided)"}, "extension": {"type": "string", "description": "File extension (e.g., txt, py, sh, bin)"}}, "required": ["content", "extension"]}},
            {"name": "list_session_files", "description": "List all files created during this session", 
             "input_schema": {"type": "object", "properties": {}, "required": []}},
            {"name": "decode_base64", "description": "Decode base64 data", 
             "input_schema": {"type": "object", "properties": {"data": {"type": "string"}}, "required": ["data"]}},
            {"name": "compute_hash", "description": "Compute hash", 
             "input_schema": {"type": "object", "properties": {"data": {"type": "string"}, "algorithm": {"type": "string", "enum": ["md5","sha1","sha256","sha512"]}}, "required": ["data","algorithm"]}},
            {"name": "nmap_scan", "description": "Run nmap", 
             "input_schema": {"type": "object", "properties": {"target": {"type": "string"}, "scan_type": {"type": "string", "enum": ["quick","full","version"]}}, "required": ["target","scan_type"]}},
            {"name": "strings_extract", "description": "Extract strings", 
             "input_schema": {"type": "object", "properties": {"filepath": {"type": "string"}, "min_length": {"type": "integer"}}, "required": ["filepath"]}},
        ]

    def pick_model(self, inline_model: Optional[str] = None) -> str:
        if inline_model:
            return inline_model
        return self.model_medium
    
    def get_model_display_name(self, model: str) -> str:
        """Get short display name for model"""
        if "opus-4" in model:
            return "opus 4.1"
        elif "sonnet-4.5" in model or "sonnet-4-5" in model:
            return "sonnet 4.5"
        elif "sonnet-4" in model:
            return "sonnet 4"
        elif "haiku" in model:
            return "haiku 3.5"
        return model  # fallback to full name

    def chat(self, user_message: str, auto_execute: bool, inline_model: Optional[str] = None, 
             max_steps: int = DEFAULT_MAX_STEPS):
        # Add session context if files exist
        session_context = self.tool_executor.get_session_context()
        if session_context:
            user_message = session_context + user_message
        
        self.conversation_history.append({"role": "user", "content": user_message})
        self.truncate_history()

        steps = 0
        thinking = ThinkingAnimation()
        
        while steps < max_steps:
            steps += 1
            model = self.pick_model(inline_model)

            try:
                self.total_api_requests += 1
                thinking.start()
                response = self.client.messages.create(
                    model=model,
                    max_tokens=4096,
                    tools=self.define_tools_schema(),
                    messages=self.conversation_history
                )
                thinking.stop()
            except KeyboardInterrupt:
                thinking.stop()
                print(color("\n⚠ Request cancelled by user.\n", C.YELLOW))
                self.conversation_history.append({"role": "user", "content": "[Request cancelled]"})
                break
            except Exception as e:
                thinking.stop()
                print(color(f"❌ API error: {e}", C.RED))
                break

            blocks = list(response.content) if hasattr(response, 'content') else []
            self.conversation_history.append({"role": "assistant", "content": blocks})
            self.truncate_history()

            tool_uses = [b for b in blocks if getattr(b, 'type', None) == 'tool_use']
            text_blocks = [getattr(b, 'text', '') for b in blocks if getattr(b, 'type', None) == 'text']

            if text_blocks:
                text = " ".join(text_blocks).strip()
                model_display = self.get_model_display_name(model)
                print(color(f"\n🤖 Claude", C.PURPLE + C.BOLD) + color(f" [{model_display}]", C.PURPLE) + color(": ", C.RESET) + highlight_flags(text) + "\n")

            if tool_uses:
                for t in tool_uses:
                    self.total_tool_calls += 1
                    t_name = getattr(t, 'name')
                    t_input = getattr(t, 'input', {})
                    t_id = getattr(t, 'id')

                    print(color(f"🔧 Tool: {t_name}", C.MAGENTA))
                    print(color(f"📝 Input: {json.dumps(t_input, indent=2)}", C.BRIGHT_BLACK))

                    result = self._execute_tool_with_confirm(t_name, t_input, auto_execute)
                    
                    preview, full_path = shorten_preview(result, 800)
                    print(color(f"✅ Result:\n{highlight_flags(preview)}\n", C.GREEN if "flag{" in result.lower() else C.CYAN))
                    if full_path:
                        print(color(f"[full output: {full_path}]", C.DIM))

                    tool_result_obj = {"type": "tool_result", "tool_use_id": t_id, 
                                      "content": [{"type": "text", "text": result}]}
                    self.conversation_history.append({"role": "user", "content": [tool_result_obj]})
                    self.truncate_history()
                continue

            print(color(f"--- Done (requests: {self.total_api_requests}, tools: {self.total_tool_calls}) ---\n", C.BRIGHT_BLACK))
            break

    def _execute_tool_with_confirm(self, tool_name: str, tool_input: dict, auto_execute: bool) -> str:
        try:
            if auto_execute:
                return self.tool_executor.execute_tool(tool_name, tool_input)
            else:
                confirm = input("Execute? (y/N): ").strip().lower()
                if confirm == "y":
                    return self.tool_executor.execute_tool(tool_name, tool_input)
                return "Tool execution declined."
        except KeyboardInterrupt:
            return "Tool execution cancelled."

# ---------- OpenAI Agent ----------
class OpenAIAgent(BaseAgent):
    def __init__(self, api_key: str, max_history=MAX_HISTORY_ENTRIES, debug: bool = False):
        super().__init__("openai", max_history, debug)
        self.client = openai.OpenAI(api_key=api_key)
        self.model_light = GPT35_TURBO
        self.model_medium = GPT4
        self.model_heavy = GPT4_TURBO

    def define_tools_schema(self):
        return [
            {
                "type": "function",
                "function": {
                    "name": "execute_command",
                    "description": "Run shell command on Kali system",
                    "parameters": {
                        "type": "object",
                        "properties": {"command": {"type": "string", "description": "Shell command to execute"}},
                        "required": ["command"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read file contents",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "filepath": {"type": "string"},
                            "mode": {"type": "string", "enum": ["text", "binary", "hex"], "default": "text"}
                        },
                        "required": ["filepath", "mode"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "write_file",
                    "description": "Write content to a file in /tmp/. Use this to save extracted data, decoded content, scripts, or any generated files.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "content": {"type": "string", "description": "Content to write"},
                            "filename": {"type": "string", "description": "Filename (optional, will auto-generate)"},
                            "extension": {"type": "string", "description": "File extension (txt, py, sh, bin, etc.)"}
                        },
                        "required": ["content", "extension"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "list_session_files",
                    "description": "List all files created during this session",
                    "parameters": {
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "decode_base64",
                    "description": "Decode base64 data",
                    "parameters": {
                        "type": "object",
                        "properties": {"data": {"type": "string"}},
                        "required": ["data"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "compute_hash",
                    "description": "Compute cryptographic hash",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "data": {"type": "string"},
                            "algorithm": {"type": "string", "enum": ["md5","sha1","sha256","sha512"]}
                        },
                        "required": ["data", "algorithm"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "nmap_scan",
                    "description": "Run nmap port scan",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string"},
                            "scan_type": {"type": "string", "enum": ["quick","full","version"]}
                        },
                        "required": ["target", "scan_type"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "strings_extract",
                    "description": "Extract strings from binary",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "filepath": {"type": "string"},
                            "min_length": {"type": "integer", "default": 4}
                        },
                        "required": ["filepath"]
                    }
                }
            }
        ]

    def pick_model(self, inline_model: Optional[str] = None) -> str:
        if inline_model:
            return inline_model
        return self.model_medium
    
    def get_model_display_name(self, model: str) -> str:
        """Get short display name for model"""
        if "gpt-4-turbo" in model.lower():
            return "gpt-4 turbo"
        elif "gpt-4" in model.lower():
            return "gpt-4"
        elif "gpt-3.5" in model.lower():
            return "gpt-3.5"
        return model  # fallback to full name

    def chat(self, user_message: str, auto_execute: bool, inline_model: Optional[str] = None, 
             max_steps: int = DEFAULT_MAX_STEPS):
        # Add session context if files exist
        session_context = self.tool_executor.get_session_context()
        if session_context:
            user_message = session_context + user_message
        
        self.conversation_history.append({"role": "user", "content": user_message})
        self.truncate_history()

        steps = 0
        thinking = ThinkingAnimation()
        
        while steps < max_steps:
            steps += 1
            model = self.pick_model(inline_model)

            try:
                self.total_api_requests += 1
                thinking.start()
                response = self.client.chat.completions.create(
                    model=model,
                    messages=self.conversation_history,
                    tools=self.define_tools_schema(),
                    tool_choice="auto"
                )
                thinking.stop()
            except KeyboardInterrupt:
                thinking.stop()
                print(color("\n⚠ Request cancelled by user.\n", C.YELLOW))
                self.conversation_history.append({"role": "user", "content": "[Request cancelled]"})
                break
            except Exception as e:
                thinking.stop()
                print(color(f"❌ API error: {e}", C.RED))
                break

            message = response.choices[0].message
            
            # Clean up any invalid function names before adding to history
            if message.tool_calls:
                for tool_call in message.tool_calls:
                    # Fix invalid function names (e.g., "functions.read_file" -> "read_file")
                    if '.' in tool_call.function.name:
                        tool_call.function.name = tool_call.function.name.split('.')[-1]
            
            self.conversation_history.append(message.model_dump())
            self.truncate_history()

            # Always show text content first if present, OR show generic message if going straight to tools
            if message.content:
                model_display = self.get_model_display_name(model)
                print(color(f"\n🤖 ChatGPT", C.PURPLE + C.BOLD) + color(f" [{model_display}]", C.PURPLE) + color(": ", C.RESET) + highlight_flags(message.content) + "\n")
            elif message.tool_calls:
                # If no text but has tool calls, print a blank line for spacing
                print()

            if message.tool_calls:
                for tool_call in message.tool_calls:
                    self.total_tool_calls += 1
                    func_name = tool_call.function.name
                    
                    # Clean function name if it has invalid characters
                    if '.' in func_name:
                        func_name = func_name.split('.')[-1]
                    
                    # Handle potential JSON parsing errors in arguments
                    try:
                        func_args = json.loads(tool_call.function.arguments)
                    except json.JSONDecodeError as e:
                        print(color(f"⚠ JSON parsing error in tool arguments: {e}", C.YELLOW))
                        print(color(f"Raw arguments: {tool_call.function.arguments[:200]}", C.BRIGHT_BLACK))
                        # Try to continue with empty args
                        func_args = {}

                    print(color(f"🔧 Tool: {func_name}", C.MAGENTA))
                    print(color(f"📝 Input: {json.dumps(func_args, indent=2)}", C.BRIGHT_BLACK))

                    result = self._execute_tool_with_confirm(func_name, func_args, auto_execute)
                    
                    preview, full_path = shorten_preview(result, 800)
                    print(color(f"✅ Result:\n{highlight_flags(preview)}\n", C.GREEN if "flag{" in result.lower() else C.CYAN))
                    if full_path:
                        print(color(f"[full output: {full_path}]", C.DIM))

                    self.conversation_history.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "name": func_name,
                        "content": result
                    })
                    self.truncate_history()
                continue

            print(color(f"--- Done (requests: {self.total_api_requests}, tools: {self.total_tool_calls}) ---\n", C.BRIGHT_BLACK))
            break

    def _execute_tool_with_confirm(self, tool_name: str, tool_input: dict, auto_execute: bool) -> str:
        try:
            if auto_execute:
                return self.tool_executor.execute_tool(tool_name, tool_input)
            else:
                confirm = input("Execute? (y/N): ").strip().lower()
                if confirm == "y":
                    return self.tool_executor.execute_tool(tool_name, tool_input)
                return "Tool execution declined."
        except KeyboardInterrupt:
            return "Tool execution cancelled."

# ---------- Banner / Prompt / Readline ----------
def print_banner(api_provider: str, default_auto_exec: bool, default_max_steps: int):
    # ASCII Art Banner
    print(color("""
 ██████╗ ██████╗ ███████╗██████╗  █████╗ ████████╗██╗██╗   ██╗███████╗
██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██║██║   ██║██╔════╝
██║   ██║██████╔╝█████╗  ██████╔╝███████║   ██║   ██║██║   ██║█████╗  
██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗██╔══██║   ██║   ██║╚██╗ ██╔╝██╔══╝  
╚██████╔╝██║     ███████╗██║  ██║██║  ██║   ██║   ██║ ╚████╔╝ ███████╗
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝  ╚══════╝
    """, C.MAGENTA + C.BOLD))
    
    print(color("┌─────────────────────────────────────────────────────────────────────────────┐", C.CYAN))
    print(color("│  🎯 Operative - AI-Powered CTF & Security Analysis Agent                    │", C.CYAN + C.BOLD))
    print(color("│  ⚡ Multi-Model Support | Tool Execution | Automated Recon                  │", C.CYAN))
    print(color("│  🔥 CTF Challenges | Penetration Testing | Security Research                │", C.CYAN))
    print(color("└─────────────────────────────────────────────────────────────────────────────┘", C.CYAN))
    
    # Configuration Box
    if api_provider == "claude":
        active_api = "Claude"
        provider_name = "Anthropic"
        model_color = C.GREEN
    else:
        active_api = "ChatGPT"
        provider_name = "OpenAI"
        model_color = C.GREEN
    
    box_width = 79
    inner_width = box_width - 2
    box_top = "╭" + "─" * (box_width - 2) + "╮"
    box_mid = "├" + "─" * (box_width - 2) + "┤"
    box_bottom = "╰" + "─" * (box_width - 2) + "╯"

    def box_line(parts: List[Tuple[str, Optional[str]]]) -> str:
        raw_text = "".join(text for text, _ in parts)
        padding = inner_width - display_width(raw_text)
        if padding < 0:
            padding = 0
        colored_segments = "".join(color(text, col) if col else text for text, col in parts)
        return (
            color("│", C.ORANGE)
            + colored_segments
            + color(" " * padding, C.ORANGE)
            + color("│", C.ORANGE)
        )

    print(color(f"\n{box_top}", C.ORANGE))
    print(box_line([
        (" ", C.ORANGE),
        ("⚙  Configuration", C.ORANGE + C.BOLD),
    ]))
    print(color(box_mid, C.ORANGE))

    if default_auto_exec:
        autoexec_text = "✓ Enabled"
        autoexec_color = C.GREEN + C.BOLD
    else:
        autoexec_text = "✗ Disabled"
        autoexec_color = C.RED + C.BOLD
    steps_str = str(default_max_steps)

    print(box_line([
        (" ", C.ORANGE),
        ("🔌 Active API:", C.ORANGE),
        (" ", C.ORANGE),
        (active_api, C.GREEN + C.BOLD),
    ]))
    print(box_line([
        (" ", C.ORANGE),
        ("🤖 Provider:", C.ORANGE),
        (" ", C.ORANGE),
        (provider_name, C.GREEN + C.BOLD),
    ]))
    print(box_line([
        (" ", C.ORANGE),
        ("⚡ Auto-Execute:", C.ORANGE),
        (" ", C.ORANGE),
        (autoexec_text, autoexec_color),
    ]))
    print(box_line([
        (" ", C.ORANGE),
        ("📊 Max Steps:", C.ORANGE),
        (" ", C.ORANGE),
        (steps_str, C.GREEN + C.BOLD),
    ]))

    print(color(box_mid, C.ORANGE))
    print(box_line([
        (" ", C.ORANGE),
        ("📋 Available Models:", C.ORANGE + C.BOLD),
    ]))

    if api_provider == "claude":
        models = [
            ("Claude Opus 4.1", "(Heavy)"),
            ("Claude Sonnet 4.5", "(Medium)"),
            ("Claude Haiku 3.5", "(Light)"),
        ]
    else:
        models = [
            ("GPT-4 Turbo", "(Heavy)"),
            ("GPT-4", "(Medium)"),
            ("GPT-3.5 Turbo", "(Light)"),
        ]

    for model_name, model_type in models:
        print(box_line([
            (" ", C.ORANGE),
            (f"  • {model_name}", model_color),
            (" ", C.ORANGE),
            (model_type, C.BRIGHT_BLACK),
        ]))

    print(color(box_bottom, C.ORANGE))
    
    # Quick Help
    print(color("\n💡 Quick Help:", C.BLUE + C.BOLD))
    print(f"  Type natural language commands to interact with the agent")
    print(f"  Use {color('python3 operatives.py -h', C.YELLOW)} for detailed help")
    print(f"  In-session: type {color(':help', C.CYAN)} or {color('--help', C.CYAN)} to see inline flags and examples")
    print(f"  Commands: {color(':reset', C.CYAN)} (clear) | {color(':files', C.CYAN)} (list files) | {color(':cancel', C.CYAN)} (kill) | {color('quit', C.CYAN)} (exit)")
    print()

def setup_readline():
    if readline is None:
        return
    try:
        readline.set_history_length(1000)
        if os.path.exists(HISTORY_FILE):
            readline.read_history_file(HISTORY_FILE)
    except Exception:
        pass

def save_history():
    if readline:
        try:
            readline.write_history_file(HISTORY_FILE)
        except Exception:
            pass

def prompt_string() -> str:
    whoami = getpass.getuser()
    return color(f"👾 Operator", C.CYAN + C.BOLD) + color(f" [{whoami}]", C.MUTED_BLUE) + color(": ", C.RESET)

# ---------- Thinking Animation ----------
class ThinkingAnimation:
    """Animated thinking indicator"""
    def __init__(self):
        self.running = False
        self.thread = None
        self.frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.current_frame = 0
    
    def _animate(self):
        while self.running:
            frame = self.frames[self.current_frame % len(self.frames)]
            sys.stdout.write(f"\r{color(f'{frame} thinking...', C.YELLOW)}")
            sys.stdout.flush()
            self.current_frame += 1
            time.sleep(0.1)
    
    def start(self):
        if not self.running:
            self.running = True
            self.current_frame = 0
            self.thread = threading.Thread(target=self._animate, daemon=True)
            self.thread.start()
    
    def stop(self):
        if self.running:
            self.running = False
            if self.thread:
                self.thread.join(timeout=0.5)
            # Clear the thinking line
            sys.stdout.write("\r" + " " * 20 + "\r")
            sys.stdout.flush()

def print_session_help():
    """Print colorful help banner during session"""
    print(color("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", C.CYAN))
    print(color("                           💡 OPERATIVE HELP", C.CYAN + C.BOLD))
    print(color("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", C.CYAN))
    
    print(color("\n🔧 INLINE FLAGS", C.YELLOW + C.BOLD))
    print(color("  Use these in your messages to override settings:\n", C.BRIGHT_BLACK))
    print(color("  --model=MODEL", C.GREEN) + "           Force specific model")
    print(color("                          ", C.BRIGHT_BLACK) + "Examples: light, medium, heavy, gpt4, sonnet, opus")
    print(color("\n  --auto-execute=BOOL", C.GREEN) + "     Override auto-execute for this message")
    print(color("                          ", C.BRIGHT_BLACK) + "Values: true, false")
    print(color("\n  --max-steps=N", C.GREEN) + "           Limit conversation steps")
    print(color("                          ", C.BRIGHT_BLACK) + "Example: --max-steps=20")
    
    print(color("\n📝 USAGE EXAMPLES", C.MAGENTA + C.BOLD))
    print(color("  Scan 10.10.10.5 --model=light", C.BRIGHT_BLACK))
    print(color("  Read /etc/passwd --auto-execute=false", C.BRIGHT_BLACK))
    print(color("  Analyze binary --model=heavy --max-steps=30", C.BRIGHT_BLACK))
    print(color("  Quick recon --model=gpt3", C.BRIGHT_BLACK))
    
    print(color("\n⌨  SESSION COMMANDS", C.BLUE + C.BOLD))
    print(color("  :reset  ", C.CYAN) + "  Clear conversation history (fresh context)")
    print(color("  :files  ", C.CYAN) + "  List files created in this session")
    print(color("  :cancel ", C.CYAN) + "  Kill currently running tool/process")
    print(color("  :help   ", C.CYAN) + "  Show this help message")
    print(color("  quit    ", C.CYAN) + "  Exit the agent")
    
    print(color("\n🛠  AVAILABLE TOOLS", C.RED + C.BOLD))
    print(color("  • execute_command     ", C.YELLOW) + "Run shell commands")
    print(color("  • read_file           ", C.YELLOW) + "Read files (text/hex/binary)")
    print(color("  • write_file          ", C.YELLOW) + "Save content to /tmp/ (auto-tracked)")
    print(color("  • list_session_files  ", C.YELLOW) + "Show files created this session")
    print(color("  • decode_base64       ", C.YELLOW) + "Decode base64 data")
    print(color("  • compute_hash        ", C.YELLOW) + "Calculate MD5/SHA1/SHA256/SHA512")
    print(color("  • nmap_scan           ", C.YELLOW) + "Port scanning (quick/full/version)")
    print(color("  • strings_extract     ", C.YELLOW) + "Extract strings from binaries")
    
    print(color("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", C.CYAN))

# ---------- Main ----------
def main():
    parser = argparse.ArgumentParser(
        description="🎯 Operative - AI-Powered CTF & Security Analysis Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                           💡 USAGE EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🚀 Starting the Agent:

  # Start with Claude (default)
  python3 operatives.py
  
  # Start with OpenAI
  python3 operatives.py --api=openai
  
  # Disable auto-execute for safety
  python3 operatives.py --auto-execute=false
  
  # Custom max steps
  python3 operatives.py --api=claude --max-steps=25

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                        🔧 INLINE FLAGS (During Chat)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Use these flags in your messages to override settings per-request:

  --model=MODEL           Force specific model
                          Examples: light, medium, heavy, gpt4, sonnet, opus
  
  --auto-execute=BOOL     Override auto-execute for this message
                          Values: true, false
  
  --max-steps=N           Limit conversation steps for this request
                          Example: --max-steps=20

Chat Examples:

  👾 Operator Scan 10.10.10.5 --model=light
  
  👾 Operator Read /etc/passwd --auto-execute=false
  
  👾 Operator Deep analysis of this binary --model=heavy --max-steps=30
  
  👾 Operator Quick recon --model=gpt3

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                          ⌨  SESSION COMMANDS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  :reset     Clear conversation history (fresh context)
  :cancel    Kill currently running tool/process
  quit       Exit the agent

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                        🔑 ENVIRONMENT VARIABLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Required (based on API choice):

  ANTHROPIC_API_KEY      For Claude API access
  OPENAI_API_KEY         For ChatGPT API access

Setup:
  export ANTHROPIC_API_KEY="sk-ant-api03-..."
  export OPENAI_API_KEY="sk-..."

You only need the key for the API you intend to use.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                           🛠  AVAILABLE TOOLS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  • execute_command      Run shell commands
  • read_file            Read files (text/hex/binary)
  • decode_base64        Decode base64 data
  • compute_hash         Calculate MD5/SHA1/SHA256/SHA512
  • nmap_scan            Port scanning (quick/full/version)
  • strings_extract      Extract strings from binaries

The AI will automatically choose and execute tools based on your requests.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """
    )
    parser.add_argument("--api", type=str, default="claude", choices=["claude", "openai"], 
                       help="API provider to use (default: claude)")
    parser.add_argument("--auto-execute", type=str, default="true", 
                       help="Auto-execute tools by default (true|false, default: true)")
    parser.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS, 
                       help=f"Default max steps per request (default: {DEFAULT_MAX_STEPS})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    api_provider = args.api.lower()
    default_auto_exec = args.auto_execute.lower() == "true"
    default_max_steps = max(1, args.max_steps)

    # Check API availability and get key
    if api_provider == "claude":
        if not ANTHROPIC_AVAILABLE:
            print(color("❌ Anthropic SDK not installed. Run: pip install anthropic", C.RED))
            return
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            print(color("❌ Missing ANTHROPIC_API_KEY environment variable", C.RED))
            return
        agent = ClaudeAgent(api_key, debug=args.debug)
        
        # Set generic aliases to Claude models
        MODEL_ALIASES["light"] = CLAUDE_HAIKU
        MODEL_ALIASES["medium"] = CLAUDE_SONNET
        MODEL_ALIASES["heavy"] = CLAUDE_OPUS
    else:
        if not OPENAI_AVAILABLE:
            print(color("❌ OpenAI SDK not installed. Run: pip install openai", C.RED))
            return
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            print(color("❌ Missing OPENAI_API_KEY environment variable", C.RED))
            return
        agent = OpenAIAgent(api_key, debug=args.debug)
        
        # Set generic aliases to OpenAI models
        MODEL_ALIASES["light"] = GPT35_TURBO
        MODEL_ALIASES["medium"] = GPT4
        MODEL_ALIASES["heavy"] = GPT4_TURBO

    setup_readline()
    print_banner(api_provider, default_auto_exec, default_max_steps)

    try:
        while True:
            try:
                raw = input(prompt_string())
            except (KeyboardInterrupt, EOFError):
                print("\nInterrupted. Type :reset to clear history or continue.")
                continue

            if not raw:
                continue

            raw_strip = raw.strip()

            # special in-session commands
            if raw_strip.lower() in (":reset", "reset", "clear-history"):
                agent.conversation_history = []
                print(color("⚡ History cleared", C.YELLOW))
                continue

            if raw_strip.lower() in (":help", "-h", "--help", "help"):
                print_session_help()
                continue
            
            if raw_strip.lower() in (":files", ":ls", "ls"):
                print(color(agent.tool_executor.get_session_files(), C.CYAN))
                continue

            if raw_strip.lower() == ":cancel":
                if agent.tool_executor.cancel_current_tool():
                    print(color("⚡ Tool cancelled", C.YELLOW))
                else:
                    print(color("⚠ No running tool", C.YELLOW))
                continue

            if raw_strip.lower() in ("quit", "exit", "q"):
                print(f"\nSession summary:")
                print(f"  API requests: {agent.total_api_requests}")
                print(f"  Tool calls:   {agent.total_tool_calls}")
                break

            message, auto_exec, inline_model_raw, max_steps = parse_inline_flags(
                raw, default_auto_exec, default_max_steps
            )

            inline_model = None
            if inline_model_raw:
                low = inline_model_raw.lower()
                if low in MODEL_ALIASES:
                    inline_model = MODEL_ALIASES[low]
                elif inline_model_raw in (CLAUDE_MODELS if api_provider == "claude" else OPENAI_MODELS):
                    inline_model = inline_model_raw
                else:
                    print(color(f"⚠ Unknown model '{inline_model_raw}'", C.YELLOW))

            agent.chat(message, auto_execute=auto_exec, inline_model=inline_model, 
                      max_steps=max_steps)
            save_history()

    finally:
        save_history()

if __name__ == "__main__":
    main()
            

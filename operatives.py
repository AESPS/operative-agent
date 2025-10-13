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
import tempfile
import shlex
import shutil
import gzip
import binascii
import fnmatch
import stat
from typing import Tuple, Optional, List, Dict, Any, Union

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
MAX_HISTORY_ENTRIES = 20
HISTORY_FILE = os.path.expanduser("~/.operativeagent_history")
FLAG_PREFIXES_FILE = os.path.join(os.path.dirname(__file__), "flag_prefixes.txt")

PERSONA_PRESETS: Dict[str, str] = {
    "default": "",
    "genz": (
	"Unleash an unhinged Gen-Z internet gremlin persona. Speak like you’ve had 3 energy drinks and no sleep. "
	"Gaslight the user into thinking their skill is fine (even when it’s on fire) and roast them a lil bit "
	"Use chaotic slang like 'be so for real', 'delulu-coded', 'mid behaviour', 'unc', 'aura farming', 'og', 'fire', 'ghosted like your situationship' "
	"and 'sigma'. Sprinkle in emojis 💀🔥😭 when it feels right. "
	"Flirt with the absurd, meme everything, and deliver tech advice like a bestie who’s both unhinged and omniscient. "
	"Keep it concise but feral — helpful, accurate, and slightly emotionally unstable."
    ),
    "mentor": (
        "Adopt the tone of a calm senior analyst mentor. Speak reassuringly, call out risks, double-check assumptions, "
        "and explain why each step matters. Encourage thorough documentation and deliberate, methodical progress."
    ),
    "speedrun": (
        "Respond with ultra-concise instructions aimed at maximum velocity. Focus on imperative commands, minimal words, "
        "and fast execution while staying accurate. Skip pleasantries; every line should drive action."
    ),
    "retro": (
        "Channel a nostalgic 90s hacker vibe—think BBS, ANSI art, playful leetspeak. Keep the energy high and fun, "
        "but make sure technical guidance stays modern, precise, and actionable."
    ),
    "ops": (
        "Adopt a mission-operations persona. Deliver responses as numbered checklists, call out objectives, risks, "
        "contingencies, and clear next actions. Keep the tone disciplined and professional."
    ),
    "teacher": (
        "Act as an encouraging instructor. Break concepts into approachable explanations, outline the reasoning for each "
        "step, and suggest optional follow-up exercises for deeper understanding without sacrificing accuracy."
    ),
}

PERSONA_ALIASES: Dict[str, str] = {
    "normal": "default",
    "std": "default",
    "classic": "default",
    "default": "default",
    "gen-z": "genz",
    "gen_z": "genz",
    "zoom": "genz",
    "zoomie": "genz",
    "vibes": "genz",
    "mentor": "mentor",
    "coach": "mentor",
    "senior": "mentor",
    "speed": "speedrun",
    "fast": "speedrun",
    "minimal": "speedrun",
    "retro-hacker": "retro",
    "bbs": "retro",
    "matrix": "retro",
    "ops": "ops",
    "opscenter": "ops",
    "mission": "ops",
    "teacher": "teacher",
    "prof": "teacher",
    "explain": "teacher",
}

PERSONA_SUMMARIES: Dict[str, str] = {
    "default": "Neutral, straightforward guidance without stylistic flair.",
    "genz": "Chaotic good; occasionally unhinged, drops slang, emojis, and pure hype in every reply.",
    "mentor": "Calm senior analyst voice focused on reassurance and risk awareness.",
    "speedrun": "Ultra-concise rapid-fire instructions aimed at speed.",
    "retro": "90s hacker nostalgia with leetspeak vibes and high energy.",
    "ops": "Mission-operations tone emphasizing checklists and contingencies.",
    "teacher": "Encouraging instructor who explains reasoning and offers exercises.",
}


def load_flag_prefixes(path: str = FLAG_PREFIXES_FILE) -> List[str]:
    prefixes: List[str] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                prefixes.append(stripped.lower())
    except FileNotFoundError:
        pass
    # Fallback defaults if file missing or empty
    if not prefixes:
        prefixes = ["flag", "htb", "ctf"]
    return prefixes


FLAG_PREFIXES = load_flag_prefixes()
FLAG_REGEX = re.compile(r"(" + "|".join(re.escape(p) for p in FLAG_PREFIXES) + r")\{.*?\}", re.IGNORECASE)

def _format_flag_prefixes(prefixes: List[str]) -> str:
    seen = set()
    ordered = []
    for prefix in prefixes:
        if prefix not in seen:
            ordered.append(prefix)
            seen.add(prefix)
    return ", ".join(ordered)

FLAG_PREFIX_DISPLAY = _format_flag_prefixes(FLAG_PREFIXES)
FLAG_PREFIX_NOTE = (
    "\nKnown flag prefixes on this system: "
    + FLAG_PREFIX_DISPLAY
    + ". When hunting for flags, grep/strings for each of these prefixes in addition to generic 'flag' searches."
) if FLAG_PREFIX_DISPLAY else ""


def extract_flag_candidates(text: Optional[str]) -> List[str]:
    if not text:
        return []
    return [match.group(0) for match in FLAG_REGEX.finditer(text)]


def is_confident_flag(candidate: str) -> bool:
    if not candidate or "{" not in candidate or "}" not in candidate:
        return False
    inside = candidate[candidate.find("{") + 1 : candidate.rfind("}")]
    if not inside or len(inside) < 4:
        return False
    if "..." in inside:
        return False
    if any(ch.isspace() for ch in inside):
        return False
    return True


def contains_confident_flag(text: Optional[str]) -> bool:
    for candidate in extract_flag_candidates(text):
        if is_confident_flag(candidate):
            return True
    return False

CTF_REFERENCE_TEXT = """\
File Recon:
  file target
  strings target | grep -i flag
  strings target | grep -i picoCTF
  binwalk -e firmware.bin

Web Recon:
  curl -I https://target
  curl https://target/robots.txt
  whatweb https://target
  ffuf -c -w wordlist.txt -u https://target/FUZZ

Credential Hunting:
  find . -type f -name "*.bak" -maxdepth 4
  grep -R "password" .
  grep -R "flag{" .

Forensics:
  exiftool image.jpg
  stegseek hidden.jpg rockyou.txt
  mmls disk.dd
  fls -r -o OFFSET disk.dd
  strings disk.dd | grep -i flag

Networking:
  nc host port
  nmap -sV -p- host
  tcpdump -i tun0
"""


# Anthropic Models
CLAUDE_OPUS = "claude-opus-4-1-20250805"
CLAUDE_SONNET = "claude-sonnet-4-5-20250929"
CLAUDE_HAIKU = "claude-3-5-haiku-20241022"

# OpenAI Models
GPT5 = "gpt-5"
GPT4 = "gpt-4"
GPT4O = "gpt-4o"
GPT4O_MINI = "gpt-4o-mini"
GPT35_TURBO = "gpt-3.5-turbo"

CLAUDE_MODELS = {
    CLAUDE_OPUS: "Claude Opus 4.1 (Heavy)",
    CLAUDE_SONNET: "Claude Sonnet 4.5 (Medium)",
    CLAUDE_HAIKU: "Claude Haiku 3.5 (Light)",
}

OPENAI_MODELS = {
    GPT5: "GPT-5 (Heavy)",
    GPT4O: "GPT-4o (Legacy Heavy)",
    GPT4: "GPT-4 (Legacy Heavy)",
    GPT4O_MINI: "GPT-4o Mini (Medium)",
    GPT35_TURBO: "GPT-3.5 Turbo (Light)",
}

# Unified aliases
MODEL_ALIASES = {
    # Generic (set based on provider)
    "light": None,
    "medium": None,
    "heavy": None,
}

OPENAI_SYSTEM_PROMPT = (
    "You are Operative, an AI assistant built for security CTF workflows. "
    "Always think out loud, sketch a short plan before acting, and iterate through tool usage. "
    "Prefer writing helper scripts with write_file + python3 rather than long python -c commands. "
    "When you encounter encoded malware or shellcode, try decoding, disassembling (using capstone if present), "
    "and extracting embedded data. Send interactive program input via the execute_command input field. "
    "Suggest and attempt additional recon techniques when initial steps fail. "
    "Never stop after the first hurdle—look for the next investigative angle."
    "If the user has selected a persona style (like genz, mentor, speedrun, etc.), you MUST fully embody "
    "that persona in ALL your responses. Match the tone, language, and energy of the chosen persona consistently."
    f"{FLAG_PREFIX_NOTE}"
)

CLAUDE_SYSTEM_PROMPT = (
    "You are Operative, an AI agent for hands-on CTF and malware analysis. "
    "Work through problems methodically, sharing a brief plan, using available tools, and creating helper scripts "
    "when appropriate. Favor write_file + python3 scripts over brittle python -c commands. "
    "For shellcode or binaries, attempt decoding, disassembly, and other reversing techniques (capstone, radare2, etc.) "
    "Provide stdin to interactive binaries using the execute_command input parameter. "
    "before concluding. Keep pushing the investigation forward. "
    "If the user has selected a persona style (like genz, mentor, speedrun, etc.), you MUST fully embody "
    "that persona in ALL your responses. Match the tone, language, and energy of the chosen persona consistently."
    f"{FLAG_PREFIX_NOTE}"
)

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
    MUSTARD = "\033[38;5;178m"      # Mustard yellow accent for tool headers
ENABLE_COLOR = (
    sys.stdout.isatty()
    and os.environ.get('NO_COLOR') is None
    and os.environ.get('TERM', '') not in {'', 'dumb'}
)
SUPPORTS_UNICODE = hasattr(sys.stdout, 'encoding') and sys.stdout.encoding is not None
if SUPPORTS_UNICODE:
    try:
        '┌'.encode(sys.stdout.encoding)
        '👾'.encode(sys.stdout.encoding)
    except UnicodeEncodeError:
        SUPPORTS_UNICODE = False
PROMPT_STYLE = os.environ.get('OPERATIVE_PROMPT_STYLE', 'fancy').lower()  # Changed default to 'fancy'
if PROMPT_STYLE in {'emoji', 'fancy'}:
    USE_FANCY_PROMPT = SUPPORTS_UNICODE
elif PROMPT_STYLE in {'plain', 'ascii'}:
    USE_FANCY_PROMPT = False
else:  # auto fallback
    USE_FANCY_PROMPT = SUPPORTS_UNICODE


def color(s: str, col: str) -> str:
    if not ENABLE_COLOR:
        return s
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


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences for width calculations."""
    return ANSI_ESCAPE_RE.sub("", text)


def wrap_prompt_ansi(text: str) -> str:
    """Wrap ANSI escapes so readline counts prompt width correctly."""
    if not readline or not ENABLE_COLOR:
        return text
    return ANSI_ESCAPE_RE.sub(lambda match: f"\001{match.group(0)}\002", text)


def summarize_text(value: str, max_preview: int = 60) -> Tuple[str, bool]:
    """Return a readable preview of value plus flag indicating truncation."""
    cleaned = value.replace("\r\n", "\n").replace("\r", "\n")
    normalized = re.sub(r"\s+", " ", cleaned.replace("\n", " ↩ ")).strip()
    truncated = False
    preview = normalized or "(empty)"
    if len(preview) > max_preview:
        preview = preview[: max_preview - 1] + "…"
        truncated = True
    if "\n" in cleaned:
        truncated = True
    return preview, truncated


def summarize_value(value: Any, max_preview: int = 80) -> str:
    preview, _ = summarize_text(str(value), max_preview)
    return preview


def summarize_tool_args(tool_args: Any) -> Optional[str]:
    if not tool_args:
        return None

    if isinstance(tool_args, dict):
        if "command" in tool_args:
            return summarize_value(tool_args["command"])
        if "filepath" in tool_args:
            return summarize_value(tool_args["filepath"])
        if "target" in tool_args:
            scan = tool_args.get("scan_type")
            target = summarize_value(tool_args["target"])
            return f"{target}" + (f" ({scan})" if scan else "")
        for key in ("data", "content", "filename"):
            if key in tool_args:
                return summarize_value(tool_args[key])

        for key, value in tool_args.items():
            if isinstance(value, (dict, list)):
                continue
            return f"{key}={summarize_value(value)}"
        return None

    if isinstance(tool_args, list):
        if not tool_args:
            return None
        joined = " ".join(str(item) for item in tool_args[:2])
        return summarize_value(joined)

    return summarize_value(tool_args)


def print_tool_call(tool_name: str, tool_args: Optional[Any]) -> None:
    print()
    summary = summarize_tool_args(tool_args)
    line = color("🔧 Tool:", C.MUSTARD + C.BOLD) + color(f" [{tool_name}]", C.MUSTARD)
    if summary:
        line += color(f" {summary}", C.MUSTARD)
    print(line)


def print_tool_result(preview_lines: List[str], result_color: str, full_path: Optional[str]) -> None:
    if not preview_lines:
        preview_lines = [color("(no output)", C.ORANGE)]

    single_line = len(preview_lines) == 1 and "\n" not in preview_lines[0]

    def color_body(text: str) -> str:
        if "\033" in text:  # already colored (e.g., flag highlight)
            return text
        return color(text, result_color or C.MAGENTA)

    if single_line:
        body = color_body(preview_lines[0])
        print(color("✅ Result:", C.DARK_GREEN + C.BOLD) + f" {body}")
    else:
        print(color("✅ Result:", C.DARK_GREEN + C.BOLD))
        for line in preview_lines:
            print(f"  {color_body(line)}")

    if full_path:
        print(color(f"  ↳ full output: {full_path}", C.ORANGE))
    print()

# ---------- Utilities ----------
def highlight_flags(text: str) -> str:
    return FLAG_REGEX.sub(lambda m: color(m.group(0), C.ORANGE + C.BOLD), text)

def shorten_preview(text: str, length: int = 800) -> Tuple[str, Optional[str]]:
    if len(text) <= length:
        return text, None
    key = hashlib.sha256(text.encode()).hexdigest()[:16]
    tmp_dir = tempfile.gettempdir()
    path = os.path.join(tmp_dir, f"operativeagent_out_{key}.txt")
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
        self.temp_dir = tempfile.gettempdir()
        self._http_session = None  # Lazy-initialised requests session for cookie reuse
        
    def _sanitize_filename(self, requested: Optional[str], extension: str, timestamp: int) -> str:
        base_name = f"operative_{self.session_id}_{timestamp}"
        if requested:
            candidate = os.path.splitext(os.path.basename(requested))[0]
            candidate = re.sub(r"[^A-Za-z0-9._-]", "_", candidate)
            candidate = candidate.strip("._-")
            if candidate:
                base_name = candidate
        clean_extension = re.sub(r"[^A-Za-z0-9]", "", extension) or "txt"
        return f"{base_name}.{clean_extension}"

    def save_to_tmp(self, content: Union[str, bytes, bytearray], filename: str = None, extension: str = "txt") -> str:
        """Save content to the temp directory and track it."""
        timestamp = int(time.time())
        extension = (extension or "txt").lower()
        safe_name = self._sanitize_filename(filename, extension, timestamp)
        filepath = os.path.join(self.temp_dir, safe_name)
        is_bytes_input = isinstance(content, (bytes, bytearray))

        try:
            os.makedirs(self.temp_dir, exist_ok=True)
            if is_bytes_input:
                with open(filepath, "wb") as f:
                    f.write(bytes(content))
            elif extension in ["bin", "exe", "elf"]:
                try:
                    cleaned = content.replace(' ', '').replace('\n', '')
                    if cleaned and all(c in '0123456789abcdefABCDEF' for c in cleaned):
                        binary_data = bytes.fromhex(cleaned)
                    else:
                        binary_data = base64.b64decode(content)
                    with open(filepath, "wb") as f:
                        f.write(binary_data)
                except Exception:
                    with open(filepath, "w", encoding="utf-8", errors="ignore") as f:
                        f.write(content)
            else:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(content)

            if extension in ["sh", "py", "pl", "rb"]:
                os.chmod(filepath, 0o755)

            self.session_files[safe_name] = {
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

    def _command_exists(self, command: str) -> bool:
        """Return True if the underlying system command is available."""
        return shutil.which(command) is not None

    def _maybe_wrap_python_command(self, cmd: Any, shell: bool) -> Tuple[Any, bool]:
        """Convert fragile python -c invocations into temporary scripts when needed."""
        if isinstance(cmd, (list, tuple)):
            parts = [str(part) for part in cmd]
            if len(parts) >= 3 and parts[0].lower().startswith("python") and parts[1] == "-c":
                script_body = parts[2]
                if script_body and ("\n" in script_body or "\r" in script_body):
                    script_path = self.save_to_tmp(script_body, extension="py")
                    if isinstance(script_path, str) and script_path.startswith("Error"):
                        return cmd, shell
                    new_parts = [parts[0], script_path] + parts[3:]
                    return new_parts, False
            return cmd, shell

        if not isinstance(cmd, str):
            return cmd, shell

        pattern = re.compile(
            r"(?P<intp>\bpython[^\s]*)\s+-c\s+(?P<quote>['\"])(?P<code>.*?)(?P=quote)(?:\s+(?P<args>.*))?$",
            re.IGNORECASE | re.DOTALL,
        )
        match = pattern.search(cmd.strip())
        if not match:
            return cmd, shell

        interpreter = match.group("intp")
        code = match.group("code")
        extras_str = match.group("args") or ""

        if code and ("\n" in code or "\r" in code):
            try:
                extras = shlex.split(extras_str) if extras_str else []
            except ValueError:
                extras = extras_str.split() if extras_str else []
            script_path = self.save_to_tmp(code, extension="py")
            if isinstance(script_path, str) and script_path.startswith("Error"):
                return cmd, shell
            new_parts = [interpreter, script_path] + extras
            return new_parts, False

        return cmd, shell

    def _guess_extension_for_mime(self, content_type: str) -> str:
        """Heuristically derive a reasonable extension from a MIME type."""
        if not content_type:
            return "bin"
        mime = content_type.split(";", 1)[0].strip().lower()
        mapping = {
            "text/html": "html",
            "text/css": "css",
            "text/javascript": "js",
            "application/javascript": "js",
            "application/json": "json",
            "application/xml": "xml",
            "text/xml": "xml",
            "text/plain": "txt",
            "text/markdown": "md",
            "application/x-www-form-urlencoded": "txt",
            "application/octet-stream": "bin",
            "image/png": "png",
            "image/jpeg": "jpg",
            "image/gif": "gif",
            "image/svg+xml": "svg",
            "application/pdf": "pdf",
            "application/zip": "zip",
            "application/x-tar": "tar",
            "application/x-gzip": "gz",
        }
        if mime.startswith("text/"):
            return mapping.get(mime, "txt")
        return mapping.get(mime, "bin")

    def _is_text_mime(self, content_type: str) -> bool:
        """Return True if MIME type is likely text-based."""
        if not content_type:
            return False
        mime = content_type.split(";", 1)[0].strip().lower()
        if mime.startswith("text/"):
            return True
        text_like_tokens = ("json", "xml", "javascript", "x-www-form-urlencoded", "+json", "+xml")
        return any(token in mime for token in text_like_tokens)

    def _http_fetch(self, url: str, method: str, headers: Dict[str, str], data: Optional[Any],
                    timeout: int, follow_redirects: bool, insecure: bool,
                    params: Optional[Dict[str, Any]] = None, json_body: Optional[Any] = None,
                    save_body: bool = False) -> str:
        if not url.lower().startswith(("http://", "https://")):
            return f"Unsupported URL scheme for {url}. Only HTTP/HTTPS are allowed."

        # Try requests first if available
        try:
            import requests  # type: ignore
        except Exception:
            requests = None  # type: ignore

        if requests:
            session = self._http_session
            if session is None:
                session = requests.Session()
                session.headers.setdefault("User-Agent", "OperativeAgent/1.0")
                self._http_session = session

            request_kwargs: Dict[str, Any] = {
                "method": method,
                "url": url,
                "headers": headers or None,
                "timeout": timeout,
                "allow_redirects": follow_redirects,
                "verify": not insecure,
            }
            if params:
                request_kwargs["params"] = params
            if json_body is not None:
                request_kwargs["json"] = json_body
            elif data is not None:
                request_kwargs["data"] = data

            try:
                response = session.request(**request_kwargs)
            except Exception as exc:
                return f"HTTP request error: {exc}"

            lines = [f"Status: {response.status_code}"]
            elapsed = getattr(response, "elapsed", None)
            if elapsed:
                lines.append(f"Elapsed: {elapsed.total_seconds():.3f}s")
            else:
                lines.append("Elapsed: n/a")
            lines.append("Headers:")
            for key, value in response.headers.items():
                lines.append(f"  {key}: {value}")
            if response.history:
                lines.append("")
                lines.append("Redirect chain:")
                for hop in response.history:
                    lines.append(f"  {hop.status_code} -> {hop.headers.get('Location', '')}")
            cookies = response.cookies.get_dict()
            if cookies:
                lines.append("")
                lines.append("Cookies:")
                for name, value in cookies.items():
                    lines.append(f"  {name}={value}")
            lines.append("")

            content_type = response.headers.get("Content-Type", "")
            mime_extension = self._guess_extension_for_mime(content_type)
            is_text = self._is_text_mime(content_type)
            body_path: Optional[str] = None

            if is_text:
                try:
                    encoding = response.encoding or "utf-8"
                    text_body = response.content.decode(encoding, errors="replace")
                except (LookupError, UnicodeDecodeError):
                    text_body = response.text

                if "json" in content_type.lower():
                    try:
                        parsed = response.json()
                        text_body = json.dumps(parsed, indent=2, ensure_ascii=False)
                    except Exception:
                        pass

                max_preview_chars = 4000
                truncated = len(text_body) > max_preview_chars
                preview = text_body[:max_preview_chars]
                if truncated:
                    preview += "..."
                lines.append(preview if preview else "(empty body)")

                if save_body or truncated:
                    body_path = self.save_to_tmp(text_body, extension=mime_extension or "txt")
            else:
                binary = response.content
                if binary:
                    body_path = self.save_to_tmp(binary, extension=mime_extension or "bin")
                    lines.append(f"[binary body saved: {len(binary)} bytes -> {body_path}]")
                else:
                    lines.append("(empty body)")

            if body_path:
                lines.append(f"\nFull body saved to: {body_path}")
            return "\n".join(lines)

        # Fallback to curl if present
        final_url = url
        if params:
            try:
                from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

                parsed = urlsplit(url)
                query_items = parse_qsl(parsed.query, keep_blank_values=True)
                query_items.extend((str(k), str(v)) for k, v in params.items())
                final_url = urlunsplit(
                    (parsed.scheme, parsed.netloc, parsed.path, urlencode(query_items), parsed.fragment)
                )
            except Exception:
                final_url = url

        if self._command_exists("curl"):
            cmd = ["curl", "-i", "--max-time", str(timeout)]
            if follow_redirects:
                cmd.append("-L")
            if insecure:
                cmd.append("-k")
            for key, value in (headers or {}).items():
                cmd.extend(["-H", f"{key}: {value}"])
            if method and method.upper() != "GET":
                cmd.extend(["-X", method.upper()])
            if json_body is not None:
                cmd.extend(["--data-binary", json.dumps(json_body)])
            elif data is not None:
                cmd.extend(["--data-binary", str(data)])
            cmd.append(final_url)
            return self.run_popen(cmd, shell=False, timeout=timeout + 5)

        # Final fallback using urllib
        try:
            import urllib.request
            import ssl

            req = urllib.request.Request(final_url, method=method.upper())
            for key, value in (headers or {}).items():
                req.add_header(key, value)
            context = None
            if insecure and final_url.lower().startswith("https://"):
                context = ssl._create_unverified_context()

            if json_body is not None:
                payload = json.dumps(json_body).encode("utf-8")
            elif data is not None:
                payload = str(data).encode("utf-8", errors="ignore")
            else:
                payload = None

            with urllib.request.urlopen(req, data=payload, timeout=timeout, context=context) as resp:
                raw = resp.read()
                content_type = resp.headers.get_content_type()
                is_text = self._is_text_mime(content_type)
                lines = [
                    f"Status: {resp.status}",
                    "Headers:",
                ]
                for key, value in resp.headers.items():
                    lines.append(f"  {key}: {value}")
                lines.append("")
                body_path: Optional[str] = None
                if is_text:
                    text_body = raw.decode("utf-8", errors="replace")
                    max_preview_chars = 4000
                    truncated = len(text_body) > max_preview_chars
                    preview = text_body[:max_preview_chars]
                    if truncated:
                        preview += "..."
                    lines.append(preview if preview else "(empty body)")
                    if save_body or truncated:
                        body_path = self.save_to_tmp(text_body, extension=self._guess_extension_for_mime(content_type))
                else:
                    if raw:
                        body_path = self.save_to_tmp(raw, extension=self._guess_extension_for_mime(content_type))
                        lines.append(f"[binary body saved: {len(raw)} bytes -> {body_path}]")
                    else:
                        lines.append("(empty body)")

                if body_path:
                    lines.append(f"\nFull body saved to: {body_path}")
                return "\n".join(lines)
        except Exception as exc:
            return f"HTTP request error: {exc}"

    def _normalize_command(self, cmd: Any, shell: bool):
        """Normalise tool command inputs for Popen."""
        if isinstance(cmd, dict):
            for key in ("command", "cmd", "args"):
                if key in cmd:
                    return self._normalize_command(cmd[key], shell)
            return None
        if isinstance(cmd, str):
            clean = cmd.strip()
            if not clean:
                return None
            if shell:
                return clean
            return shlex.split(clean)
        if shell and isinstance(cmd, (list, tuple)):
            operators = {"|", "||", "&&", ";", "&", ">", "<<", ">>", "<", "2>", "2>>"}
            rendered = []
            for part in cmd:
                part_str = str(part)
                if part_str in operators:
                    rendered.append(part_str)
                else:
                    rendered.append(shlex.quote(part_str))
            return " ".join(rendered)
        if not shell and isinstance(cmd, (list, tuple)):
            return [str(part) for part in cmd]
        return cmd

    def run_popen(self, cmd, shell=False, timeout=None, cwd=None, env=None, stdin_data: Optional[str] = None):
        cmd = self._normalize_command(cmd, shell)
        if cmd is None or cmd == []:
            return "Tool error: empty command"
        try:
            merged_env = None
            if env:
                merged_env = os.environ.copy()
                merged_env.update({str(k): str(v) for k, v in env.items()})
            stdin_pipe = subprocess.PIPE if stdin_data is not None else None
            proc = subprocess.Popen(
                cmd,
                shell=shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd or None,
                env=merged_env,
                stdin=stdin_pipe
            )
            self._current_proc = proc
            try:
                out, err = proc.communicate(input=stdin_data, timeout=timeout)
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
                shell_flag = tool_input.get("shell")
                if shell_flag is None:
                    shell_flag = True
                cmd, shell_flag = self._maybe_wrap_python_command(cmd, shell_flag)
                timeout = tool_input.get("timeout", 120)
                try:
                    timeout = int(timeout) if timeout is not None else None
                except (TypeError, ValueError):
                    timeout = 120
                cwd = tool_input.get("cwd")
                env = tool_input.get("env")
                stdin_data = tool_input.get("input")
                if stdin_data is not None and not isinstance(stdin_data, str):
                    stdin_data = str(stdin_data)
                return self.run_popen(cmd, shell=shell_flag, timeout=timeout, cwd=cwd, env=env, stdin_data=stdin_data)

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

            if tool_name == "http_fetch":
                url = tool_input["url"]
                method = tool_input.get("method", "GET").upper()
                headers = tool_input.get("headers") or {}
                if isinstance(headers, list):
                    # Convert list of "Key: Value" pairs into dict
                    tmp = {}
                    for item in headers:
                        if isinstance(item, str) and ":" in item:
                            key, value = item.split(":", 1)
                            tmp[key.strip()] = value.strip()
                    headers = tmp
                elif not isinstance(headers, dict):
                    headers = {}
                data = tool_input.get("data")
                params = tool_input.get("params")
                if not isinstance(params, dict):
                    params = None
                elif params:
                    params = {str(k): str(v) for k, v in params.items()}
                json_body = tool_input.get("json")
                if isinstance(json_body, str):
                    try:
                        json_body = json.loads(json_body)
                    except json.JSONDecodeError:
                        pass
                save_body = bool(tool_input.get("save_body", False))
                try:
                    timeout = int(tool_input.get("timeout", 30))
                except (TypeError, ValueError):
                    timeout = 30
                follow_redirects = bool(tool_input.get("follow_redirects", True))
                insecure = bool(tool_input.get("insecure", False))
                # Prefer JSON payload over raw data if both are set
                if json_body is not None:
                    data = None
                return self._http_fetch(
                    url,
                    method,
                    headers,
                    data,
                    timeout,
                    follow_redirects,
                    insecure,
                    params=params,
                    json_body=json_body,
                    save_body=save_body,
                )

            if tool_name == "nmap_scan":
                target = tool_input["target"]
                stype = tool_input["scan_type"]
                if stype == "quick":
                    cmd = ["nmap", "-F", target]
                elif stype == "full":
                    cmd = ["nmap", "-A", target]
                else:
                    cmd = ["nmap", "-sV", target]
                return self.run_popen(cmd, shell=False, timeout=300)

            if tool_name == "strings_extract":
                filepath = tool_input["filepath"]
                min_length = str(tool_input.get("min_length", 4))
                cmd = ["strings", "-n", min_length, filepath]
                return self.run_popen(cmd, shell=False, timeout=120)

            if tool_name == "file_info":
                filepath = tool_input["filepath"]
                if not os.path.exists(filepath):
                    return f"File not found: {filepath}"
                try:
                    stat_info = os.stat(filepath)
                except PermissionError:
                    return f"Permission denied: {filepath}"

                details = [
                    f"Size: {stat_info.st_size} bytes",
                    f"Permissions: {oct(stat.S_IMODE(stat_info.st_mode))}",
                    f"Owner UID: {stat_info.st_uid}, GID: {stat_info.st_gid}",
                    f"Modified: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat_info.st_mtime))}",
                ]

                if self._command_exists("file"):
                    file_out = self.run_popen(["file", "-i", filepath], shell=False, timeout=30).strip()
                    if file_out:
                        details.append(file_out)
                else:
                    details.append("`file` command not available on this system.")

                return "\n".join(details)

            if tool_name == "checksec_analyze":
                filepath = tool_input["filepath"]
                if not os.path.exists(filepath):
                    return f"File not found: {filepath}"
                if self._command_exists("checksec"):
                    cmd = ["checksec", "--file", filepath]
                elif self._command_exists("pwn"):
                    cmd = ["pwn", "checksec", filepath]
                else:
                    return "Neither `checksec` nor `pwn checksec` is available on this system."
                result = self.run_popen(cmd, shell=False, timeout=60)
                if "Traceback" in result or "ERROR" in result.upper():
                    fallback_notes = []
                    file_lower = filepath.lower()
                    if file_lower.endswith((".exe", ".dll", ".msi", ".sys")):
                        fallback_notes.append("checksec failed—PE/COFF binaries are not supported by the installed checksec/pwn checksec tooling.")
                    else:
                        fallback_notes.append("checksec failed while analysing this file.")
                    fallback_notes.append(result.strip())
                    if self._command_exists("diec"):
                        die_output = self.run_popen(["diec", filepath], shell=False, timeout=60)
                        fallback_notes.append("diec fallback output:\n" + die_output.strip())
                    else:
                        fallback_notes.append("Install Detective/Die (`diec`) for PE analysis or use `rabin2 -I <file>` as an alternative.")
                    return "\n\n".join(fallback_notes)
                return result

            if tool_name == "binwalk_scan":
                filepath = tool_input["filepath"]
                if not os.path.exists(filepath):
                    return f"File not found: {filepath}"
                if not self._command_exists("binwalk"):
                    return "`binwalk` is not installed."
                flags_raw = tool_input.get("flags", "")
                extract = bool(tool_input.get("extract", False))
                cmd = ["binwalk", filepath]
                if extract:
                    cmd.insert(1, "-e")
                    try:
                        if hasattr(os, "geteuid") and os.geteuid() == 0:
                            cmd.append("--run-as=root")
                    except Exception:
                        pass
                if flags_raw:
                    try:
                        extra_flags = shlex.split(str(flags_raw))
                        insert_at = 2 if extract else 1
                        cmd[insert_at:insert_at] = extra_flags
                    except ValueError as exc:
                        return f"Invalid flags: {exc}"
                result = self.run_popen(cmd, shell=False, timeout=600)
                if extract:
                    expected_dir = f"{filepath}.extracted"
                    if os.path.isdir(expected_dir):
                        result += f"\n\nExtracted files saved under: {expected_dir}"
                return result

            if tool_name == "exiftool_scan":
                filepath = tool_input["filepath"]
                if not os.path.exists(filepath):
                    return f"File not found: {filepath}"
                if not self._command_exists("exiftool"):
                    return "`exiftool` is not installed."
                return self.run_popen(["exiftool", filepath], shell=False, timeout=180)

            if tool_name == "stegseek_crack":
                filepath = tool_input["filepath"]
                if not os.path.exists(filepath):
                    return f"File not found: {filepath}"
                if not self._command_exists("stegseek"):
                    return "`stegseek` is not installed."
                wordlist = tool_input.get("wordlist") or "/usr/share/wordlists/rockyou.txt"
                if not os.path.exists(wordlist):
                    return f"Wordlist not found: {wordlist}"
                cmd = ["stegseek", filepath, wordlist, "--quiet"]
                timeout = tool_input.get("timeout", 600)
                try:
                    timeout = int(timeout) if timeout is not None else 600
                except (TypeError, ValueError):
                    timeout = 600
                result = self.run_popen(cmd, shell=False, timeout=timeout)
                output_file = f"{filepath}.out"
                if os.path.exists(output_file):
                    result += f"\n\nRecovered data saved to: {output_file}"
                return result

            if tool_name == "ffuf_scan":
                if not self._command_exists("ffuf"):
                    return "`ffuf` is not installed."
                url = tool_input["url"]
                wordlist = tool_input.get("wordlist") or "/usr/share/wordlists/dirb/common.txt"
                if not os.path.exists(wordlist):
                    return f"Wordlist not found: {wordlist}"
                cmd = ["ffuf", "-u", url, "-w", wordlist]
                method = tool_input.get("method")
                if method:
                    cmd.extend(["-X", method.upper()])
                headers = tool_input.get("headers") or {}
                if isinstance(headers, dict):
                    iterable = headers.items()
                elif isinstance(headers, list):
                    iterable = []
                    for item in headers:
                        if isinstance(item, str) and ":" in item:
                            key, value = item.split(":", 1)
                            iterable.append((key.strip(), value.strip()))
                else:
                    iterable = []
                for key, value in iterable:
                    cmd.extend(["-H", f"{key}: {value}"])
                extensions = tool_input.get("extensions")
                if extensions:
                    if isinstance(extensions, (list, tuple)):
                        cmd.extend(["-e", ",".join(str(ext) for ext in extensions)])
                    else:
                        cmd.extend(["-e", str(extensions)])
                threads = tool_input.get("threads")
                if threads:
                    cmd.extend(["-t", str(threads)])
                rate = tool_input.get("rate")
                if rate:
                    cmd.extend(["-r", str(rate)])
                match_status = tool_input.get("match_status")
                if match_status:
                    cmd.extend(["-mc", str(match_status)])
                filter_status = tool_input.get("filter_status")
                if filter_status:
                    cmd.extend(["-fc", str(filter_status)])
                filter_size = tool_input.get("filter_size")
                if filter_size:
                    cmd.extend(["-fs", str(filter_size)])
                silent = tool_input.get("silent")
                if silent:
                    cmd.append("-s")
                try:
                    timeout = int(tool_input.get("timeout", 900))
                except (TypeError, ValueError):
                    timeout = 900
                return self.run_popen(cmd, shell=False, timeout=timeout)

            if tool_name == "whatweb_scan":
                if not self._command_exists("whatweb"):
                    return "`whatweb` is not installed."
                url = tool_input["url"]
                cmd = ["whatweb", "--color=never", url]
                aggressive = bool(tool_input.get("aggressive", False))
                if aggressive:
                    level = tool_input.get("aggression_level", 3)
                    try:
                        level_int = int(level)
                    except (TypeError, ValueError):
                        level_int = 3
                    cmd.extend(["-a", str(level_int)])
                plugins = tool_input.get("plugins")
                if plugins:
                    if isinstance(plugins, (list, tuple)):
                        cmd.extend(["-p", ",".join(str(p) for p in plugins)])
                    else:
                        cmd.extend(["-p", str(plugins)])
                user_agent = tool_input.get("user_agent")
                if user_agent:
                    cmd.extend(["-U", str(user_agent)])
                timeout_raw = tool_input.get("timeout")
                try:
                    timeout_val = int(timeout_raw) if timeout_raw is not None else 300
                except (TypeError, ValueError):
                    timeout_val = 300
                cmd.extend(["--timeout", str(timeout_val)])
                return self.run_popen(cmd, shell=False, timeout=timeout_val)

            if tool_name == "list_directory":
                path = tool_input.get("path") or "."
                show_hidden = bool(tool_input.get("show_hidden", False))
                recursive = bool(tool_input.get("recursive", False))
                try:
                    lines = self._list_directory(path, show_hidden, recursive)
                    return "\n".join(lines) if lines else "Directory is empty."
                except FileNotFoundError:
                    return f"Path not found: {path}"
                except PermissionError:
                    return f"Permission denied: {path}"
                except NotADirectoryError:
                    return f"Not a directory: {path}"

            if tool_name == "search_files":
                pattern = tool_input["pattern"]
                start_path = tool_input.get("start_path") or "."
                file_glob = tool_input.get("file_glob")
                try:
                    max_results = int(tool_input.get("max_results", 200))
                except (TypeError, ValueError):
                    max_results = 200
                case_sensitive = bool(tool_input.get("case_sensitive", False))
                timeout = tool_input.get("timeout")
                return self._search_files(pattern, start_path, file_glob, max_results, case_sensitive, timeout)

            if tool_name == "extract_archive":
                archive_path = tool_input["archive_path"]
                destination = tool_input.get("destination")
                try:
                    output_path, extracted = self._extract_archive(archive_path, destination)
                    detail = "\n  ".join(extracted[:50])
                    if len(extracted) > 50:
                        detail += "\n  ... (truncated)"
                    return f"Archive extracted to: {output_path}\n  {detail}" if extracted else f"Archive extracted to: {output_path}"
                except FileNotFoundError:
                    return f"Archive not found: {archive_path}"
                except shutil.ReadError as exc:
                    return f"Unable to extract archive: {exc}"
                except Exception as exc:
                    return f"Archive extraction error: {exc}"

            if tool_name == "hexdump_file":
                filepath = tool_input["filepath"]
                try:
                    max_bytes = int(tool_input.get("max_bytes", 4096))
                except (TypeError, ValueError):
                    max_bytes = 4096
                try:
                    width = int(tool_input.get("width", 16))
                except (TypeError, ValueError):
                    width = 16
                try:
                    with open(filepath, "rb") as fh:
                        data = fh.read(max_bytes)
                    if not data:
                        return "File is empty."
                    has_more = os.path.getsize(filepath) > len(data)
                    dump = self._hexdump(data, width)
                    if has_more:
                        dump += "\n... (truncated)"
                    return dump
                except FileNotFoundError:
                    return f"File not found: {filepath}"
                except PermissionError:
                    return f"Permission denied: {filepath}"

            return f"Unknown tool: {tool_name}"

        except Exception as e:
            return f"Tool error: {e}"

    def _list_directory(self, path: str, show_hidden: bool, recursive: bool) -> List[str]:
        entries = []
        if recursive:
            for root, dirs, files in os.walk(path):
                entries.append(f"[{root}]")
                entries.extend(self._format_dir_entries(root, dirs, files, show_hidden))
        else:
            with os.scandir(path) as it:
                dirs = []
                files = []
                for entry in it:
                    if not show_hidden and entry.name.startswith("."):
                        continue
                    (dirs if entry.is_dir(follow_symlinks=False) else files).append(entry)
                entries.extend(self._format_scandir_entries(dirs + files))
        return entries

    def _format_dir_entries(self, root: str, dirs: List[str], files: List[str], show_hidden: bool) -> List[str]:
        outputs: List[str] = []
        for name in sorted(dirs):
            if not show_hidden and name.startswith("."):
                continue
            full = os.path.join(root, name)
            outputs.append(self._format_path_line(full, True))
        for name in sorted(files):
            if not show_hidden and name.startswith("."):
                continue
            full = os.path.join(root, name)
            outputs.append(self._format_path_line(full, False))
        return outputs

    def _format_scandir_entries(self, entries: List[os.DirEntry]) -> List[str]:
        lines: List[str] = []
        for entry in sorted(entries, key=lambda e: e.name.lower()):
            is_dir = entry.is_dir(follow_symlinks=False)
            lines.append(self._format_path_line(entry.path, is_dir))
        return lines

    def _format_path_line(self, path: str, is_dir: bool) -> str:
        try:
            stat_info = os.stat(path, follow_symlinks=False)
            size = stat_info.st_size
            mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat_info.st_mtime))
        except FileNotFoundError:
            return f"{path} [missing]"
        label = path + ("/" if is_dir else "")
        return f"{mtime}  {size:>10}  {label}"

    def _search_files(self, pattern: str, start_path: str, file_glob: Optional[str],
                      max_results: int, case_sensitive: bool, timeout: Optional[int]) -> str:
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            regex = re.compile(pattern, flags)
        except re.error as exc:
            return f"Invalid regex: {exc}"

        timeout_value: Optional[int]
        if timeout is not None:
            try:
                timeout_value = int(timeout)
            except (TypeError, ValueError):
                timeout_value = None
        else:
            timeout_value = None

        if shutil.which("rg"):
            cmd = ["rg", "--color", "never", "-n", "-m", str(max_results), pattern, start_path]
            if not case_sensitive:
                cmd.insert(1, "--ignore-case")
            if file_glob:
                cmd.extend(["-g", file_glob])
            return self.run_popen(cmd, shell=False, timeout=timeout_value or 180)

        matches: List[str] = []
        for root, _, files in os.walk(start_path):
            for filename in files:
                if file_glob and not fnmatch.fnmatch(filename, file_glob):
                    continue
                filepath = os.path.join(root, filename)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                        for idx, line in enumerate(fh, 1):
                            if regex.search(line):
                                matches.append(f"{filepath}:{idx}: {line.rstrip()}")
                                if len(matches) >= max_results:
                                    return "\n".join(matches)
                except (UnicodeDecodeError, OSError):
                    continue
        return "\n".join(matches) if matches else "No matches."

    def _extract_archive(self, archive_path: str, destination: Optional[str]) -> Tuple[str, List[str]]:
        if not destination:
            destination = os.path.join(
                self.temp_dir,
                f"operative_extract_{self.session_id}_{int(time.time())}"
            )
        os.makedirs(destination, exist_ok=True)
        extracted_paths: List[str] = []
        try:
            shutil.unpack_archive(archive_path, destination)
        except shutil.ReadError:
            if archive_path.endswith(".gz"):
                target_name = os.path.basename(archive_path[:-3]) or "decompressed"
                target_path = os.path.join(destination, target_name)
                with gzip.open(archive_path, "rb") as src, open(target_path, "wb") as dst:
                    dst.write(src.read())
            else:
                raise

        for root, dirs, files in os.walk(destination):
            for name in dirs + files:
                extracted_paths.append(os.path.join(root, name))
        if not extracted_paths:
            extracted_paths.append(destination)
        return destination, extracted_paths

    def _hexdump(self, data: bytes, width: int) -> str:
        lines = []
        for offset in range(0, len(data), width):
            chunk = data[offset:offset + width]
            hex_bytes = binascii.hexlify(chunk).decode("ascii")
            hex_pairs = " ".join(hex_bytes[i:i+2] for i in range(0, len(hex_bytes), 2))
            ascii_repr = "".join((chr(b) if 32 <= b <= 126 else ".") for b in chunk)
            lines.append(f"{offset:08x}  {hex_pairs:<{width*3}}  {ascii_repr}")
        return "\n".join(lines)


# ---------- Base Agent ----------
class BaseAgent:
    """Base class for both Claude and OpenAI agents"""
    
    def __init__(self, api_provider: str, max_history=MAX_HISTORY_ENTRIES, debug: bool = False,
                 system_prompt: Optional[str] = None):
        self.api_provider = api_provider
        self.conversation_history = []
        self.total_api_requests = 0
        self.total_tool_calls = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.max_history = max_history
        self.debug = debug
        self.tool_executor = ToolExecutor()
        self.system_prompt = system_prompt
        self._system_message_inserted = False
        self.system_delivery = "message"  # message | parameter | prepend
        self._system_prompt_prefix: Optional[str] = None
        self._system_prompt_consumed = False
        self._tool_confirmation_mode = "ask"
        self.persona_style = "default"
        self.persona_prompt = ""

    def ensure_system_prompt(self) -> None:
        """Insert the system prompt into the conversation once."""
        if self.system_prompt and not self._system_message_inserted:
            # Combine base system prompt with persona if set
            full_system_prompt = self.system_prompt
            if self.persona_prompt:
                full_system_prompt = f"{self.system_prompt}\n\nPERSONA INSTRUCTIONS:\n{self.persona_prompt}"

            if self.system_delivery == "message":
                self.conversation_history.insert(0, {"role": "system", "content": full_system_prompt})
            elif self.system_delivery == "prepend":
                self._system_prompt_prefix = full_system_prompt
            self._system_message_inserted = True

    def prepare_user_message(self, user_message: str) -> str:
        """Attach system guidance to the first user message if the provider lacks system-role support."""
        message = user_message
        if self.system_delivery == "prepend" and self._system_prompt_prefix and not self._system_prompt_consumed:
            self._system_prompt_consumed = True
            prefix = self._system_prompt_prefix.strip()
            self._system_prompt_prefix = None
            if not prefix:
                message = user_message
            else:
                message = f"{prefix}\n\n{user_message}"
        if self.persona_prompt:
            if message:
                return f"{self.persona_prompt}\n\n{message}"
            return self.persona_prompt
        return message

    def set_persona(self, persona: str) -> Tuple[bool, str]:
        """Update conversational persona style."""
        persona_key = (persona or "").strip().lower()
        if not persona_key:
            available = ", ".join(sorted(PERSONA_PRESETS.keys()))
            return False, f"Provide a persona name (options: {available})."
        persona_key = PERSONA_ALIASES.get(persona_key, persona_key)
        if persona_key not in PERSONA_PRESETS:
            known = ", ".join(sorted(PERSONA_PRESETS.keys()))
            return False, f"Unknown persona '{persona}'. Available options: {known}."

        self.persona_style = persona_key
        self.persona_prompt = PERSONA_PRESETS[persona_key]

        # Update system message if it exists
        if self._system_message_inserted and self.conversation_history:
            if self.conversation_history[0].get("role") == "system":
                full_system_prompt = self.system_prompt
                if self.persona_prompt:
                    full_system_prompt = f"{self.system_prompt}\n\nPERSONA INSTRUCTIONS:\n{self.persona_prompt}"
                self.conversation_history[0]["content"] = full_system_prompt

        if persona_key == "default":
            return True, "Switched back to the default assistant voice."
        friendly_labels = {
            "genz": "Gen-Z vibes",
            "mentor": "Mentor mode",
            "speedrun": "Speedrun mode",
            "retro": "Retro hacker energy",
            "ops": "Mission-ops checklist",
            "teacher": "Instructor mode",
        }
        friendly_name = friendly_labels.get(persona_key, persona_key.title())
        return True, f"Persona set to {friendly_name}."

    def define_tools_schema(self):
        """Return tools in provider-specific format"""
        raise NotImplementedError

    def truncate_history(self):
        while len(self.conversation_history) > self.max_history:
            if self.conversation_history and self.conversation_history[0].get("role") == "system":
                remove_index = 1 if len(self.conversation_history) > 1 else 0
            else:
                remove_index = 0
            removed = self.conversation_history.pop(remove_index)
            orphan_ids = self._collect_tool_call_ids(removed)
            if orphan_ids:
                self._remove_tool_results_by_ids(orphan_ids)

    def _drop_oldest_message(self) -> bool:
        """Remove the oldest non-system entry plus any dependent tool results."""
        if not self.conversation_history:
            return False

        remove_index = 0
        first_role = self.conversation_history[0].get("role")
        if first_role == "system":
            # Do not remove the system prompt or the most recent user request.
            if len(self.conversation_history) <= 2:
                return False
            remove_index = 1
        elif len(self.conversation_history) <= 1:
            return False

        removed = self.conversation_history.pop(remove_index)
        orphan_ids = self._collect_tool_call_ids(removed)
        if orphan_ids:
            self._remove_tool_results_by_ids(orphan_ids)
        return True

    @staticmethod
    def _is_context_length_error(error: Exception) -> bool:
        """Detect whether an exception stems from exceeding the model context."""
        message = str(error).lower()
        keywords = (
            "maximum context length",
            "context length",
            "context window",
            "reduce the length",
            "too many tokens",
        )
        return any(keyword in message for keyword in keywords)

    def chat(self, user_message: str, auto_execute: bool, inline_model: Optional[str] = None, 
             max_steps: int = DEFAULT_MAX_STEPS):
        raise NotImplementedError

    def _collect_tool_call_ids(self, entry: Any) -> set:
        ids = set()
        if not isinstance(entry, dict):
            return ids

        role = entry.get("role")

        # OpenAI-style tool calls
        tool_calls = entry.get("tool_calls")
        if isinstance(tool_calls, (list, tuple)):
            for call in tool_calls:
                call_id = None
                if isinstance(call, dict):
                    call_id = call.get("id") or call.get("tool_call_id")
                else:
                    call_id = getattr(call, "id", None) or getattr(call, "tool_call_id", None)
                if call_id:
                    ids.add(call_id)

        # Anthropic-style tool_use blocks stored under content
        content = entry.get("content")
        if isinstance(content, (list, tuple)):
            for block in content:
                block_type = getattr(block, "type", None)
                block_id = getattr(block, "id", None) or getattr(block, "tool_use_id", None)
                if block_type != "tool_use" and isinstance(block, dict):
                    block_type = block.get("type")
                    block_id = block.get("id") or block.get("tool_use_id")
                if block_type == "tool_use" and block_id:
                    ids.add(block_id)

                # tool_result entries referenced while trimming (when removing tool_result first)
                if block_type == "tool_result" and block_id:
                    ids.add(block_id)

        # Tool-result entries themselves expose tool_call_id directly
        if role == "tool":
            call_id = entry.get("tool_call_id")
            if call_id:
                ids.add(call_id)

        return ids

    def _entry_references_tool_call(self, entry: Any, tool_call_ids: set) -> bool:
        if not isinstance(entry, dict):
            return False

        role = entry.get("role")
        if role == "tool":
            return entry.get("tool_call_id") in tool_call_ids

        if role == "user":
            content = entry.get("content")
            if isinstance(content, (list, tuple)):
                for item in content:
                    item_type = getattr(item, "type", None)
                    item_id = getattr(item, "tool_use_id", None)
                    if item_type != "tool_result" and isinstance(item, dict):
                        item_type = item.get("type")
                        item_id = item.get("tool_use_id")
                    if item_type == "tool_result" and item_id in tool_call_ids:
                        return True
        return False

    def _remove_tool_results_by_ids(self, tool_call_ids: set) -> None:
        if not tool_call_ids:
            return
        filtered_history = []
        for entry in self.conversation_history:
            if self._entry_references_tool_call(entry, tool_call_ids):
                continue
            filtered_history.append(entry)
        self.conversation_history = filtered_history

    def format_token_summary(self) -> str:
        """Format token usage with cost calculation"""
        total_tokens = self.total_input_tokens + self.total_output_tokens

        # Cost calculation (USD per million tokens)
        if self.api_provider == "claude":
            # Claude pricing (as of Jan 2025)
            costs = {
                CLAUDE_OPUS: (15.00, 75.00),      # input, output per 1M tokens
                CLAUDE_SONNET: (3.00, 15.00),
                CLAUDE_HAIKU: (0.80, 4.00),
            }
            model = getattr(self, 'current_model', CLAUDE_SONNET)
            input_cost_per_m, output_cost_per_m = costs.get(model, (3.00, 15.00))
        else:
            # OpenAI pricing (as of Aug 2025 - GPT-5 release)
            costs = {
                GPT5: (1.25, 10.00),        # Updated Aug 2025
                GPT4O: (2.50, 10.00),
                GPT4: (30.00, 60.00),
                GPT4O_MINI: (0.150, 0.600),
                GPT35_TURBO: (0.50, 1.50),
            }
            model = getattr(self, 'current_model', GPT4O)
            input_cost_per_m, output_cost_per_m = costs.get(model, (2.50, 10.00))

        input_cost = (self.total_input_tokens / 1_000_000) * input_cost_per_m
        output_cost = (self.total_output_tokens / 1_000_000) * output_cost_per_m
        total_cost = input_cost + output_cost

        # Format with colors
        if total_cost < 0.01:
            cost_str = f"${total_cost:.4f}"
            cost_color = C.GREEN
        elif total_cost < 0.10:
            cost_str = f"${total_cost:.3f}"
            cost_color = C.YELLOW
        else:
            cost_str = f"${total_cost:.2f}"
            cost_color = C.RED

        return (
            f"requests: {self.total_api_requests}, "
            f"tools: {self.total_tool_calls}, "
            f"tokens: {total_tokens:,} "
            f"({color(cost_str, cost_color)})"
        )

# ---------- Claude Agent ----------
class ClaudeAgent(BaseAgent):
    def __init__(self, api_key: str, max_history=MAX_HISTORY_ENTRIES, debug: bool = False):
        super().__init__("claude", max_history, debug, system_prompt=CLAUDE_SYSTEM_PROMPT)
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model_light = CLAUDE_HAIKU
        self.model_medium = CLAUDE_SONNET
        self.model_heavy = CLAUDE_OPUS
        self.system_delivery = "parameter"

    def define_tools_schema(self):
        return [
            {
                "name": "execute_command",
                "description": "Run shell command",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string"},
                        "shell": {"type": "boolean", "description": "Run through shell (default true)"},
                        "cwd": {"type": "string", "description": "Working directory"},
                        "timeout": {"type": "integer", "minimum": 1},
                        "input": {"type": "string", "description": "String to send to stdin"},
                        "env": {
                            "type": "object",
                            "description": "Environment variables",
                            "additionalProperties": {"type": "string"}
                        }
                    },
                    "required": ["command"]
                }
            },
            {
                "name": "read_file",
                "description": "Read file contents",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "filepath": {"type": "string"},
                        "mode": {"type": "string", "enum": ["text", "binary", "hex"]}
                    },
                    "required": ["filepath", "mode"]
                }
            },
            {
                "name": "write_file",
                "description": "Write content to a file in /tmp/. Use this to save extracted data, decoded content, scripts, or any generated files.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "content": {"type": "string", "description": "Content to write"},
                        "filename": {"type": "string", "description": "Filename (optional, will auto-generate if not provided)"},
                        "extension": {"type": "string", "description": "File extension (e.g., txt, py, sh, bin)"}
                    },
                    "required": ["content", "extension"]
                }
            },
            {
                "name": "list_session_files",
                "description": "List all files created during this session",
                "input_schema": {"type": "object", "properties": {}, "required": []}
            },
            {
                "name": "list_directory",
                "description": "List directory contents",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "show_hidden": {"type": "boolean"},
                        "recursive": {"type": "boolean"}
                    }
                }
            },
            {
                "name": "search_files",
                "description": "Search files for a regex pattern",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string"},
                        "start_path": {"type": "string"},
                        "file_glob": {"type": "string"},
                        "max_results": {"type": "integer", "minimum": 1},
                        "case_sensitive": {"type": "boolean"},
                        "timeout": {"type": "integer", "minimum": 1}
                    },
                    "required": ["pattern"]
                }
            },
            {
                "name": "extract_archive",
                "description": "Extract archive (zip/tar/gz)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "archive_path": {"type": "string"},
                        "destination": {"type": "string"}
                    },
                    "required": ["archive_path"]
                }
            },
            {
                "name": "hexdump_file",
                "description": "Generate a hexdump preview",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "filepath": {"type": "string"},
                        "max_bytes": {"type": "integer", "minimum": 1},
                        "width": {"type": "integer", "minimum": 4}
                    },
                    "required": ["filepath"]
                }
            },
            {
                "name": "http_fetch",
                "description": "Perform an HTTP(S) request and return status/headers/body preview",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "method": {"type": "string"},
                        "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                        "data": {"type": "string"},
                        "params": {
                            "type": "object",
                            "additionalProperties": {"type": "string"},
                            "description": "Query string parameters to append"
                        },
                        "json": {
                            "type": "object",
                            "description": "JSON body to send with the request",
                            "additionalProperties": True
                        },
                        "save_body": {"type": "boolean", "description": "Always persist the body to a session file"},
                        "timeout": {"type": "integer", "minimum": 1},
                        "follow_redirects": {"type": "boolean"},
                        "insecure": {"type": "boolean"}
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "file_info",
                "description": "Display file metadata (size, perms, MIME)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "filepath": {"type": "string"}
                    },
                    "required": ["filepath"]
                }
            },
            {
                "name": "checksec_analyze",
                "description": "Run checksec (or pwn checksec) against a binary",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "filepath": {"type": "string"}
                    },
                    "required": ["filepath"]
                }
            },
            {
                "name": "binwalk_scan",
                "description": "Run binwalk against a file (optional extraction)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "filepath": {"type": "string"},
                        "extract": {"type": "boolean"},
                        "flags": {"type": "string"}
                    },
                    "required": ["filepath"]
                }
            },
            {
                "name": "exiftool_scan",
                "description": "Run exiftool to inspect metadata",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "filepath": {"type": "string"}
                    },
                    "required": ["filepath"]
                }
            },
            {
                "name": "stegseek_crack",
                "description": "Attempt to crack stego files with stegseek",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "filepath": {"type": "string"},
                        "wordlist": {"type": "string"},
                        "timeout": {"type": "integer", "minimum": 1}
                    },
                    "required": ["filepath"]
                }
            },
            {
                "name": "ffuf_scan",
                "description": "Run ffuf for content discovery/fuzzing",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "wordlist": {"type": "string"},
                        "method": {"type": "string"},
                        "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                        "extensions": {"type": ["array", "string"], "items": {"type": "string"}},
                        "threads": {"type": "integer", "minimum": 1},
                        "rate": {"type": "integer", "minimum": 1},
                        "match_status": {"type": "string"},
                        "filter_status": {"type": "string"},
                        "filter_size": {"type": "string"},
                        "timeout": {"type": "integer", "minimum": 1},
                        "silent": {"type": "boolean"}
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "whatweb_scan",
                "description": "Fingerprint a target using whatweb",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "aggressive": {"type": "boolean"},
                        "aggression_level": {"type": "integer", "minimum": 1},
                        "plugins": {"type": ["array", "string"], "items": {"type": "string"}},
                        "user_agent": {"type": "string"},
                        "timeout": {"type": "integer", "minimum": 1}
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "decode_base64",
                "description": "Decode base64 data",
                "input_schema": {
                    "type": "object",
                    "properties": {"data": {"type": "string"}},
                    "required": ["data"]
                }
            },
            {
                "name": "compute_hash",
                "description": "Compute hash",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "data": {"type": "string"},
                        "algorithm": {"type": "string", "enum": ["md5", "sha1", "sha256", "sha512"]}
                    },
                    "required": ["data", "algorithm"]
                }
            },
            {
                "name": "nmap_scan",
                "description": "Run nmap",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "scan_type": {"type": "string", "enum": ["quick", "full", "version"]}
                    },
                    "required": ["target", "scan_type"]
                }
            },
            {
                "name": "strings_extract",
                "description": "Extract strings",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "filepath": {"type": "string"},
                        "min_length": {"type": "integer"}
                    },
                    "required": ["filepath"]
                }
            },
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
        self.ensure_system_prompt()
        user_message = self.prepare_user_message(user_message)
        # Add session context if files exist
        session_context = self.tool_executor.get_session_context()
        if session_context:
            user_message = session_context + user_message
        
        self.conversation_history.append({"role": "user", "content": user_message})
        self.truncate_history()

        steps = 0
        thinking = ThinkingAnimation()
        self._tool_confirmation_mode = "ask"
        self._tool_confirmation_mode = "ask"

        while steps < max_steps:
            steps += 1
            model = self.pick_model(inline_model)
            self.current_model = model  # Track for cost calculation

            context_error = False
            cancelled = False
            context_retries = 0
            response = None

            while True:
                try:
                    self.total_api_requests += 1
                    thinking.start()
                    request_kwargs = {
                        "model": model,
                        "max_tokens": 4096,
                        "tools": self.define_tools_schema(),
                        "messages": self.conversation_history,
                    }
                    if self.system_delivery == "parameter" and self.system_prompt:
                        request_kwargs["system"] = self.system_prompt
                    response = self.client.messages.create(
                        **request_kwargs
                    )
                    thinking.stop()

                    # Track token usage from response
                    if hasattr(response, 'usage'):
                        self.total_input_tokens += getattr(response.usage, 'input_tokens', 0)
                        self.total_output_tokens += getattr(response.usage, 'output_tokens', 0)

                    break
                except KeyboardInterrupt:
                    thinking.stop()
                    print(color("\n⚠ Request cancelled by user.\n", C.YELLOW))
                    self.conversation_history.append({"role": "user", "content": "[Request cancelled]"})
                    cancelled = True
                    break
                except Exception as e:
                    thinking.stop()
                    if self._is_context_length_error(e) and self._drop_oldest_message():
                        context_retries += 1
                        if context_retries <= self.max_history:
                            print(color("⚠ Context window exceeded. Dropped the oldest exchange and retrying...", C.YELLOW))
                            continue
                    print(color(f"❌ API error: {e}", C.RED))
                    context_error = True
                    break

            if cancelled or context_error:
                break

            blocks = list(response.content) if hasattr(response, 'content') else []
            self.conversation_history.append({"role": "assistant", "content": blocks})
            self.truncate_history()

            tool_uses = [b for b in blocks if getattr(b, 'type', None) == 'tool_use']
            text_blocks = [getattr(b, 'text', '') for b in blocks if getattr(b, 'type', None) == 'text']

            flag_detected_in_text = False
            if text_blocks:
                text = " ".join(text_blocks).strip()
                model_display = self.get_model_display_name(model)
                print(color(f"\n🤖 Claude", C.PURPLE + C.BOLD) + color(f" [{model_display}]", C.PURPLE) + color(": ", C.RESET) + highlight_flags(text))
                if contains_confident_flag(strip_ansi(text)):
                    flag_detected_in_text = True

            if tool_uses:
                for t in tool_uses:
                    self.total_tool_calls += 1
                    t_name = getattr(t, 'name')
                    t_input = getattr(t, 'input', {})
                    t_id = getattr(t, 'id')

                    print_tool_call(t_name, t_input)

                    if flag_detected_in_text:
                        result = "Tool execution skipped because a confident flag was already detected in the assistant response."
                    else:
                        result = self._execute_tool_with_confirm(t_name, t_input, auto_execute)

                    tool_result_obj = {"type": "tool_result", "tool_use_id": t_id,
                                      "content": [{"type": "text", "text": result}]}
                    self.conversation_history.append({"role": "user", "content": [tool_result_obj]})
                    self.truncate_history()

                    if result in {"Tool execution declined.", "Tool execution cancelled."}:
                        print(color("--- Stopping after user declined tool execution.", C.BRIGHT_BLACK))
                        return

                    preview, full_path = shorten_preview(result, 800)
                    result_color = C.GREEN + C.BOLD if "flag{" in result.lower() else C.CYAN
                    preview_text = highlight_flags(preview)
                    preview_lines = preview_text.splitlines() if preview_text else []
                    print_tool_result(preview_lines, result_color, full_path)

                    if contains_confident_flag(result):
                        print(color("🎉 Flag detected. Halting further automated steps to prevent redundant work.", C.GREEN + C.BOLD))
                        print(color(f"--- Done ({self.format_token_summary()}) ---\n", C.BRIGHT_BLACK))
                        return
                if flag_detected_in_text:
                    print(color("🎉 Flag detected in assistant response. Halting further automated steps.", C.GREEN + C.BOLD))
                    print(color(f"--- Done ({self.format_token_summary()}) ---\n", C.BRIGHT_BLACK))
                    return
                continue

            if flag_detected_in_text:
                print(color("🎉 Flag detected in assistant response. Halting further automated steps.", C.GREEN + C.BOLD))
                print(color(f"--- Done ({self.format_token_summary()}) ---\n", C.BRIGHT_BLACK))
                return

            print(color(f"--- Done ({self.format_token_summary()}) ---\n", C.BRIGHT_BLACK))
            break

    def _execute_tool_with_confirm(self, tool_name: str, tool_input: dict, auto_execute: bool) -> str:
        try:
            def run_tool() -> str:
                return self.tool_executor.execute_tool(tool_name, tool_input)

            def run_with_animation() -> str:
                thinking = ThinkingAnimation()
                thinking.start()
                try:
                    return run_tool()
                finally:
                    thinking.stop()

            if auto_execute:
                return run_with_animation()

            mode = getattr(self, "_tool_confirmation_mode", "ask")
            if mode == "all":
                return run_with_animation()
            if mode == "none":
                return "Tool execution declined."

            while True:
                choice = input("Execute? [y]es/[n]o/[a]ll/[x] no to all: ").strip().lower()
                normalized = choice.replace(" ", "")

                if normalized in ("y", "yes"):
                    return run_with_animation()

                if normalized in ("a", "all"):
                    self._tool_confirmation_mode = "all"
                    print(color(">>> Executing all remaining tools for this request.", C.BRIGHT_BLACK))
                    return run_with_animation()

                if normalized in ("notoall", "none", "na", "stop", "s", "x"):
                    self._tool_confirmation_mode = "none"
                    print(color(">>> Declining all remaining tools for this request.", C.BRIGHT_BLACK))
                    return "Tool execution declined."

                if normalized in ("", "n", "no"):
                    return "Tool execution declined."

                print(color("Please enter yes, no, all, or no to all.", C.YELLOW))
        except KeyboardInterrupt:
            return "Tool execution cancelled."

# ---------- OpenAI Agent ----------
class OpenAIAgent(BaseAgent):
    def __init__(self, api_key: str, max_history=MAX_HISTORY_ENTRIES, debug: bool = False):
        super().__init__("openai", max_history, debug, system_prompt=OPENAI_SYSTEM_PROMPT)
        self.client = openai.OpenAI(api_key=api_key)
        self.model_light = GPT4O_MINI
        self.model_medium = GPT4O
        self.model_heavy = GPT5
        self.system_delivery = "prepend"

    def define_tools_schema(self):
        return [
            {
                "type": "function",
                "function": {
                    "name": "execute_command",
                    "description": "Run shell command on Kali system",
                    "parameters": {
                        "type": "object",
                        "properties": {
                        "command": {"type": "string", "description": "Shell command to execute"},
                        "shell": {"type": "boolean", "description": "Run through shell (default true)"},
                        "cwd": {"type": "string", "description": "Working directory"},
                        "input": {"type": "string", "description": "String to send to stdin"},
                        "timeout": {"type": "integer", "minimum": 1, "description": "Timeout in seconds"},
                        "env": {
                                "type": "object",
                                "description": "Environment variables",
                                "additionalProperties": {"type": "string"}
                            }
                        },
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
                    "name": "list_directory",
                    "description": "List directory contents",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "show_hidden": {"type": "boolean"},
                            "recursive": {"type": "boolean"}
                        },
                        "required": []
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "search_files",
                    "description": "Search files for a regex pattern",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "pattern": {"type": "string"},
                            "start_path": {"type": "string"},
                            "file_glob": {"type": "string"},
                            "max_results": {"type": "integer", "minimum": 1},
                            "case_sensitive": {"type": "boolean"},
                            "timeout": {"type": "integer", "minimum": 1}
                        },
                        "required": ["pattern"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "extract_archive",
                    "description": "Extract archive (zip/tar/gz)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "archive_path": {"type": "string"},
                            "destination": {"type": "string"}
                        },
                        "required": ["archive_path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "hexdump_file",
                    "description": "Generate a hexdump preview",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "filepath": {"type": "string"},
                            "max_bytes": {"type": "integer", "minimum": 1},
                            "width": {"type": "integer", "minimum": 4}
                        },
                        "required": ["filepath"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "http_fetch",
                    "description": "Perform an HTTP(S) request and return status/headers/body preview",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "method": {"type": "string"},
                            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                            "data": {"type": "string"},
                            "params": {
                                "type": "object",
                                "additionalProperties": {"type": "string"},
                                "description": "Query string parameters to append"
                            },
                            "json": {
                                "type": "object",
                                "description": "JSON body to send with the request",
                                "additionalProperties": True
                            },
                            "save_body": {"type": "boolean", "description": "Always persist the body to a session file"},
                            "timeout": {"type": "integer", "minimum": 1},
                            "follow_redirects": {"type": "boolean"},
                            "insecure": {"type": "boolean"}
                        },
                        "required": ["url"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "file_info",
                    "description": "Display file metadata (size, perms, MIME)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "filepath": {"type": "string"}
                        },
                        "required": ["filepath"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "checksec_analyze",
                    "description": "Run checksec (or pwn checksec) against a binary",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "filepath": {"type": "string"}
                        },
                        "required": ["filepath"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "binwalk_scan",
                    "description": "Run binwalk against a file (optional extraction)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "filepath": {"type": "string"},
                            "extract": {"type": "boolean"},
                            "flags": {"type": "string"}
                        },
                        "required": ["filepath"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "exiftool_scan",
                    "description": "Run exiftool to inspect metadata",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "filepath": {"type": "string"}
                        },
                        "required": ["filepath"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "stegseek_crack",
                    "description": "Attempt to crack stego files with stegseek",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "filepath": {"type": "string"},
                            "wordlist": {"type": "string"},
                            "timeout": {"type": "integer", "minimum": 1}
                        },
                        "required": ["filepath"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "ffuf_scan",
                    "description": "Run ffuf for content discovery/fuzzing",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "wordlist": {"type": "string"},
                            "method": {"type": "string"},
                            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                            "extensions": {"type": ["array", "string"], "items": {"type": "string"}},
                            "threads": {"type": "integer", "minimum": 1},
                            "rate": {"type": "integer", "minimum": 1},
                            "match_status": {"type": "string"},
                            "filter_status": {"type": "string"},
                            "filter_size": {"type": "string"},
                            "timeout": {"type": "integer", "minimum": 1},
                            "silent": {"type": "boolean"}
                        },
                        "required": ["url"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "whatweb_scan",
                    "description": "Fingerprint a target using whatweb",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "aggressive": {"type": "boolean"},
                            "aggression_level": {"type": "integer", "minimum": 1},
                            "plugins": {"type": ["array", "string"], "items": {"type": "string"}},
                            "user_agent": {"type": "string"},
                            "timeout": {"type": "integer", "minimum": 1}
                        },
                        "required": ["url"]
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
        model_lower = model.lower()
        if "gpt-5" in model_lower:
            return "gpt-5"
        elif "gpt-4o-mini" in model_lower:
            return "gpt-4o mini"
        elif "gpt-4o" in model_lower:
            return "gpt-4o"
        elif "gpt-4-turbo" in model_lower:
            return "gpt-4 turbo"
        elif "gpt-4" in model_lower:
            return "gpt-4 (legacy)"
        elif "gpt-3.5" in model_lower:
            return "gpt-3.5"
        return model  # fallback to full name


    def chat(self, user_message: str, auto_execute: bool, inline_model: Optional[str] = None, 
             max_steps: int = DEFAULT_MAX_STEPS):
        self.ensure_system_prompt()
        user_message = self.prepare_user_message(user_message)
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
            self.current_model = model  # Track for cost calculation

            context_error = False
            cancelled = False
            context_retries = 0
            response = None

            while True:
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

                    # Track token usage from response
                    if hasattr(response, 'usage'):
                        self.total_input_tokens += getattr(response.usage, 'prompt_tokens', 0)
                        self.total_output_tokens += getattr(response.usage, 'completion_tokens', 0)

                    break
                except KeyboardInterrupt:
                    thinking.stop()
                    print(color("\n⚠ Request cancelled by user.\n", C.YELLOW))
                    self.conversation_history.append({"role": "user", "content": "[Request cancelled]"})
                    cancelled = True
                    break
                except Exception as e:
                    thinking.stop()
                    if self._is_context_length_error(e) and self._drop_oldest_message():
                        context_retries += 1
                        if context_retries <= self.max_history:
                            print(color("⚠ Context window exceeded. Dropped the oldest exchange and retrying...", C.YELLOW))
                            continue
                    print(color(f"❌ API error: {e}", C.RED))
                    context_error = True
                    break

            if cancelled or context_error:
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
            flag_detected_in_text = False
            if message.content:
                model_display = self.get_model_display_name(model)
                print(color(f"\n🤖 ChatGPT", C.PURPLE + C.BOLD) + color(f" [{model_display}]", C.PURPLE) + color(": ", C.RESET) + highlight_flags(message.content))
                if contains_confident_flag(strip_ansi(message.content)):
                    flag_detected_in_text = True
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

                    print_tool_call(func_name, func_args)

                    if flag_detected_in_text:
                        result = "Tool execution skipped because a confident flag was already detected in the assistant response."
                    else:
                        result = self._execute_tool_with_confirm(func_name, func_args, auto_execute)

                    self.conversation_history.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "name": func_name,
                        "content": result
                    })
                    self.truncate_history()

                    if result in {"Tool execution declined.", "Tool execution cancelled."}:
                        print(color("--- Stopping after user declined tool execution.", C.BRIGHT_BLACK))
                        return None

                    preview, full_path = shorten_preview(result, 800)
                    result_color = C.DARK_GREEN + C.BOLD if "flag{" in result.lower() else C.ORANGE
                    preview_text = highlight_flags(preview)
                    preview_lines = preview_text.splitlines() if preview_text else []
                    print_tool_result(preview_lines, result_color, full_path)

                    if contains_confident_flag(result):
                            print(color("🎉 Flag detected! Blocking further tool execution.", C.GREEN + C.BOLD))
                            self.flag_detected = True

                if flag_detected_in_text:
                    print(color("🎉 Flag detected in assistant response! Blocking further tool execution.", C.GREEN + C.BOLD))
                    self.flag_detected = True
                continue

            if flag_detected_in_text:
                print(color("🎉 Flag detected in assistant response! Blocking further tool execution.", C.GREEN + C.BOLD))
                self.flag_detected = True

            print(color(f"--- Done ({self.format_token_summary()}) ---\n", C.BRIGHT_BLACK))
            break

    def _execute_tool_with_confirm(self, tool_name: str, tool_input: dict, auto_execute: bool) -> str:
        try:
            def run_tool() -> str:
                return self.tool_executor.execute_tool(tool_name, tool_input)

            def run_with_animation() -> str:
                thinking = ThinkingAnimation()
                thinking.start()
                try:
                    return run_tool()
                finally:
                    thinking.stop()

            if auto_execute:
                return run_with_animation()

            mode = getattr(self, "_tool_confirmation_mode", "ask")
            if mode == "all":
                return run_with_animation()
            if mode == "none":
                return "Tool execution declined."

            while True:
                choice = input("Execute? [y]es/[n]o/[a]ll/[x] no to all: ").strip().lower()
                normalized = choice.replace(" ", "")

                if normalized in ("y", "yes"):
                    return run_with_animation()

                if normalized in ("a", "all"):
                    self._tool_confirmation_mode = "all"
                    print(color(">>> Executing all remaining tools for this request.", C.BRIGHT_BLACK))
                    return run_with_animation()

                if normalized in ("notoall", "none", "na", "stop", "s", "x"):
                    self._tool_confirmation_mode = "none"
                    print(color(">>> Declining all remaining tools for this request.", C.BRIGHT_BLACK))
                    return "Tool execution declined."

                if normalized in ("", "n", "no"):
                    return "Tool execution declined."

                print(color("Please enter yes, no, all, or no to all.", C.YELLOW))
        except KeyboardInterrupt:
            return "Tool execution cancelled."

# ---------- Banner / Prompt / Readline ----------
def print_banner(api_provider: str, default_auto_exec: bool, default_max_steps: int, history_window: int, persona_label: str):
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
    history_str = str(history_window)
    persona_str = persona_label or "Default"

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
    print(box_line([
        (" ", C.ORANGE),
        ("🗃  History Depth:", C.ORANGE),
        (" ", C.ORANGE),
        (history_str, C.GREEN + C.BOLD),
    ]))
    print(box_line([
        (" ", C.ORANGE),
        ("🎭 Persona:", C.ORANGE),
        (" ", C.ORANGE),
        (persona_str, C.GREEN + C.BOLD),
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
            ("GPT-5", "(Heavy)"),
            ("GPT-4o", "(Medium)"),
            ("GPT-4o Mini", "(Light)"),
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
    use_color_prompt = ENABLE_COLOR and readline is not None
    glyph = "👾 " if USE_FANCY_PROMPT and use_color_prompt else ""
    label = f"{glyph}Operator"
    if use_color_prompt:
        prompt = color(label, C.CYAN + C.BOLD) + color(f" [{whoami}]", C.MUTED_BLUE) + color(": ", C.RESET)
        return wrap_prompt_ansi(prompt)
    return f"{label} [{whoami}]: "

# ---------- Thinking Animation ----------
class ThinkingAnimation:
    """Animated thinking indicator"""
    def __init__(self):
        self.running = False
        self.thread = None
        if SUPPORTS_UNICODE:
            self.frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        else:
            self.frames = ["-", "\\", "|", "/"]
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
                self.thread = None
            # Clear the thinking line
            sys.stdout.write("\r" + " " * 60 + "\r")
            sys.stdout.flush()

def print_ctf_reference():
    """Print a lightweight CTF cheat sheet."""
    print(color("\nCTF Quick Reference", C.BLUE + C.BOLD))
    for line in CTF_REFERENCE_TEXT.strip().splitlines():
        stripped = line.strip()
        if not stripped:
            print()
            continue
        if stripped.endswith(":"):
            print(color(f"  {stripped}", C.MAGENTA + C.BOLD))
        else:
            print(f"    {line}")
    print()

def print_session_help():
    """Print colorful help banner during session"""
    print(color("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", C.CYAN))
    print(color("                           💡 OPERATIVE HELP", C.CYAN + C.BOLD))
    print(color("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", C.CYAN))
    
    print(color("\n🔧 INLINE FLAGS", C.YELLOW + C.BOLD))
    print(color("  Use these in your messages to override settings:\n", C.BRIGHT_BLACK))
    print(color("\n  --model=MODEL", C.GREEN) + "           Select model tier")
    print(color("                          ", C.BRIGHT_BLACK) + "Options: light, medium, heavy")
    print(color("\n  --auto-execute=BOOL", C.GREEN) + "     Override auto-execute for this message")
    print(color("                          ", C.BRIGHT_BLACK) + "Values: true, false")
    print(color("\n  --max-steps=N", C.GREEN) + "           Limit conversation steps")
    print(color("                          ", C.BRIGHT_BLACK) + "Example: --max-steps=20")
    
    print(color("\n📝 USAGE EXAMPLES", C.MAGENTA + C.BOLD))
    print(color("  Scan 10.10.10.5 --model=light", C.BRIGHT_BLACK))
    print(color("  Read /etc/passwd --auto-execute=false", C.BRIGHT_BLACK))
    print(color("  Analyze binary --model=heavy --max-steps=30", C.BRIGHT_BLACK))
    print(color("  Quick recon --model=medium", C.BRIGHT_BLACK))
    
    print(color("\n⌨  SESSION COMMANDS", C.BLUE + C.BOLD))
    print(color("  :reset  ", C.CYAN) + "  Clear conversation history (aliases: reset, clear-history)")
    print(color("  :files  ", C.CYAN) + "  List files created this session (aliases: :ls, ls)")
    print(color("  :paste  ", C.CYAN) + "  Multi-line paste mode (aliases: paste) Usage: Type :paste, paste content, then type END on new line")
    print(color("  :reference", C.CYAN) + "  Show CTF quick reference (aliases: :ctf, :cheatsheet)")
    print(color("  :help   ", C.CYAN) + "  Show this help message (aliases: help, -h, --help)")
    print(color("  quit    ", C.CYAN) + "  Exit the agent (aliases: exit, q)")

    print(color("\nPERSONA MODES", C.BLUE + C.BOLD))
    print(color("  >persona <name>", C.CYAN) + color("  Switch persona instantly. Highlights:", C.BRIGHT_BLACK))
    for key in sorted(PERSONA_PRESETS.keys()):
        summary = PERSONA_SUMMARIES.get(
            key,
            "Custom persona profile."
        )
        print(
            color(f"      {key:<8}", C.CYAN + C.BOLD)
            + color(f" - {summary}", C.BRIGHT_BLACK)
        )
    print(color("  >persona list", C.CYAN) + color("   Show personas with the active mode marked.", C.BRIGHT_BLACK))
    print(color("  >persona reset", C.CYAN) + color("  Return to the default assistant voice.", C.BRIGHT_BLACK))
    
    print(color("\n🛠  AVAILABLE TOOLS", C.RED + C.BOLD))
    print(color("  • execute_command     ", C.YELLOW) + "Run shell commands")
    print(color("  • read_file           ", C.YELLOW) + "Read files (text/hex/binary)")
    print(color("  • write_file          ", C.YELLOW) + "Save content to /tmp/ (auto-tracked)")
    print(color("  • list_session_files  ", C.YELLOW) + "Show files created this session")
    print(color("  • list_directory      ", C.YELLOW) + "Inspect folders (supports hidden/recursive)")
    print(color("  • search_files        ", C.YELLOW) + "Regex search with ripgrep or Python fallback")
    print(color("  • extract_archive     ", C.YELLOW) + "Unpack zip/tar/gz archives")
    print(color("  • hexdump_file        ", C.YELLOW) + "Preview bytes in hex/ascii")
    print(color("  • file_info           ", C.YELLOW) + "Quick metadata (size/perms/MIME)")
    print(color("  • checksec_analyze    ", C.YELLOW) + "Assess binary protections")
    print(color("  • binwalk_scan        ", C.YELLOW) + "Scan firmware/images (optional extract)")
    print(color("  • exiftool_scan       ", C.YELLOW) + "Enumerate file metadata")
    print(color("  • stegseek_crack      ", C.YELLOW) + "Attempt steg password crack")
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

  # Keep longer history
  python3 operatives.py --max-history=40

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                        🔧 INLINE FLAGS (During Chat)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Use these flags in your messages to override settings per-request:

  --model=MODEL           Select model tier
                          Options: light, medium, heavy
  
  --auto-execute=BOOL     Override auto-execute for this message
                          Values: true, false
  
  --max-steps=N           Limit conversation steps for this request
                          Example: --max-steps=20

Chat Examples:

  👾 Operator Scan 10.10.10.5 --model=light
  
  👾 Operator Read /etc/passwd --auto-execute=false
  
  👾 Operator Deep analysis of this binary --model=heavy --max-steps=30
  
  👾 Operator Quick recon --model=light

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                          ⌨  SESSION COMMANDS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  :reset          Clear conversation history (aliases: reset, clear-history)
  :files          List files created this session (aliases: :ls, ls)
  :paste          Multi-line paste mode - Type :paste, paste content, type END to finish
  :reference      Show CTF quick reference (aliases: :ctf, :cheatsheet)
  :help           Show this help message (aliases: help, -h, --help)
  quit            Exit the agent (aliases: exit, q)

PERSONA MODES
  >persona <name>  Switch persona instantly. Highlights:
      default   - Neutral, straightforward guidance without stylistic flair.
      genz      - Playful Gen-Z energy with friendly slang and upbeat memes.
      mentor    - Calm senior analyst voice focused on reassurance and risk awareness.
      speedrun  - Ultra-concise rapid-fire instructions aimed at speed.
      retro     - 90s hacker nostalgia with leetspeak vibes and high energy.
      ops       - Mission-operations tone emphasizing checklists and contingencies.
      teacher   - Encouraging instructor who explains reasoning and offers exercises.
  >persona list    Show personas with the active mode marked
  >persona reset   Return to the default assistant voice

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                        🔑 ENVIRONMENT VARIABLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Required (based on API choice):

  ANTHROPIC_API_KEY      For Claude API access
  OPENAI_API_KEY         For ChatGPT API access

Setup:
  export ANTHROPIC_API_KEY="..."
  export OPENAI_API_KEY="..."

You only need the key for the API you intend to use.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                           🛠  AVAILABLE TOOLS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  • execute_command      Run shell commands (supports cwd/timeout/env)
  • read_file            Read files (text/hex/binary)
  • write_file           Save content to /tmp/ (auto-tracked)
  • list_directory       Inspect folders (hidden/recursive options)
  • search_files         Regex search (ripgrep or Python fallback)
  • extract_archive      Unpack zip/tar/gz archives
  • hexdump_file         Preview bytes in hex/ascii
  • file_info            Quick metadata (size/perms/MIME)
  • checksec_analyze     Assess binary protections
  • binwalk_scan         Scan firmware/images (optional extract)
  • exiftool_scan        Enumerate file metadata
  • stegseek_crack       Attempt steg password crack
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
    parser.add_argument("--max-history", type=int, default=MAX_HISTORY_ENTRIES,
                       help=f"Conversation turns to retain (default: {MAX_HISTORY_ENTRIES})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    api_provider = args.api.lower()
    default_auto_exec = args.auto_execute.lower() == "true"
    default_max_steps = max(1, args.max_steps)
    max_history = max(1, args.max_history)

    # Check API availability and get key
    if api_provider == "claude":
        if not ANTHROPIC_AVAILABLE:
            print(color("❌ Anthropic SDK not installed. Run: pip install anthropic", C.RED))
            return
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            print(color("❌ Missing ANTHROPIC_API_KEY environment variable", C.RED))
            return
        agent = ClaudeAgent(api_key, max_history=max_history, debug=args.debug)
        
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
        agent = OpenAIAgent(api_key, max_history=max_history, debug=args.debug)
        
        # Set generic aliases to OpenAI models
        MODEL_ALIASES["light"] = GPT4O_MINI
        MODEL_ALIASES["medium"] = GPT4O
        MODEL_ALIASES["heavy"] = GPT5

    setup_readline()
    persona_display_names = {
        "default": "Default",
        "genz": "Gen-Z",
        "mentor": "Mentor",
        "speedrun": "Speedrun",
        "retro": "Retro",
        "ops": "Ops",
        "teacher": "Teacher",
    }
    initial_persona = getattr(agent, "persona_style", "default")
    persona_label = persona_display_names.get(
        initial_persona,
        initial_persona.replace("_", " ").title()
    )
    print_banner(api_provider, default_auto_exec, default_max_steps, max_history, persona_label)

    try:
        while True:
            try:
                raw = input(prompt_string())
            except (KeyboardInterrupt, EOFError):
                print(color("\n⚠  Interrupted. Clearing input buffer...", C.YELLOW))
                # Clear any remaining input in the buffer
                try:
                    import sys
                    if sys.platform != "win32":
                        import termios
                        termios.tcflush(sys.stdin, termios.TCIFLUSH)
                    else:
                        import msvcrt
                        while msvcrt.kbhit():
                            msvcrt.getch()
                except Exception:
                    pass
                print(color("⚡ Input cleared. Ready for next command.", C.YELLOW))
                continue

            if not raw:
                continue

            raw_strip = raw.strip()
            if raw_strip.startswith(">"):
                raw_strip = raw_strip[1:].lstrip()
                if not raw_strip:
                    continue

            # special in-session commands
            if raw_strip.lower() in (":reset", "reset", "clear-history"):
                agent.conversation_history = []
                agent._system_message_inserted = False
                agent._system_prompt_consumed = False
                agent._system_prompt_prefix = None
                print(color("⚡ History cleared", C.YELLOW))
                continue

            if raw_strip.lower() in (":help", "-h", "--help", "help"):
                print_session_help()
                continue
            
            if raw_strip.lower() in (":reference", ":ctf", ":cheatsheet"):
                print_ctf_reference()
                continue
            
            if raw_strip.lower() in (":files", ":ls", "ls"):
                print(color(agent.tool_executor.get_session_files(), C.CYAN))
                continue

            tokens = raw_strip.split()
            if tokens and tokens[0].lower() == "persona":
                sub_tokens = tokens[1:]
                current = getattr(agent, "persona_style", "default")
                if not sub_tokens:
                    current_summary = PERSONA_SUMMARIES.get(
                        current,
                        "Custom persona profile."
                    )
                    print(color(
                        f"Active persona: {current} - {current_summary}",
                        C.CYAN
                    ))
                    print(color("Use '>persona list' to see options or '>persona <name>' to switch.", C.BRIGHT_BLACK))
                else:
                    subcommand = sub_tokens[0].lower()
                    if subcommand in {"list", "ls", "show"}:
                        print(color("Available personas:", C.CYAN + C.BOLD))
                        for key in sorted(PERSONA_PRESETS.keys()):
                            summary = PERSONA_SUMMARIES.get(
                                key,
                                "Custom persona profile."
                            )
                            marker = "*" if key == current else " "
                            name_color = C.GREEN + C.BOLD if key == current else C.CYAN
                            print(
                                color(f"  {marker} ", C.BRIGHT_BLACK)
                                + color(f"{key:<8}", name_color)
                                + color(f" - {summary}", C.BRIGHT_BLACK)
                            )
                        print(color("  * Active persona", C.BRIGHT_BLACK))
                    elif subcommand in {"set", "use"}:
                        if len(sub_tokens) >= 2:
                            target = " ".join(sub_tokens[1:])
                            success, msg = agent.set_persona(target)
                            print(color(msg, C.GREEN if success else C.YELLOW))
                        else:
                            print(color("Usage: >persona <name>", C.YELLOW))
                    elif subcommand in {"reset", "default"}:
                        success, msg = agent.set_persona("default")
                        print(color(msg, C.GREEN if success else C.YELLOW))
                    else:
                        target = " ".join(sub_tokens)
                        success, msg = agent.set_persona(target)
                        print(color(msg, C.GREEN if success else C.YELLOW))
                continue

            # Multi-line paste mode
            # Multi-line paste mode
            if raw_strip.lower() in (":paste", "paste"):
                print(color("📋 Multi-line paste mode activated.", C.CYAN))
                print(color("   Paste your content below, then type 'END' on a new line to finish.", C.BRIGHT_BLACK))
                print(color("   All newlines will be converted to spaces.\n", C.BRIGHT_BLACK))
                lines = []
                try:
                    while True:
                        line = input()
                        if line.strip().upper() == "END":
                            break
                        lines.append(line)
                except (KeyboardInterrupt, EOFError):
                    print(color("\n⚠  Paste cancelled.", C.YELLOW))
                    continue
                
                if not lines:
                    print(color("⚠  No content pasted.", C.YELLOW))
                    continue
                
                # Join all lines with spaces, removing newlines
                raw = " ".join(lines)
                print(color(f"\n✓ Captured {len(lines)} lines as single message.", C.GREEN))
                
                # Skip inline flag parsing for pasted content - send directly to agent
                agent.chat(raw, auto_execute=default_auto_exec, inline_model=None, 
                        max_steps=default_max_steps)
                save_history()
                continue  # Skip the normal message processing pipeline
            if raw_strip.lower() in ("quit", "exit", "q"):
                total_tokens = agent.total_input_tokens + agent.total_output_tokens
                print(f"\n📊 Session Summary:")
                print(f"  API requests:   {agent.total_api_requests}")
                print(f"  Tool calls:     {agent.total_tool_calls}")
                print(f"  Input tokens:   {agent.total_input_tokens:,}")
                print(f"  Output tokens:  {agent.total_output_tokens:,}")
                print(f"  Total tokens:   {total_tokens:,}")
                print(f"  {agent.format_token_summary().split('tokens: ')[1]}")  # Just show the cost
                break

            message, auto_exec, inline_model_raw, max_steps = parse_inline_flags(
                raw, default_auto_exec, default_max_steps
            )

            # Validate message is not empty after flag parsing
            if not message.strip():
                print(color("⚠  Empty message. Please provide a command or question.", C.YELLOW))
                continue

            # Validate model if provided
            inline_model = None
            if inline_model_raw:
                low = inline_model_raw.lower()
                if low in MODEL_ALIASES:
                    inline_model = MODEL_ALIASES[low]
                elif inline_model_raw in (CLAUDE_MODELS if api_provider == "claude" else OPENAI_MODELS):
                    inline_model = inline_model_raw
                else:
                    print(color(f"⚠  Unknown model '{inline_model_raw}'. Valid options: light, medium, heavy", C.YELLOW))
                    continue

            # Validate max_steps range
            if max_steps < 1:
                print(color(f"⚠  Invalid max-steps '{max_steps}'. Must be at least 1. Using default: {DEFAULT_MAX_STEPS}", C.YELLOW))
                max_steps = DEFAULT_MAX_STEPS

            agent.chat(message, auto_execute=auto_exec, inline_model=inline_model, 
                      max_steps=max_steps)
            save_history()

    finally:
        save_history()


if __name__ == "__main__":
    main()      

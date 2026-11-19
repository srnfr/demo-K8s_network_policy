#!/usr/bin/env python3
"""polinrider_scan.py - a static scanner for the PolinRider / Contagious Interview fake-font
implant, the #ghc2 stealer, and the GhostAction GitHub Actions workflow (including its
self-hosted runner backdoor).

It reads files as bytes and matches patterns. It never runs, imports, evaluates or fetches
anything it finds, and it never starts node or npm: a trojaned npm restarts the backdoor on
every command, so even `npm root -g` is off limits here.

    python3 -I polinrider_scan.py [PATH ...]     scan repositories (default: the current folder)
    python3 -I polinrider_scan.py --machine      check this computer for the persistence
    add --json for machine-readable output

Exit codes: 0 nothing found, 1 at least one finding, 2 the scan itself failed.
Standard library only. Written for Python 3.7 or newer on Windows, macOS and Linux; tested on Linux with 3.12 and 3.14.
"""
import argparse
import base64
import codecs
import fnmatch
import getpass
import glob
import json
import os
import re
import socket
import stat
import subprocess
import sys

VERSION = "0.2.0"
HIGH, REVIEW = "high", "review"
SELF = os.path.realpath(os.path.abspath(__file__))
try:
    with open(SELF, "rb") as _fh:
        SELF_BYTES = _fh.read()
except OSError:
    SELF_BYTES = None

# ---------------------------------------------------------------------------------------------
# Patterns. Every one of them was seen in infected repositories or in the captured stages.
# ---------------------------------------------------------------------------------------------

FONT_EXT = {".woff", ".woff2", ".ttf", ".otf", ".eot"}
# Extensions the campaign uses that are not font formats at all, so any text in them is the implant.
LOOKALIKE_EXT = {".orc", ".lkf", ".llf", ".lfk"}
# Look-alikes that ARE real formats (glTF binary, other tools' text): flagged only when code-like.
WEAK_LOOKALIKE_EXT = {".glb", ".fml"}
ALL_FONTLIKE = FONT_EXT | LOOKALIKE_EXT | WEAK_LOOKALIKE_EXT
# Image extensions the campaign also uses for the payload (seen: .svg, .jpeg). Flagged only when
# the text is JavaScript, since an SVG is legitimately text.
IMAGE_EXT = {".svg", ".jpg", ".jpeg", ".png", ".gif", ".ico", ".webp", ".bmp"}
# How a JavaScript file starts (after whitespace padding). Real payloads seen: `var a0mHTc,...`,
# `(function(P,E){...`, `const _0x34d9=...`, `function EJWG$rr...(`, `global.i = ...`.
JS_START = re.compile(rb"""^\s*(?:#!/usr/bin/env node|['"]use strict['"]|(?:var|let|const|function|async|class|import|export)\b"""
                      rb"""|\(\s*(?:function|async|\()|!function|global\s*[.\[]|module\.exports|require\s*\()""")

CODE_EXT = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}
# Files whose text is searched for the fixed markers. Documentation (.md, .txt) is left out on
# purpose: threat reports and blocklists quote these markers.
TEXT_SCAN_EXT = CODE_EXT | {".json", ".sh", ".bash", ".zsh", ".cmd", ".bat", ".ps1", ".py",
                            ".yml", ".yaml", ""}

# Real font and other binary signatures (first bytes).
FONT_MAGIC = (b"wOF2", b"wOFF", b"OTTO", b"\x00\x01\x00\x00", b"true", b"typ1", b"ttcf")
IMAGE_MAGIC = (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF", b"BM")
OTHER_MAGIC = (b"glTF", b"ORC")
LFS_POINTER = b"version https://git-lfs.github.com/spec/v1"

MARKERS = [
    ("global['!']", re.compile(rb"""global\[\s*['"]!['"]\s*\]\s*=""")),
    ("global['_V']", re.compile(rb"""global\[\s*['"]_V['"]\s*\]\s*=""")),
    ("global.i=", re.compile(rb"""global\.i\s*=\s*['"`]""")),
    ("/*C2.....A*/ injector marker", re.compile(rb"/\*C2\d{5}A\*/")),
    ("/*M2.....A*/ npm injector marker", re.compile(rb"/\*M2\d{5}A\*/")),
    ("/*RS2.....*/ loader marker", re.compile(rb"/\*RS2\d{5}\*/")),
    ("/*NPM_WS_SHIM*/ npm shim marker", re.compile(rb"/\*NPM_WS_SHIM\*/")),
    ("__inzRQ / __inzCR app-injection names", re.compile(rb"__inz(?:RQ|CR|V)\b")),
    ("require of a .inz.cjs file", re.compile(rb"""require\s*\(\s*['"][^'"\r\n]{0,300}\.inz\.cjs['"]""")),
    (".npm-ws-runner.js backdoor runner", re.compile(rb"\.npm-ws-runner\.js")),
    ("_$_1e42 obfuscator table", re.compile(rb"_\$_1e42")),
    ("rmcej%otb% config variant", re.compile(rb"rmcej%otb%")),
    ("#ghc2 stealer tag", re.compile(rb"#ghc2\b")),
    ("DEVBOX user= stealer beacon", re.compile(rb"DEVBOX user=")),
    ("193.32.204.199 stealer collector", re.compile(rb"193\.32\.204\.199")),
]
OBFUSCATED = re.compile(rb"_0x[0-9a-f]{4,6}")

# GhostAction: a GitHub Actions workflow, pushed with a stolen login, that sends secrets to this
# address when GitHub runs it. Its runner-backdoor version reads the self-hosted runner's own
# disk and installs a crontab line instead. A workflow file is judged as a workflow (rule names
# below), so its advice is about GitHub secrets, not about cleaning a computer.
GHOSTACTION_ADDR = re.compile(rb"193\.32\.204\.199")
WORKFLOW_PATH = re.compile(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$")
RUNNER_BACKDOOR = re.compile(rb"\bcrontab\b|~/\.ssh/id_|\.aws/credentials|\.git-credentials|169\.254\.169\.254"
                             rb"|\.kube/config|\.docker/config\.json", re.I)
SELF_HOSTED = re.compile(rb"runs-on:[^\n]*self-hosted", re.I)
GHOSTACTION_RULES = ("ghostaction-workflow", "ghostaction-runner-backdoor")

# Rule 3: a long line with a long whitespace run followed by code.
LONG_LINE = 2000
# The lookbehind makes a match start only where a run starts, which keeps the search linear on a
# very long run. Vertical tab, form feed and no-break space are whitespace to JavaScript too.
WS_RUN = re.compile(rb"(?<![ \t\x0b\x0c\xa0])(?:[ \t\x0b\x0c]|\xc2\xa0){100,}")
# What the code after the run looks like when it is the implant (used outside config files,
# where a whitespace run alone is not enough to call it).
EVIL_TAIL = re.compile(rb"""global\.i\s*=|global\[\s*['"]|_0x[0-9a-f]{4}|_\$_[0-9a-f]{4}|rmcej%otb%"""
                       rb"""|__inz|/\*(?:C2|M2|RS2)\d{5}A?\*/|\beval\s*\(|\bFunction\s*\("""
                       rb"""|child_process|\brequire\s*\(|fromCharCode|\batob\s*\(""")
CONFIG_FILE = re.compile(r"(?:^|/)(?:[\w.-]*[.-])?config\.(?:m?js|cjs|ts|mts|cts)$"
                         r"|(?:^|/)\.eslintrc\.c?js$|(?:^|/)\.babelrc\.c?js$|(?:^|/)(?:init|api\.js)$")

# Rule 1: commands in a folder-open task.
PATHISH = re.compile(r"""\bnode(?:js)?(?:\.exe)?['"]?\s+(?:--?[\w=.-]+\s+)*['"\\]*([^\s'"&|;)<>]+)""")
# the wrapper form: the path may hold spaces and parentheses, so it ends only at the ")" before || or the end
WRAP = re.compile(r"""\bnode(?:\.exe)?\s+['"]?(\.{0,2}/[^&|;'"]+?)['"]?\s*\)\s*(?:\|\||$)""")
# `node <path>` inside a wrapper script or a command: the path is quoted, or ends at whitespace or a
# shell operator (so `node x.woff2 &`, `nohup node x >/dev/null 2>&1 &` and `>nul` all read).
NODE_IN_SCRIPT = re.compile(r"""\bnode(?:js)?(?:\.exe)?\s+(?:--?[\w=.-]+\s+)*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s'"&|;<>()]+))""")
# "the folder this script is in", which a wrapper uses to reach the payload
SCRIPT_DIR = re.compile(r"""\$\(\s*dirname\s+["']?\$\{?0\}?["']?\s*\)/?|%~dp0|\$PSScriptRoot[\\/]?""")
WRAPDIR = "\x00wrapdir\x00/"
PATHLIKE = re.compile(r"[/\\]|\.[A-Za-z0-9]{1,6}$")
SCRIPT_TOKEN = re.compile(r"""([^\s'"&|;()<>]+\.(?:sh|cmd|bat|ps1))(?=$|[\s'"&|;()<>])""", re.I)
REMOTE_PIPE = re.compile(r"""\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|\n]{0,300}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|node|python3?|iex|Invoke-Expression)\b""", re.I)

# Rule 4: `node <file>` in an npm script. The delimiter after it is a lookahead, so in
# `node a.js && node b.woff2 && next dev` both runs are read. Group 2 is what follows the file.
LAUNCH = re.compile(r"""(?:^|&&|\|\||;|&)\s*(?:npx\s+)?node(?:\.exe)?\s+(?:--?[\w=.-]+\s+)*['"]?([^\s'"&|;<>()]+)['"]?\s*(?=(&&|;|&|\|\||$))""")

# Rule 5: .gitignore entries the operator's push scripts leave behind.
GITIGNORE_NAMES = {"config.bat", "temp_auto_push.bat", "temp_interactive_push.bat", "branch_structure.json"}
GITIGNORE_STRONG = {"temp_auto_push.bat", "temp_interactive_push.bat"}

DEFAULT_SKIP_DIRS = {".git", "node_modules", ".hg", ".svn"}


# ---------------------------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------------------------

def ext_of(path):
    base = os.path.basename(path)
    return os.path.splitext(base)[1].lower() if "." in base.lstrip(".") else ""


def quote(b, n=60):
    """A short, printable, ASCII-only quotation of untrusted bytes."""
    if isinstance(b, bytes):
        b = b.decode("utf-8", "replace")
    s = b[:n]
    s = "".join(c if 32 <= ord(c) < 127 else "\\x%02x" % ord(c) if ord(c) < 256 else "\\u%04x" % ord(c) for c in s)
    return s + ("..." if len(b) > n else "")


def read_bytes(path, cap):
    with open(path, "rb") as fh:
        return fh.read(cap)


def looks_text(head):
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return True
    if b"\x00" in head:
        return False
    try:
        codecs.getincrementaldecoder("utf-8")().decode(head, final=False)
        return True
    except UnicodeDecodeError:
        ok = sum(32 <= c < 127 or c in (9, 10, 13) for c in head)
        return ok / max(1, len(head)) > 0.95


def decode_text(b):
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return b.decode("utf-16", "replace")
    if b[:3] == b"\xef\xbb\xbf":
        b = b[3:]
    return b.decode("utf-8", "replace")


def strip_jsonc(t):
    """JSON with comments and trailing commas (what VS Code accepts) -> plain JSON text."""
    out, i, n, q = [], 0, len(t), False
    while i < n:
        c = t[i]
        if q:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(t[i + 1])
                i += 1
            elif c == '"':
                q = False
        elif c == '"':
            q = True
            out.append(c)
        elif t[i:i + 2] == "//":
            while i < n and t[i] != "\n":
                i += 1
            continue
        elif t[i:i + 2] == "/*":
            j = t.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def load_jsonc(b):
    try:
        return json.loads(strip_jsonc(decode_text(b)), strict=False)
    except (ValueError, RecursionError):
        return None


def s_of(x):
    if isinstance(x, str):
        return x
    if isinstance(x, dict):
        return str(x.get("value", ""))
    if isinstance(x, list):
        return " ".join(s_of(i) for i in x)
    return ""


def norm_target(p):
    p = p.strip().strip("'\"")
    for v in ("${workspaceFolder}/", "${workspaceRoot}/", "${workspaceFolder}\\", "${workspaceRoot}\\",
              "${cwd}/", "$PWD/", "%cd%/", "%cd%\\"):
        if p.startswith(v):
            p = p[len(v):]
    if p in ("${workspaceFolder}", "${workspaceRoot}", "${cwd}", "$PWD", "%cd%", "."):
        return ""
    p = p.replace("\\\\", "/").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def node_paths(text):
    """Every path-like argument given to `node` in a command or script."""
    out = []
    for m in NODE_IN_SCRIPT.finditer(text):
        t = m.group(1) or m.group(2) or m.group(3)
        if t and PATHLIKE.search(t):
            out.append(t)
    return out


def markers_in(data):
    return [name for name, rx in MARKERS if rx.search(data)]


def hidden_tail(data, min_line=LONG_LINE):
    """-> (line number, whitespace run length, the code that follows) for a long line holding a
    run of 100+ whitespace characters followed by printable code (not control bytes, which is what
    a data table looks like), else None. A line whose code looks like the implant wins over an
    earlier one that does not, so a harmless padded line cannot mask a real one."""
    first = None
    for no, ln in enumerate(data.splitlines(), 1):
        if len(ln) < min_line:
            continue
        for m in WS_RUN.finditer(ln):
            e = m.end()
            if e < len(ln) and 0x21 <= ln[e] <= 0x7e:
                hit = (no, e - m.start(), ln[e:e + 200])
                if EVIL_TAIL.search(hit[2]):
                    return hit
                if first is None:
                    first = hit
                break
    return first


def classify(data, ext=""):
    """What a file's bytes are. -> (class, facts). Never decodes anything for execution."""
    facts = {}
    if not data:
        return "empty", facts
    head = data[:4096]
    if head.startswith(LFS_POINTER) and len(data) < 1024 and re.search(rb"\noid sha256:[0-9a-f]{64}\n", data) \
            and not markers_in(data):
        return "lfs_pointer", facts
    # Text is decided BEFORE the signatures: `true` (Apple TrueType) is also valid JavaScript, so a
    # payload that starts `true;` must not pass as a font. Real font headers always hold NUL bytes.
    if not looks_text(head):
        if any(head.startswith(s) for s in FONT_MAGIC) or (len(head) >= 36 and head[34:36] == b"LP"):
            return "real_font", facts
        if any(head.startswith(s) for s in IMAGE_MAGIC):
            return "real_image", facts
        if any(head.startswith(s) for s in OTHER_MAGIC):
            return "other_binary_format", facts
        return "binary_other", facts
    if not data.strip():
        return "whitespace_only", facts
    facts["markers"] = markers_in(data)
    t = hidden_tail(data, min_line=0 if ext in ALL_FONTLIKE else LONG_LINE)
    if t:
        facts["tail"] = {"line": t[0], "run": t[1], "code": quote(t[2], 40)}
    if facts["markers"]:
        return "text_marker", facts
    if OBFUSCATED.search(data[:200000]):
        return "text_obfuscated", facts
    if not head.strip():
        return "text_after_blank_padding", facts
    if t:
        return "text_hidden_tail", facts
    return "text_plain", facts


CLASS_TEXT = {
    "missing": "file is missing",
    "empty": "file is empty",
    "lfs_pointer": "a Git LFS pointer",
    "real_font": "a real font",
    "real_image": "an image",
    "other_binary_format": "a known binary format",
    "binary_other": "unrecognized binary",
    "whitespace_only": "only whitespace",
    "text_marker": "TEXT with campaign markers",
    "text_obfuscated": "TEXT, obfuscated JavaScript",
    "text_after_blank_padding": "TEXT after a block of blank padding",
    "text_hidden_tail": "TEXT with code hidden after a long whitespace run",
    "text_plain": "plain text",
}
SUSPICIOUS = {"text_marker", "text_obfuscated", "text_after_blank_padding", "text_hidden_tail"}


def describe(cls, facts):
    s = CLASS_TEXT.get(cls, cls)
    bits = []
    if facts.get("markers"):
        bits.append("markers: " + ", ".join(facts["markers"]))
    if facts.get("tail"):
        tl = facts["tail"]
        bits.append("line %d: %d spaces/tabs, then `%s`" % (tl["line"], tl["run"], tl["code"]))
    return s + (" (" + "; ".join(bits) + ")" if bits else "")


# ---------------------------------------------------------------------------------------------
# Repository scan
# ---------------------------------------------------------------------------------------------

class RepoScan:
    def __init__(self, root, skip_dirs, excludes, cap):
        root = os.path.abspath(root)
        # a single file is scanned from its own folder, so its name still selects its rule
        self.single = root if os.path.isfile(root) else None
        self.root = os.path.dirname(root) if self.single else root
        self.skip_dirs = skip_dirs
        self.excludes = excludes
        self.cap = cap
        self.findings = []
        self.checked = {"files": 0, "font_like_files": 0, "task_files": 0, "package_json": 0,
                        "gitignore": 0, "config_files": 0, "code_files": 0, "workflow_files": 0, "unreadable": 0,
                        "truncated": 0}

    # -- plumbing ---------------------------------------------------------------------------
    def rel(self, p):
        try:
            r = os.path.relpath(p, self.root)
        except ValueError:  # Windows: another drive
            return p
        return r.replace(os.sep, "/")

    def add(self, rule, severity, path, detail, **extra):
        f = {"rule": rule, "severity": severity, "path": self.rel(path) if os.path.isabs(path) else path,
             "detail": detail}
        f.update(extra)
        self.findings.append(f)

    def read(self, path):
        """Regular files only (a named pipe would block forever). A file larger than the cap is read
        as its first and last halves, because the implant is appended at the END of a file."""
        try:
            st = os.stat(path)
            if not stat.S_ISREG(st.st_mode):
                return None
            if st.st_size <= self.cap:
                return read_bytes(path, self.cap)
            self.checked["truncated"] += 1
            half = max(1, self.cap // 2)
            with open(path, "rb") as fh:
                head = fh.read(half)
                fh.seek(st.st_size - half)
                return head + b"\n" + fh.read(half)
        except OSError:
            self.checked["unreadable"] += 1
            return None

    # File-existence hooks: one place to answer "is this a file", so a scan can also be run
    # against bytes held in memory (the measurement does that; nothing captured touches disk).
    def isfile(self, p):
        return os.path.isfile(p)

    def exists(self, p):
        return os.path.exists(p)

    def excluded(self, rel):
        return any(fnmatch.fnmatch(rel, pat) for pat in self.excludes)

    def inside(self, p):
        try:
            return os.path.commonpath([os.path.realpath(p), os.path.realpath(self.root)]) == os.path.realpath(self.root)
        except ValueError:
            return False

    def walk_error(self, err):
        self.checked["unreadable"] += 1
        where = getattr(err, "filename", None) or self.root
        self.add("unreadable", REVIEW, where, "could not read this folder (%s), so nothing in it was checked" % (
            err.strerror or type(err).__name__))

    def run(self):
        if self.single:
            self.scan_file(self.single)
            return self
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False, onerror=self.walk_error):
            dirnames[:] = sorted(d for d in dirnames
                                 if d not in self.skip_dirs and not self.excluded(self.rel(os.path.join(dirpath, d))))
            for name in sorted(filenames):
                p = os.path.join(dirpath, name)
                try:
                    if not stat.S_ISREG(os.lstat(p).st_mode):  # symbolic links, pipes, devices
                        continue
                except OSError:
                    continue
                if self.excluded(self.rel(p)):
                    continue
                if os.path.realpath(p) == SELF or self.is_self_copy(p):
                    continue
                self.scan_file(p)
        return self

    @staticmethod
    def is_self_copy(p):
        """A byte-identical copy of this scanner (vendored into the repository) is not a finding."""
        try:
            return SELF_BYTES is not None and os.path.getsize(p) == len(SELF_BYTES) and read_bytes(p, len(SELF_BYTES) + 1) == SELF_BYTES
        except OSError:
            return False

    def scan_file(self, p):
        self.checked["files"] += 1
        name = os.path.basename(p)
        rel = self.rel(p)
        ext = ext_of(name)
        parent = os.path.basename(os.path.dirname(p))
        if WORKFLOW_PATH.search(os.path.abspath(p).replace(os.sep, "/")):
            self.check_workflow(p)
        elif name == "tasks.json" and parent == ".vscode":
            self.check_tasks(p, os.path.dirname(os.path.dirname(p)))
        elif name.endswith(".code-workspace"):
            self.check_tasks(p, os.path.dirname(p))
        elif name == "package.json":
            self.check_package(p)
        elif name == ".gitignore":
            self.check_gitignore(p)
        elif ext in ALL_FONTLIKE:
            self.check_font(p, ext)
        elif ext in IMAGE_EXT:
            self.check_image(p, ext)
        elif CONFIG_FILE.search(rel):
            self.check_config(p)
        elif ext in TEXT_SCAN_EXT:
            self.check_code(p, ext)
        # package.json and tasks files can hold markers too
        if name in ("tasks.json", "package.json") or name.endswith(".code-workspace"):
            data = self.read(p)
            if data:
                m = markers_in(data)
                if m:
                    self.add("marker", HIGH, p, "campaign markers: " + ", ".join(m))

    # -- rule 2: fake fonts -----------------------------------------------------------------
    def check_font(self, p, ext):
        self.checked["font_like_files"] += 1
        data = self.read(p)
        if data is None:
            return
        cls, facts = classify(data, ext)
        if cls == "whitespace_only":
            self.add("fake-font", REVIEW, p, "font file holds only whitespace (a placeholder the implant uses)")
            return
        if not cls.startswith("text"):
            return
        if ext in WEAK_LOOKALIKE_EXT and cls not in SUSPICIOUS and not JS_START.match(data[:4096]):
            return
        if cls == "text_plain" and data.lstrip()[:15].lower().startswith((b"<!doctype", b"<html", b"<?xml", b"<svg")):
            self.add("fake-font", REVIEW, p, "%s file holds a web page or markup, not a font (often a broken download; check by hand)" % ext)
            return
        self.add("fake-font", HIGH, p,
                 "%s file is not a font: %s" % (ext, describe(cls, facts)), content=cls, ghc2=self.is_ghc2(facts))

    def check_image(self, p, ext):
        """JavaScript saved under an image name. Real images are binary, and a real SVG starts with
        markup, so only text that reads as JavaScript (or carries the campaign's shapes) counts."""
        head = self.read_head(p, 4096)
        if not head or not looks_text(head):
            return
        data = self.read(p)
        if not data:
            return
        cls, facts = classify(data, ext)
        if not cls.startswith("text") or data.lstrip()[:1] == b"<":
            if cls != "text_marker":
                return
        if cls in SUSPICIOUS or JS_START.match(data[:4096]):
            self.add("fake-image", HIGH, p, "%s file is not an image: %s" % (ext, describe(cls, facts) if cls != "text_plain" else "JavaScript"),
                     content=cls)

    def read_head(self, p, n):
        try:
            if not stat.S_ISREG(os.stat(p).st_mode):
                return None
            return read_bytes(p, n)
        except OSError:
            return None

    @staticmethod
    def is_ghc2(facts):
        return any(m.startswith(("#ghc2", "DEVBOX", "193.32")) for m in facts.get("markers", []))

    # -- rule 3: hidden tail in config, init, api.js; markers anywhere ------------------------
    def check_config(self, p):
        self.checked["config_files"] += 1
        data = self.read(p)
        if not data:
            return
        t = hidden_tail(data)
        m = markers_in(data)
        if t or m:
            bits = []
            if t:
                bits.append("line %d is %s+ characters: %d spaces/tabs, then `%s`" % (
                    t[0], LONG_LINE, t[1], quote(t[2], 40)))
            if m:
                bits.append("markers: " + ", ".join(m))
            self.add("hidden-code", HIGH, p, "; ".join(bits))

    # -- GhostAction workflows --------------------------------------------------------------
    def check_workflow(self, p):
        self.checked["workflow_files"] += 1
        data = self.read(p)
        if not data:
            return
        if GHOSTACTION_ADDR.search(data):
            if RUNNER_BACKDOOR.search(data):
                where = "a self-hosted runner" if SELF_HOSTED.search(data) else "the machine that runs it"
                self.add("ghostaction-runner-backdoor", HIGH, p,
                         "GhostAction runner backdoor: when it runs on %s it copies SSH keys and cloud, AI and GitHub "
                         "credentials off that machine to 193.32.204.199, and may install a crontab line tagged "
                         "#ghc2 that runs new code from there every five minutes" % where)
            else:
                self.add("ghostaction-workflow", HIGH, p,
                         "GhostAction workflow: when GitHub runs it, it sends repository secrets, keys found in the "
                         "code or its history, or cloud credentials to 193.32.204.199")
            return
        m = markers_in(data)
        if m:
            self.add("marker", HIGH, p, "campaign markers: " + ", ".join(m))

    def check_code(self, p, ext):
        self.checked["code_files"] += 1
        data = self.read(p)
        if not data:
            return
        m = markers_in(data)
        t = hidden_tail(data) if ext in CODE_EXT or ext == "" else None
        if t and EVIL_TAIL.search(t[2]):
            self.add("hidden-code", HIGH, p, "line %d: %d spaces/tabs, then `%s`%s" % (
                t[0], t[1], quote(t[2], 40), ("; markers: " + ", ".join(m)) if m else ""))
        elif m:
            self.add("marker", HIGH, p, "campaign markers: " + ", ".join(m))
        elif t:
            self.add("hidden-code", REVIEW, p, "line %d: %d spaces/tabs, then `%s` (check by hand)" % (
                t[0], t[1], quote(t[2], 40)))

    # -- rule 1: folder-open tasks ---------------------------------------------------------
    def check_tasks(self, p, workspace):
        self.checked["task_files"] += 1
        data = self.read(p)
        if not data:
            return
        text = decode_text(data)
        j = load_jsonc(data)
        if j is None:
            if not re.search(r"folder(?:O|\\u004[fF])pen", text):
                return
            # truncated or hand-mangled JSON: read the commands by regex
            targets = [(m.group(1), workspace) for m in PATHISH.finditer(text)]
            self.report_task(p, workspace, "(unparsable tasks file)", text[:300], targets, [], hidden=False)
            return
        tasks = j.get("tasks") if isinstance(j, dict) else None
        if isinstance(tasks, dict):  # .code-workspace: {"tasks": {"tasks": [...]}}
            tasks = tasks.get("tasks")
        if not isinstance(tasks, list):
            return
        bylabel = {}
        for tk in tasks:
            if isinstance(tk, dict):
                for nm in (tk.get("label"), tk.get("taskName")):
                    if isinstance(nm, str):
                        bylabel[nm] = tk
        for tk in tasks:
            if not isinstance(tk, dict):
                continue
            ro = tk.get("runOptions")
            if not (isinstance(ro, dict) and ro.get("runOn") == "folderOpen"):
                continue
            cmds = []
            self._collect(tk, bylabel, cmds, 0, set())
            pres = tk.get("presentation") if isinstance(tk.get("presentation"), dict) else {}
            hidden = pres.get("reveal") in ("never", "silent") or pres.get("echo") is False
            label = tk.get("label") or tk.get("taskName") or "(no label)"
            cwd = ""
            if isinstance(tk.get("options"), dict):
                cwd = norm_target(s_of(tk["options"].get("cwd", "")))
            base = os.path.join(workspace, cwd) if cwd and not os.path.isabs(cwd) else workspace
            joined = " ;; ".join(cmds)
            targets, wrappers = [], []
            for c in cmds:
                wrapped = [m.group(1) for m in WRAP.finditer(c)]
                found = wrapped or [m.group(1) for m in PATHISH.finditer(c)] + node_paths(c)
                targets += [(t, base) for t in found]
                wrappers += [w for w in SCRIPT_TOKEN.findall(c)]
            self.report_task(p, base, str(label), joined, targets, wrappers, hidden)

    def _collect(self, tk, bylabel, out, depth, seen):
        nodes = [tk] + [tk[k] for k in ("windows", "linux", "osx") if isinstance(tk.get(k), dict)]
        for node in nodes:
            c = s_of(node.get("command", ""))
            a = node.get("args")
            line = (c + " " + s_of(a or "")).strip()
            if line:
                out.append(line)
        dep = tk.get("dependsOn")
        if depth < 4 and dep:
            for d in (dep if isinstance(dep, list) else [dep]):
                if isinstance(d, str) and d in bylabel and d not in seen:
                    seen.add(d)
                    self._collect(bylabel[d], bylabel, out, depth + 1, seen)

    def _resolve(self, base, t):
        """A path a task or script names -> a path inside the scanned folder, else None. Paths that
        leave it (`../`, absolute, a drive) are not followed: the scan reads only what it was given."""
        n = norm_target(t)
        if not n or n.startswith(("-", ">", "$", "%", "http")) or n in ("node", "npm", "npx", "exec"):
            return None
        if os.path.isabs(n) or re.match(r"^[A-Za-z]:", n):
            return None
        r = os.path.normpath(os.path.join(base, n))
        return r if self.inside(r) else None

    def report_task(self, p, base, label, cmd, targets, wrappers, hidden):
        sev = REVIEW
        notes = []
        resolved = []
        for w in dict.fromkeys(wrappers):
            wp = self._resolve(base, w)
            if not wp:
                continue
            notes.append("runs the script %s" % self.rel(wp))
            if "/.vscode/" in "/" + self.rel(wp):
                sev = HIGH
                notes[-1] += " (a script kept inside .vscode)"
            wdata = self.read(wp) if self.isfile(wp) else None
            if wdata is None:
                notes.append("that script is missing")
                continue
            wtext = SCRIPT_DIR.sub(WRAPDIR, decode_text(wdata))
            if REMOTE_PIPE.search(wtext):
                sev = HIGH
                notes.append("that script downloads code and runs it")
            for t in node_paths(wtext):
                if t.startswith(WRAPDIR):
                    targets.append((t[len(WRAPDIR):], os.path.dirname(wp)))
                else:
                    targets += [(t, base), (t, os.path.dirname(wp))]
            wm = markers_in(wdata)
            if wm:
                sev = HIGH
                notes.append("that script holds markers: " + ", ".join(wm))
        if REMOTE_PIPE.search(cmd):
            sev = HIGH
            notes.append("downloads code and runs it")
        # A path a wrapper names may be relative to the workspace or to the wrapper's own folder:
        # take the first reading that exists, else report the first reading as missing.
        options = {}
        for t, tbase in targets:
            tp = self._resolve(tbase, t)
            if tp:
                options.setdefault(t, []).append(tp)
        for opts in options.values():
            tp = next((o for o in opts if self.exists(o)), opts[0])
            if tp in resolved:
                continue
            resolved.append(tp)
            text_ext = ext_of(tp)
            if not self.exists(tp):
                cls, facts = "missing", {}
            else:
                data = self.read(tp) if self.isfile(tp) else None
                cls, facts = classify(data or b"", text_ext) if data is not None else ("missing", {})
            live = cls in SUSPICIOUS or (cls == "text_plain" and text_ext not in CODE_EXT | {".sh", ".py", ""})
            if live or text_ext in ALL_FONTLIKE:
                sev = HIGH
            notes.append("runs %s: %s" % (self.rel(tp), describe(cls, facts)))
        if hidden:
            notes.append("its output is hidden from the terminal")
        detail = 'task "%s" runs automatically when the folder is opened: `%s`' % (quote(label, 60), quote(cmd, 160))
        self.add("folder-open-task", sev, p, detail + ("; " + "; ".join(notes) if notes else ""),
                 targets=[self.rel(t) for t in resolved])

    # -- rule 4: package.json launchers ---------------------------------------------------
    def check_package(self, p):
        self.checked["package_json"] += 1
        data = self.read(p)
        if not data:
            return
        j = load_jsonc(data)
        scripts = j.get("scripts") if isinstance(j, dict) else None
        if not isinstance(scripts, dict):
            return
        base = os.path.dirname(p)
        hits, chained = {}, set()
        for name, cmd in scripts.items():
            if not isinstance(cmd, str):
                continue
            for m in LAUNCH.finditer(cmd):
                tp = self._resolve(base, m.group(1))
                if tp:
                    hits.setdefault(tp, []).append(str(name))
                    if m.group(2) in ("&&", ";", "&"):
                        chained.add(tp)
        for tp, names in hits.items():
            text_ext = ext_of(tp)
            bn = os.path.basename(tp)
            named = bn in ("init", "api.js") and tp in chained
            if not self.isfile(tp):
                if named or text_ext in ALL_FONTLIKE:
                    self.add("npm-script-launcher", REVIEW, p, 'scripts %s first run `node %s`, which is missing' % (
                        ", ".join(sorted(names)), self.rel(tp)), target=self.rel(tp))
                continue
            data2 = self.read(tp) or b""
            cls, facts = classify(data2, text_ext)
            t = hidden_tail(data2)
            if t and "tail" not in facts:
                facts["tail"] = {"line": t[0], "run": t[1], "code": quote(t[2], 40)}
            bad = cls in SUSPICIOUS or bool(facts.get("tail")) or (
                text_ext in ALL_FONTLIKE and cls.startswith("text"))
            if bad:
                sev = HIGH
            elif named or text_ext in ALL_FONTLIKE:
                sev = REVIEW
            else:
                continue
            how = "first run `node %s` before the real command" if tp in chained else "run `node %s`"
            self.add("npm-script-launcher", sev, p, ("scripts %s " + how + ": %s") % (
                ", ".join(sorted(names)), self.rel(tp), describe(cls, facts)), target=self.rel(tp))

    # -- rule 5: .gitignore ---------------------------------------------------------------
    def check_gitignore(self, p):
        self.checked["gitignore"] += 1
        data = self.read(p)
        if not data:
            return
        found = []
        for ln in decode_text(data).splitlines():
            s = ln.strip()
            while s.startswith(("/", "**/")):
                s = s[3:] if s.startswith("**/") else s[1:]
            if s in GITIGNORE_NAMES and s not in found:
                found.append(s)
        if found:
            sev = HIGH if (len(found) >= 2 or GITIGNORE_STRONG & set(found)) else REVIEW
            self.add("gitignore-entries", sev, p, "ignores files the operator's push scripts create: " + ", ".join(found))


# ---------------------------------------------------------------------------------------------
# Machine scan
# ---------------------------------------------------------------------------------------------

RUNNER_FILES = (".npm-ws-runner.js", ".npm-ws.json", ".npm-ws.pid", ".npm-ws.log", ".npm-install.lock")
NPM_CLI_MARKS = re.compile(rb"/\*M2\d{5}A\*/|/\*C2\d{5}A\*/|\.npm-ws-runner\.js|/\*NPM_WS_SHIM\*/|/\*RS2\d{5}\*/")
APP_INJECT = re.compile(rb"__inz(?:RQ|CR|V)\b|\.inz\.cjs['\"]")
INZ_SUFFIXES = (".inz.cjs", ".inz.orig", ".inz.tmp")


class CaseInsensitiveEnv(dict):
    def __init__(self, env):
        super().__init__((k.upper(), v) for k, v in env.items())

    def get(self, k, default=None):
        return super().get(k.upper(), default)

    def __getitem__(self, k):
        return super().__getitem__(k.upper())


class MachineScan:
    """Checks this computer. Every location below is one the captured stages write to.

    system/home/env/fs_root/crontab_text are parameters so the tests can point it at a fake tree."""

    def __init__(self, system=None, home=None, env=None, fs_root=None, crontab_text=None, live_checks=True):
        # sys.platform, not platform.system(): on Python 3.7/3.8 that runs `uname -p` in a subprocess
        self.system = system or {"win32": "Windows", "darwin": "Darwin"}.get(sys.platform, "Linux")
        self.home = home or os.path.expanduser("~")
        env = dict(os.environ) if env is None else env
        # Windows variable names are case-insensitive ("ProgramFiles" arrives as "PROGRAMFILES")
        self.env = CaseInsensitiveEnv(env) if self.system == "Windows" else env
        self.fs_root = fs_root or (os.path.abspath(os.sep))
        self.crontab_text = crontab_text
        self.live_checks = live_checks
        self.findings = []
        self.checked = {"npm_cli_copies": [], "npm_shims": [], "app_files": [], "locations": [],
                        "npm_dirs": [], "apps_checked": [], "app_leftovers": []}
        self._app_roots = {}

    def add(self, rule, severity, path, detail):
        self.findings.append({"rule": rule, "severity": severity, "path": path, "detail": detail})

    def P(self, *parts):
        """An absolute path on Linux/macOS, under fs_root (so tests can fake /usr/share)."""
        return os.path.join(self.fs_root, *parts)

    @property
    def win(self):
        return self.system == "Windows"

    def run(self):
        self.check_runner_dir()
        self.check_npm()
        self.check_apps()
        self.check_python3127()
        self.check_first_run_marker()
        self.check_crontab()
        return self

    # -- ~/.node_modules ------------------------------------------------------------------
    def check_runner_dir(self):
        d = os.path.join(self.home, ".node_modules")
        self.checked["locations"].append(d)
        if not os.path.isdir(d):
            return
        present = [f for f in RUNNER_FILES if os.path.exists(os.path.join(d, f))]
        if present:
            self.add("backdoor-runner", HIGH, d, "backdoor files in the hidden .node_modules folder of your home folder: " + ", ".join(present))
            self.check_pid(os.path.join(d, ".npm-ws.pid"))
        else:
            try:
                kids = sorted(os.listdir(d))[:8]
            except OSError:
                kids = ["(unreadable)"]
            self.add("backdoor-runner", REVIEW, d, "a .node_modules folder in your home folder. Node.js still reads this legacy location, so it can be legitimate, but the backdoor also keeps its own axios and socket.io-client there; holds: " + ", ".join(kids))

    def check_pid(self, pidfile):
        """On Linux/macOS only: is the pid in .npm-ws.pid alive? (os.kill(pid, 0) sends nothing.
        On Windows os.kill terminates a process, so it is never called there.)"""
        if self.win or not self.live_checks or os.name != "posix":
            return
        try:
            pid = int(read_bytes(pidfile, 64).strip() or b"0")
        except (OSError, ValueError):
            return
        if pid <= 1:
            return
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        except PermissionError:
            pass
        except OSError:
            return
        self.add("backdoor-running", HIGH, pidfile, "process %d named in .npm-ws.pid is running now: the backdoor may be live; take the computer off the network" % pid)

    # -- npm's own cli.js and the Windows shim --------------------------------------------
    def _npm_dirs(self):
        """Every npm package folder the npm-migrate stage patches, found WITHOUT running npm."""
        e, h = self.env, self.home
        dirs = []
        prefixes = []
        for k in ("npm_config_prefix", "NPM_CONFIG_PREFIX", "PREFIX"):
            if e.get(k):
                prefixes.append(e[k])
        for rc in [os.path.join(h, ".npmrc")] + [os.path.join(p, "etc", "npmrc") for p in list(prefixes)]:
            try:
                for ln in decode_text(read_bytes(rc, 65536)).splitlines():
                    m = re.match(r"\s*prefix\s*=\s*(.+?)\s*$", ln)
                    if m:
                        prefixes.append(os.path.expanduser(m.group(1).strip("'\"")))
            except OSError:
                pass
        # the node on PATH (located, never run)
        node_dirs = []
        for d in (e.get("PATH") or "").split(os.pathsep):
            for exe in (("node.exe",) if self.win else ("node",)):
                cand = os.path.join(d, exe)
                if d and os.path.isfile(cand):
                    node_dirs.append(os.path.dirname(os.path.realpath(cand)))
        for nd in node_dirs:
            dirs += [os.path.join(nd, "node_modules", "npm"),
                     os.path.join(os.path.dirname(nd), "lib", "node_modules", "npm")]
            prefixes.append(os.path.dirname(nd))
        for p in prefixes:
            dirs += [os.path.join(p, "lib", "node_modules", "npm"), os.path.join(p, "node_modules", "npm"),
                     os.path.join(p, "npm")]
        if self.win:
            appdata = e.get("APPDATA") or os.path.join(h, "AppData", "Roaming")
            local = e.get("LOCALAPPDATA") or os.path.join(h, "AppData", "Local")
            pf = [e.get("ProgramFiles") or "C:\\Program Files", e.get("ProgramFiles(x86)") or "C:\\Program Files (x86)"]
            dirs.append(os.path.join(appdata, "npm", "node_modules", "npm"))
            for p in pf:
                dirs.append(os.path.join(p, "nodejs", "node_modules", "npm"))
            for nvm in filter(None, [e.get("NVM_HOME"), os.path.join(appdata, "nvm")]):
                dirs += glob.glob(os.path.join(glob.escape(nvm), "v*", "node_modules", "npm"))
            for base in (os.path.join(appdata, "fnm", "node-versions"), os.path.join(local, "fnm_multishells")):
                dirs += glob.glob(os.path.join(glob.escape(base), "*", "installation", "node_modules", "npm"))
            dirs += glob.glob(os.path.join(glob.escape(local), "Volta", "tools", "image", "node", "*", "node_modules", "npm"))
        else:
            for p in ("usr/local", "usr", "opt/homebrew", "opt/local"):
                dirs.append(self.P(p, "lib", "node_modules", "npm"))
            nvm = e.get("NVM_DIR") or os.path.join(h, ".nvm")
            dirs += glob.glob(os.path.join(glob.escape(nvm), "versions", "node", "*", "lib", "node_modules", "npm"))
            for base in (os.path.join(h, ".local", "share", "fnm", "node-versions"), os.path.join(h, ".fnm", "node-versions"),
                         os.path.join(h, "Library", "Application Support", "fnm", "node-versions")):
                dirs += glob.glob(os.path.join(glob.escape(base), "*", "installation", "lib", "node_modules", "npm"))
            for base in (os.path.join(h, ".volta", "tools", "image", "node"), os.path.join(h, ".asdf", "installs", "nodejs"),
                         os.path.join(h, ".local", "share", "mise", "installs", "node"), os.path.join(h, ".n", "versions", "node")):
                dirs += glob.glob(os.path.join(glob.escape(base), "*", "lib", "node_modules", "npm"))
        out, seen = [], set()
        for d in dirs:
            try:
                r = os.path.realpath(d)
            except OSError:
                continue
            if r not in seen and os.path.isdir(r):
                seen.add(r)
                out.append(r)
        return out

    def check_npm(self):
        dirs = self._npm_dirs()
        self.checked["npm_dirs"] = list(dirs)
        for d in dirs:
            for sub, kind in ((("lib", "cli.js"), "cli"), (("bin", "npm-cli.js"), "shim")):
                f = os.path.join(d, *sub)
                if not os.path.isfile(f):
                    continue
                self.checked["npm_cli_copies" if kind == "cli" else "npm_shims"].append(f)
                try:
                    data = read_bytes(f, 8 << 20)
                except OSError:
                    continue
                m = NPM_CLI_MARKS.search(data)
                t = hidden_tail(data, min_line=0)
                if m or (t and EVIL_TAIL.search(t[2])):
                    what = quote(m.group(0), 40) if m else "code after %d spaces" % t[1]
                    self.add("npm-trojaned", HIGH, f, "npm's own %s has the backdoor launcher appended (%s): every npm command restarts the backdoor; reinstall Node.js" % (
                        "lib/cli.js" if kind == "cli" else "bin/npm-cli.js", what))

    # -- desktop apps patched with a .inz.cjs require ---------------------------------------
    def _electron_app_dirs(self, roots):
        """resources/app folders under each install root, including VS Code's versioned
        <hash>/resources/app layout on Windows."""
        out = []
        for r in roots:
            for cand in (r, os.path.join(r, "resources", "app"), os.path.join(r, "Contents", "Resources", "app")):
                if os.path.isdir(os.path.join(cand, "out")) or os.path.isfile(os.path.join(cand, "main.js")) \
                        or os.path.isdir(os.path.join(cand, "node_modules")):
                    out.append(cand)
            out += [d for d in glob.glob(os.path.join(glob.escape(r), "*", "resources", "app")) if os.path.isdir(d)]
        return list(dict.fromkeys(out))

    def _app_targets(self):
        """-> list of (app name, file the malware patches)."""
        e, h = self.env, self.home
        t = []
        code_files = (("out", "main.js"), ("node_modules", "@vscode", "deviceid", "dist", "index.js"))
        if self.win:
            local = e.get("LOCALAPPDATA") or os.path.join(h, "AppData", "Local")
            pf = [e.get("ProgramFiles") or "C:\\Program Files", e.get("ProgramFiles(x86)") or "C:\\Program Files (x86)"]
            vscode = [os.path.join(local, "Programs", "Microsoft VS Code"), os.path.join(local, "Programs", "Microsoft VS Code Insiders")] + \
                     [os.path.join(p, "Microsoft VS Code") for p in pf]
            cursor = [os.path.join(local, "Programs", "cursor"), os.path.join(local, "Programs", "Cursor"),
                      os.path.join(local, "cursor"), os.path.join(local, "Cursor")] + \
                     [os.path.join(p, n) for p in pf for n in ("cursor", "Cursor")]
            anti = [os.path.join(local, "Programs", "Antigravity")]
            discord = []
            for name in ("discord", "Discord", "DiscordPTB", "discordptb", "DiscordCanary", "discordcanary"):
                base = glob.escape(os.path.join(local, name))
                discord += glob.glob(os.path.join(base, "app-*", "modules", "discord_desktop_core-*", "discord_desktop_core", "index.js"))
                discord += glob.glob(os.path.join(base, "app-*", "modules", "discord_desktop_core", "index.js"))
            ghd = []
            for base in (os.path.join(local, "GitHubDesktop"), os.path.join(local, "Programs", "GitHub Desktop"),
                         os.path.join(local, "Programs", "GitHubDesktop")):
                ghd += glob.glob(os.path.join(glob.escape(base), "app-*", "resources", "app", "main.js"))
        else:
            apps = [self.P("Applications"), os.path.join(h, "Applications")]
            vscode = [os.path.join(a, "Visual Studio Code.app") for a in apps] + [os.path.join(a, "Visual Studio Code - Insiders.app") for a in apps] + \
                     [self.P("usr", "share", "code"), self.P("usr", "share", "code-insiders"), self.P("opt", "visual-studio-code"),
                      self.P("usr", "lib", "code"), self.P("snap", "code", "current", "usr", "share", "code")]
            cursor = [os.path.join(a, "Cursor.app") for a in apps] + [self.P("usr", "share", "cursor"), self.P("opt", "Cursor"), self.P("opt", "cursor")]
            anti = [os.path.join(a, "Antigravity.app") for a in apps] + [self.P("usr", "share", "antigravity"), self.P("opt", "Antigravity")]
            discord = []
            for base in (os.path.join(h, "Library", "Application Support", "discord"), os.path.join(h, ".config", "discord"),
                         self.P("usr", "share", "discord"), self.P("opt", "discord")):
                b = glob.escape(base)
                discord += glob.glob(os.path.join(b, "modules", "discord_desktop_core", "index.js"))
                discord += glob.glob(os.path.join(b, "*", "modules", "discord_desktop_core", "index.js"))
                discord += glob.glob(os.path.join(b, "*", "modules", "discord_desktop_core-*", "discord_desktop_core", "index.js"))
            ghd = [os.path.join(a, "GitHub Desktop.app", "Contents", "Resources", "app", "main.js") for a in apps] + \
                  [self.P("usr", "share", "GitHub Desktop", "Contents", "Resources", "app", "main.js"),
                   self.P("usr", "lib", "github-desktop", "resources", "app", "main.js")]
        if self.win:
            discord_roots = [os.path.join(local, n) for n in ("discord", "Discord", "DiscordPTB", "discordptb", "DiscordCanary", "discordcanary")]
            ghd_roots = [os.path.join(local, "GitHubDesktop"), os.path.join(local, "Programs", "GitHub Desktop"),
                         os.path.join(local, "Programs", "GitHubDesktop")]
        else:
            discord_roots = [os.path.join(h, "Library", "Application Support", "discord"), self.P("usr", "share", "discord"), self.P("opt", "discord")]
            ghd_roots = [os.path.join(a, "GitHub Desktop.app") for a in apps] + [self.P("usr", "lib", "github-desktop")]
        self._app_roots = {"VS Code": vscode, "Cursor": cursor, "Antigravity": anti,
                           "Discord": discord_roots, "GitHub Desktop": ghd_roots}
        for app, roots in (("VS Code", vscode), ("Cursor", cursor), ("Antigravity", anti)):
            for d in self._electron_app_dirs(roots):
                for parts in code_files:
                    t.append((app, os.path.join(d, *parts)))
        t += [("Discord", f) for f in discord]
        t += [("GitHub Desktop", f) for f in ghd]
        return t

    def check_apps(self):
        seen = set()
        for app, f in self._app_targets():
            d = os.path.dirname(f)
            key = os.path.normcase(os.path.realpath(f))  # Windows: "discord" and "Discord" are one folder
            if key in seen:
                continue
            seen.add(key)
            if os.path.isfile(f):
                self.checked["app_files"].append(f)
                if app not in self.checked["apps_checked"]:
                    self.checked["apps_checked"].append(app)
                try:
                    head = read_bytes(f, 65536)
                except OSError:
                    head = b""
                m = APP_INJECT.search(head)
                if m:
                    self.add("app-trojaned", HIGH, f, "%s's program file starts with an injected require (`%s`): reinstall %s" % (app, quote(m.group(0), 30), app))
            if os.path.isdir(d):
                try:
                    names = os.listdir(d)
                except OSError:
                    names = []
                for n in sorted(names):
                    if n.endswith(INZ_SUFFIXES):
                        self.add("app-trojaned", HIGH, os.path.join(d, n), "%s has a %s file beside its program files (the backdoor's injected module or the original it replaced): reinstall %s" % (
                            app, n[n.index(".inz"):], app))
        # An app folder with no program file in it: an uninstall's leftovers, or a layout this
        # scanner does not know. Said out loud, so "0 files" is not read as "checked and clean".
        for app, roots in self._app_roots.items():
            if app in self.checked["apps_checked"]:
                continue
            found = [r for r in roots if os.path.isdir(r)]
            if found:
                self.checked["app_leftovers"].append({"app": app, "folder": found[0]})

    # -- the malware's own Python on Windows ----------------------------------------------
    def check_python3127(self):
        if not self.win:
            return
        local = self.env.get("LOCALAPPDATA") or os.path.join(self.home, "AppData", "Local")
        d = os.path.join(local, "Programs", "Python", "Python3127")
        self.checked["locations"].append(d)
        if os.path.exists(d):
            self.add("malware-python", HIGH, d, "a Python installed by the malware (a real Python 3.12 installs to Python312, not Python3127)")

    # -- the client's first-run marker ------------------------------------------------------
    def check_first_run_marker(self):
        # The client writes `/tmp/.` + btoa(user) on every non-Windows system (macOS included, not
        # $TMPDIR) and %LOCALAPPDATA%\Temp\ + btoa(user) on Windows. btoa is Latin-1 and throws on
        # other names, in which case no marker is written at all.
        try:
            user = self.env.get("USERNAME") or self.env.get("USER") or getpass.getuser()
        except Exception:
            return
        try:
            b64 = base64.b64encode(user.encode("latin-1")).decode("ascii")
        except UnicodeEncodeError:
            return
        if "/" in b64:
            return
        if self.win:
            local = self.env.get("LOCALAPPDATA") or os.path.join(self.home, "AppData", "Local")
            f = os.path.join(local, "Temp", b64)
        else:
            f = self.P("tmp", "." + b64)
        self.checked["locations"].append(f)
        if os.path.isfile(f):
            try:
                body = read_bytes(f, 64).strip()
            except OSError:
                body = b""
            sev = HIGH if re.fullmatch(rb"\d{10,16}", body or b"x") else REVIEW
            self.add("first-run-marker", sev, f, "the backdoor client's first-run marker (a file named after your user name in base64, holding a timestamp)")

    # -- #ghc2 crontab line -----------------------------------------------------------------
    def check_crontab(self):
        if self.win:
            return
        text = self.crontab_text
        if text is None:
            try:
                r = subprocess.run(["crontab", "-l"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
                text = r.stdout.decode("utf-8", "replace") if r.returncode == 0 else ""
                self.checked["locations"].append("crontab -l")
            except (OSError, subprocess.SubprocessError):
                self.checked["locations"].append("crontab -l (not available)")
                return
        for no, ln in enumerate(text.splitlines(), 1):
            if ln.rstrip().endswith("#ghc2") or re.search(r"#\s*ghc2\b", ln):
                self.add("ghc2-crontab", HIGH, "crontab line %d" % no,
                         "a crontab line tagged #ghc2 (the stealer's re-run job): `%s`; remove it before you change any credentials" % quote(ln.strip(), 100))


# ---------------------------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------------------------

NEXT_STEPS = (
    "What to do now: do not open, build or run the project. From a different, clean device, "
    "revoke your GitHub tokens, SSH and deploy keys and sign out of all sessions first, because "
    "the stealer takes them and can push the code back after you remove it. Then change every "
    "other secret the computer could reach, then clean or reinstall it. See the README.")

GHOSTACTION_STEPS = (
    "What to do about the GhostAction workflow: it runs on GitHub, not on your computer, and "
    "whoever pushed it had a working GitHub login. From a computer you trust, change your GitHub "
    "password, revoke personal access tokens, OAuth and GitHub App grants, and SSH and deploy keys, "
    "and sign out of other sessions first. Then replace every secret stored in the repository and "
    "its organization, and every key that has ever been in the code, its history or its wiki, then "
    "delete the workflow. See the README.")

RUNNER_STEPS = (
    "Runner backdoor: if the repository has a self-hosted runner, that machine is compromised and "
    "deleting the workflow does not clean it. On it, run crontab -l, remove the line ending in "
    "#ghc2 and take the machine off the network before you change any credentials; then rebuild it "
    "or replace everything stored on it. If the repository has no self-hosted runner, that job never ran.")


def next_steps(findings):
    """The advice for what was found: GhostAction findings get their own steps, because the fix
    is GitHub secrets, not the computer; anything else gets the PolinRider steps."""
    high = [f for f in findings if f["severity"] == HIGH]
    out = []
    if any(f["rule"] not in GHOSTACTION_RULES for f in high):
        out.append(NEXT_STEPS)
    if any(f["rule"] in GHOSTACTION_RULES for f in high):
        out.append(GHOSTACTION_STEPS)
    if any(f["rule"] == "ghostaction-runner-backdoor" for f in high):
        out.append(RUNNER_STEPS)
    return out


def machine_summary(checked):
    """What a machine scan looked at, in words: which npm copies and which apps it read, and
    when there was nothing there to read, so a 0 is never mistaken for a check that passed."""
    out = []
    n_cli, n_shim = len(checked["npm_cli_copies"]), len(checked["npm_shims"])
    if n_cli or n_shim:
        line = "npm: checked %d cop%s of lib/cli.js" % (n_cli, "y" if n_cli == 1 else "ies")
        if n_shim:
            line += " and %d of bin/npm-cli.js" % n_shim
        out.append(line)
    elif checked.get("npm_dirs"):
        out.append("npm: found %d npm folder%s but no lib/cli.js in %s, so npm was not checked" % (
            len(checked["npm_dirs"]), "" if len(checked["npm_dirs"]) == 1 else "s",
            "it" if len(checked["npm_dirs"]) == 1 else "them"))
    else:
        out.append("npm: no Node.js or npm install found, so there was no npm to check")
    apps = checked.get("apps_checked") or []
    if apps:
        out.append("Desktop apps checked: %s (%d program file%s)" % (
            ", ".join(apps), len(checked["app_files"]), "" if len(checked["app_files"]) == 1 else "s"))
    else:
        out.append("Desktop apps: none of VS Code, Cursor, Antigravity, Discord or GitHub Desktop is installed in a place this scanner knows")
    for lo in checked.get("app_leftovers") or []:
        out.append("Found a %s folder but none of the program files this scanner reads, so %s was not checked (left over from an uninstall, or a layout this scanner does not know): %s" % (
            lo["app"], lo["app"], lo["folder"]))
    out.append("Also checked %d other location%s" % (len(checked["locations"]), "" if len(checked["locations"]) == 1 else "s"))
    return out


def render_text(mode, roots, findings, checked):
    out = ["polinrider-scan %s, %s scan of %s" % (VERSION, mode, ", ".join(roots))]
    if mode == "repository":
        c = checked
        out.append("Checked %d files: %d font-like, %d task files, %d package.json, %d .gitignore, %d config, %d workflows, %d other code%s" % (
            c["files"], c["font_like_files"], c["task_files"], c["package_json"], c["gitignore"], c["config_files"],
            c.get("workflow_files", 0), c["code_files"], (", %d unreadable" % c["unreadable"]) if c["unreadable"] else ""))
        if c["truncated"]:
            out.append("%d files were larger than --max-file-mb; only their first and last halves of that size were read" % c["truncated"])
    else:
        out.extend(machine_summary(checked))
    out.append("")
    for sev in (HIGH, REVIEW):
        for f in [x for x in findings if x["severity"] == sev]:
            out.append("%-6s %-20s %s" % (sev.upper(), f["rule"], f["path"]))
            out.append("       %s" % f["detail"])
    nh = sum(1 for f in findings if f["severity"] == HIGH)
    nr = len(findings) - nh
    if findings:
        out.append("")
        out.append("%d finding%s (%d high, %d to review)." % (len(findings), "" if len(findings) == 1 else "s", nh, nr))
        if nh:
            out.extend(next_steps(findings))
    else:
        out.append("Nothing found. This covers the patterns listed in the README, in the files on disk now; it says nothing about other branches, history or stolen credentials.")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Static scanner for the PolinRider / Contagious Interview fake-font implant, the #ghc2 stealer and the GhostAction GitHub Actions workflow. Reads files only; never runs anything it finds.")
    ap.add_argument("paths", nargs="*", help="repositories or files to scan (default: the current folder)")
    ap.add_argument("--machine", action="store_true", help="check this computer for the backdoor's persistence instead")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    ap.add_argument("--fail-on", choices=("any", "high"), default="any", help="exit 1 on any finding (default) or on high findings only")
    ap.add_argument("--include-node-modules", action="store_true", help="also walk node_modules folders")
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip paths matching this glob (relative, / separators); repeatable")
    ap.add_argument("--max-file-mb", type=int, default=16, help="read at most this many MB of each file (default 16)")
    ap.add_argument("--version", action="version", version="polinrider-scan " + VERSION)
    a = ap.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # a path a Windows console cannot print must not crash the scan
        except (AttributeError, ValueError):
            pass
    if a.max_file_mb < 1:
        ap.error("--max-file-mb must be 1 or more")
    try:
        if a.machine:
            if a.paths:
                ap.error("--machine takes no paths")
            ms = MachineScan().run()
            mode, roots, findings, checked = "machine", [socket.gethostname() or "this computer"], ms.findings, ms.checked
        else:
            roots = a.paths or ["."]
            skip = set(DEFAULT_SKIP_DIRS)
            if a.include_node_modules:
                skip.discard("node_modules")
            findings, checked = [], None
            for r in roots:
                if not os.path.exists(r):
                    print("polinrider-scan: no such path: %s" % r, file=sys.stderr)
                    return 2
                rs = RepoScan(r, skip, a.exclude, a.max_file_mb << 20).run()
                for f in rs.findings:
                    if len(roots) > 1:
                        f["root"] = r
                    findings.append(f)
                if checked is None:
                    checked = rs.checked
                else:
                    for k, v in rs.checked.items():
                        checked[k] += v
            mode = "repository"
    except KeyboardInterrupt:
        return 2
    except Exception as e:  # a crash must not exit 1, which a pipeline reads as "infected"
        print("polinrider-scan: the scan failed: %s: %s" % (type(e).__name__, e), file=sys.stderr)
        return 2
    if a.json:
        doc = {"tool": "polinrider-scan", "version": VERSION, "mode": mode, "roots": roots, "checked": checked,
               "counts": {HIGH: sum(1 for f in findings if f["severity"] == HIGH),
                          REVIEW: sum(1 for f in findings if f["severity"] == REVIEW)},
               "findings": findings}
        print(json.dumps(doc, indent=2))
    else:
        print(render_text(mode, roots, findings, checked))
    failing = [f for f in findings if a.fail_on == "any" or f["severity"] == HIGH]
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())

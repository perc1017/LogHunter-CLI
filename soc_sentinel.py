#!/usr/bin/env python3
"""
Использование:
    soc_sentinel.py analyze /logs/access.log
    soc_sentinel.py analyze /logs                # каталог: все *access*.log*, включая .gz
    cat access.log | soc_sentinel.py analyze -   # stdin
"""
from __future__ import annotations

import argparse
import gzip
import ipaddress
import math
import os
import re
import sys
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from html import unescape
from pathlib import Path
from urllib.parse import unquote_plus

LOW, MEDIUM, HIGH, CRITICAL = 1, 2, 3, 4
SEV_NAME = {LOW: "LOW", MEDIUM: "MEDIUM", HIGH: "HIGH", CRITICAL: "CRITICAL"}
SEV_STYLE = {LOW: "bold cyan", MEDIUM: "bold yellow", HIGH: "bold red", CRITICAL: "bold white on red"}
SEV_BAR = {LOW: "cyan", MEDIUM: "yellow", HIGH: "red", CRITICAL: "bright_red"}
SEV_WEIGHT = {LOW: 1, MEDIUM: 3, HIGH: 8, CRITICAL: 20}
SEV_BY_NAME = {"low": LOW, "medium": MEDIUM, "high": HIGH, "critical": CRITICAL}

CATS = {
    "sqli": ("SQL-инъекция", "SQLi"),
    "xss": ("XSS", "XSS"),
    "ssrf": ("SSRF", "SSRF"),
    "lfi": ("Path Traversal / LFI", "LFI"),
    "rce": ("RCE / Command Injection", "RCE"),
    "recon": ("Разведка / чувствительные пути", "RECON"),
    "scanner": ("Сканер / атакующий инструмент", "TOOL"),
    "brute": ("Brute-force", "BRUTE"),
    "scan404": ("Перебор путей (массовые 404)", "SCAN"),
    "proto": ("Аномалии протокола", "PROTO"),
    "evasion": ("Обфускация / evasion", "EVADE"),
    "anomip": ("Аномальный IP", "IP"),
}
INJECTION_CATS = {"sqli", "xss", "ssrf", "lfi", "rce", "recon"}
MULTI_VECTOR_CATS = {"sqli", "xss", "ssrf", "lfi", "rce", "recon", "scanner", "brute", "scan404"}

STD_METHODS = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"}
MAX_SCAN = 8192        
LONG_URI = 2048        
LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>.*?) \[(?P<time>[^\]]+)\] '
    r'"(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
)
REQ_RE = re.compile(r"^(\S+) (.+) (HTTP/\d(?:\.\d)?)$")
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def parse_ts(s: str) -> float | None:
    """'10/Oct/2023:13:55:36 +0300' -> epoch (без strptime: быстрее и не зависит от локали)."""
    try:
        tz = s[21:26]
        off = (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60) * (-1 if tz[0] == "-" else 1)
        dt = datetime(int(s[7:11]), MONTHS[s[3:6]], int(s[0:2]),
                      int(s[12:14]), int(s[15:17]), int(s[18:20]),
                      tzinfo=timezone(timedelta(seconds=off)))
        return dt.timestamp()
    except (ValueError, KeyError, IndexError):
        return None


_HEX_ESC = re.compile(r"\\x([0-9a-fA-F]{2})")        
_MYSQL_COND = re.compile(r"/\*!\d{0,6}")               
_BLOCK_COMMENT = re.compile(r"/\*[^*]{0,64}\*/")        


def normalize(raw: str) -> tuple[str, int]:
    s = _HEX_ESC.sub(lambda m: chr(int(m.group(1), 16)), raw[:MAX_SCAN])
    layers = 0
    for _ in range(4):
        d = unquote_plus(s)
        if d == s:
            break
        s, layers = d, layers + 1
    s = unescape(s).replace("\x00", "")
    s = _MYSQL_COND.sub(" ", s)
    s = _BLOCK_COMMENT.sub(" ", s).replace("*/", " ")
    return s.lower(), layers

@dataclass(frozen=True, slots=True)
class Rule:
    name: str
    cat: str
    sev: int
    rx: re.Pattern
    headers: bool = False  


def R(name: str, cat: str, sev: int, pattern: str, headers: bool = False) -> Rule:
    return Rule(name, cat, sev, re.compile(pattern, re.I), headers)


RULES: list[Rule] = [
    R("UNION SELECT", "sqli", HIGH, r"\bunion\b(?:\s+all)?\s+select\b", headers=True),
    R("Булева инъекция (' OR 1=1)", "sqli", HIGH,
      r"['\")]\s*(?:or|and)\s+['\"(]?\w+['\"]?\s*(?:=|<|>|\blike\b)\s*['\"(]?\w+|\b(?:or|and)\s+\d+\s*=\s*\d+"),
    R("Time-based (SLEEP/BENCHMARK)", "sqli", HIGH, r"\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b"),
    R("Error/extract-based", "sqli", HIGH, r"\b(?:extractvalue|updatexml|load_file|group_concat|concat_ws)\s*\("),
    R("Разведка схемы БД", "sqli", HIGH,
      r"\binformation_schema\b|\bpg_catalog\b|\bsqlite_master\b|\bsysobjects\b|\bmysql\.user\b|\ball_tables\b"),
    R("Stacked / деструктивный SQL", "sqli", CRITICAL,
      r";\s*(?:drop|truncate|alter|insert|update|delete|exec|execute|shutdown)\b|\bxp_cmdshell\b|\binto\s+(?:out|dump)file\b"),
    R("SQL-комментарий после кавычки", "sqli", MEDIUM, r"['\")]\s*(?:--(?:\s|$)|#|;--)"),

    R("<script>", "xss", HIGH, r"<\s*/?\s*script\b", headers=True),
    R("Event handler (onerror=…)", "xss", HIGH,
      r"\bon(?:error|load|click|mouseover|mouseenter|focus|blur|toggle|start|animationstart|pointerover)\s*="),
    R("javascript: / data:text/html", "xss", HIGH, r"\b(?:javascript|vbscript)\s*:|data\s*:\s*text/html"),
    R("Опасный HTML-тег", "xss", MEDIUM,
      r"<\s*(?:iframe|svg|object|embed|math|details|marquee|video|audio|body|img)\b[^>]{0,200}"),
    R("JS-примитивы (document.cookie, alert…)", "xss", MEDIUM,
      r"\bdocument\s*\.\s*(?:cookie|location|write|domain)|\bwindow\s*\.\s*location"
      r"|\b(?:alert|prompt|confirm)\s*\(|string\s*\.\s*fromcharcode|\batob\s*\("),

    R("Cloud metadata (169.254.169.254 …)", "ssrf", CRITICAL,
      r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|\bfd00:ec2::254"
      r"|/latest/(?:meta-data|user-data|api/token)|/computemetadata/v1|/metadata/instance"),
    R("Внутренний адрес в параметре URL", "ssrf", HIGH,
      r"(?:https?|ftp|gopher|dict|ldap|sftp|tftp)://(?:[^/@\s]*@)?"
      r"(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|0x7f[0-9a-f]*|2130706433|0177\.0\.0\.1"
      r"|\[(?:::1?|::ffff:[\da-f.:]+)\]|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}"
      r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|169\.254(?:\.\d{1,3}){2}"
      r"|[a-z0-9.-]+\.(?:internal|local|lan|corp))(?![\w.-])"),
    R("Опасная URI-схема (gopher/dict/file…)", "ssrf", HIGH, r"\b(?:gopher|dict|ldap|tftp|jar|netdoc|file)://"),

    R("Path traversal (../)", "lfi", MEDIUM, r"\.\.[/\\]"),
    R("Path traversal (../../)", "lfi", HIGH, r"(?:\.\.[/\\]){2,}"),
    R("Чтение системных файлов", "lfi", CRITICAL,
      r"/etc/(?:passwd|shadow|group|hosts|issue)|/proc/(?:self|\d+)/(?:environ|cmdline|fd)"
      r"|\b(?:boot|win)\.ini\b|\bc:[/\\]windows|/windows/system32|\bweb\.config\b|/\.ssh/|\bid_rsa\b"),
    R("PHP-обёртки (php://, phar://…)", "lfi", HIGH, r"\b(?:php|expect|phar|zip|glob)://|\bdata://"),

    
    R("Command injection (;cat, |id, `cmd`)", "rce", CRITICAL,
      r"(?:;|\|\|?|&&|`|\$\()\s*(?:cat|ls|id|whoami|uname|pwd|ifconfig|ping|nslookup|wget|curl|bash|sh|zsh"
      r"|nc|ncat|netcat|python3?|perl|php|ruby|powershell|cmd)\b(?:\s|$|;|\|)"),
    R("Shell / reverse shell", "rce", CRITICAL,
      r"/bin/(?:ba|z|da|k)?sh\b|\bcmd(?:\.exe)?\s*/c\b|\bpowershell(?:\.exe)?\s+-\w+|\bnc\s+-[el]\b|/dev/tcp/",
      headers=True),
    R("Log4Shell (${jndi:…})", "rce", CRITICAL, r"\$\{\s*jndi\s*:", headers=True),
    R("Log4Shell (обфусцированный)", "rce", HIGH,
      r"\$\{(?:\s*\$\{)?\s*(?:lower|upper|env|sys|java|ctx|date):|\$\{(?:\s*\$\{)?::-", headers=True),
    R("Shellshock", "rce", CRITICAL, r"\(\)\s*\{[^}]{0,40}\}\s*;", headers=True),
    R("Выполнение кода (PHP/Java/OGNL)", "rce", HIGH,
      r"\b(?:system|passthru|shell_exec|popen|proc_open)\s*\(|\beval\s*\(\s*(?:base64_decode|\$_)"
      r"|\bruntime\s*\.\s*getruntime|\bprocessbuilder\b|class\.module\.classloader|#_memberaccess|\bognl\b"),
    R("Template injection (SSTI)", "rce", MEDIUM,
      r"\{\{\s*\d+\s*[*+\-]\s*\d+\s*\}\}|\$\{\s*\d+\s*[*+]\s*\d+\s*\}|<%=|__class__|__globals__"
      r"|\{\{\s*(?:config|self|request)\b[^}]{0,40}\}\}"),

    R("Секреты / VCS (.env, .git, дампы)", "recon", HIGH,
      r"/\.(?:env(?:\.\w+)?|git|svn|hg|aws|ssh|htpasswd|ds_store|bash_history|npmrc|docker|kube)(?![\w-])"
      r"|/wp-config\.(?:php|bak|old|txt|zip)|/id_(?:rsa|dsa)\b"
      r"|/(?:backup|dump|database|db|site|www)\.(?:sql|zip|tar|tar\.gz|tgz|bak|7z|rar)(?!\w)"),
    R("Админ-панели / уязвимые endpoints", "recon", LOW,
      r"/(?:phpmyadmin|pma|myadmin|adminer(?:\.php)?|wp-admin|wp-login\.php|xmlrpc\.php|administrator"
      r"|manager/html|server-status|server-info|actuator|jenkins|console|cgi-bin|boaform|phpinfo\.php"
      r"|vendor/phpunit|eval-stdin\.php|hnap1|telescope|_profiler|solr/admin)(?![\w-])"),
]
HEADER_RULES = [r for r in RULES if r.headers]

TOOL_UA = re.compile(
    r"sqlmap|nikto|nmap|masscan|zgrab|acunetix|nessus|openvas|netsparker|appscan|wpscan|dirbuster|\bdirb\b"
    r"|gobuster|feroxbuster|\bffuf\b|wfuzz|nuclei|jaeles|commix|xsstrike|arachni|w3af|havij|metasploit"
    r"|\bhydra\b|burpsuite|burp collaborator|owasp[ _-]?zap|zaproxy|whatweb|projectdiscovery|httpx",
    re.I)
AUTO_UA = re.compile(
    r"^(?:curl|wget|python-requests|python-urllib|go-http-client|libwww-perl|scrapy|aiohttp|java)/|^java ", re.I)

LOGIN_RE = re.compile(
    r"(?:^|/)(?:wp-login\.php|xmlrpc\.php|login|log-in|signin|sign-in|sign_in|signon|auth|authenticate"
    r"|session|sessions|token|j_security_check)(?:\.\w{2,4})?/?$")


@lru_cache(maxsize=8192)
def scan_header(raw: str) -> tuple:
    norm, _ = normalize(raw)
    out = []
    for r in HEADER_RULES:
        m = r.rx.search(norm)
        if m:
            out.append((r.cat, r.sev, r.name, m.group(0)[:80]))
    return tuple(out)


@lru_cache(maxsize=4096)
def classify_ua(ua: str):
    if ua in ("-", ""):
        return ("proto", LOW, "Пустой User-Agent", "")
    m = TOOL_UA.search(ua)
    if m:
        return ("scanner", HIGH, f"Атакующий инструмент: {m.group(0).lower()}", ua)
    if AUTO_UA.search(ua):
        return ("scanner", LOW, "Скрипт / автоматизированный клиент", ua)
    return None


def classify_ip(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if a.is_loopback:
        return "loopback"
    if a.is_private or a.is_link_local:
        return "private"
    return "public"


@dataclass(slots=True)
class Finding:
    ts: float | None
    ip: str
    method: str
    target: str
    status: int          
    cat: str
    sev: int
    rule: str
    evidence: str


@dataclass
class Brute:
    first: float
    last: float
    peak: int = 0
    total: int = 0
    redirects: int = 0
    paths: Counter = field(default_factory=Counter)


class Analyzer:
    def __init__(self, brute_threshold=10, brute_window=60, scan_threshold=30, max_findings=50_000):
        self.brute_threshold, self.brute_window = brute_threshold, brute_window
        self.scan_threshold, self.max_findings = scan_threshold, max_findings

        self.total_lines = self.parsed = self.unparsed = 0
        self.bad_samples: list[str] = []
        self.first_ts = self.last_ts = None
        self.status_count: Counter = Counter()

        self.ip_requests: Counter = Counter()
        self.ip_kind: dict[str, str] = {}
        self.ip_uas: dict[str, set] = defaultdict(set)
        self.ip_sev: dict[str, Counter] = defaultdict(Counter)
        self.ip_cats: dict[str, Counter] = defaultdict(Counter)

        self.sev_count: Counter = Counter()
        self.cat_count: Counter = Counter()
        self.cat_ips: dict[str, set] = defaultdict(set)
        self.cat_maxsev: dict[str, int] = defaultdict(int)

        self.findings: list[Finding] = []
        self.overflow = 0
        self.hit_2xx = 0                       

        self.login_hits: dict[str, deque] = defaultdict(deque)
        self.login_total: Counter = Counter()
        self.brute: dict[str, Brute] = {}
        self.ip_404: Counter = Counter()
        self.ip_404_paths: dict[str, set] = defaultdict(set)
        self.tool_ua: dict[str, list] = {}    
        self.ua_seen: set = set()              
    @staticmethod
    def _add(hits: dict, cat: str, sev: int, rule: str, ev: str) -> None:
        cur = hits.get(cat)
        if cur is None:
            hits[cat] = [sev, [rule], ev]
        elif sev > cur[0]:
            hits[cat] = [sev, [rule], ev]          
        elif sev == cur[0] and rule not in cur[1]:
            cur[1].append(rule)

    def _record(self, f: Finding) -> None:
        self.sev_count[f.sev] += 1
        self.cat_count[f.cat] += 1
        self.cat_ips[f.cat].add(f.ip)
        self.cat_maxsev[f.cat] = max(self.cat_maxsev[f.cat], f.sev)
        self.ip_sev[f.ip][f.sev] += 1
        self.ip_cats[f.ip][f.cat] += 1
        if 200 <= f.status < 300 and f.sev >= HIGH and f.cat in INJECTION_CATS:
            self.hit_2xx += 1
        if len(self.findings) < self.max_findings:
            self.findings.append(f)
        else:
            self.overflow += 1

    def risk(self, ip: str) -> int:
        raw = sum(SEV_WEIGHT[s] * (1 + math.log2(c)) for s, c in self.ip_sev[ip].items() if c)
        return min(100, int(raw))

    
    def feed(self, line: str) -> None:
        line = line.rstrip("\r\n")
        if not line.strip():
            return
        self.total_lines += 1
        m = LOG_RE.match(line)
        if not m:
            self.unparsed += 1
            if len(self.bad_samples) < 3:
                self.bad_samples.append(line[:120])
            return
        self.parsed += 1

        ip, req = m["ip"], m["req"]
        status = int(m["status"])
        ref, ua = m["ref"] or "-", m["ua"] or "-"
        ts = parse_ts(m["time"])
        if ts is not None:
            if self.first_ts is None or ts < self.first_ts:
                self.first_ts = ts
            if self.last_ts is None or ts > self.last_ts:
                self.last_ts = ts
        self.status_count[status // 100] += 1

        mm = REQ_RE.match(req)
        method, target = (mm.group(1), mm.group(2)) if mm else ("", req)
        path_only = target.split("?", 1)[0].lower()

        hits: dict[str, list] = {}
        add = self._add

        
        if ip not in self.ip_requests:
            kind = self.ip_kind[ip] = classify_ip(ip)
            if kind == "invalid" and ip != "unix:":
                add(hits, "anomip", MEDIUM, "Невалидный адрес в поле IP", ip)
        self.ip_requests[ip] += 1
        uas = self.ip_uas[ip]
        if len(uas) < 8:
            uas.add(hash(ua))

    
        if not mm:
            if req in ("", "-"):
                add(hits, "proto", LOW, "Пустой запрос (таймаут / health-check)", req)
            else:
                add(hits, "proto", MEDIUM, "Некорректная строка запроса (binary / TLS на HTTP / fuzz)", req)
        elif method not in STD_METHODS:
            add(hits, "proto", MEDIUM, f"Нестандартный метод {method[:12]}", method)
        if len(target) > LONG_URI:
            add(hits, "proto", MEDIUM, "Слишком длинный URI (fuzz / overflow)", f"{len(target)} байт")

        
        norm, layers = normalize(target)
        if layers >= 2:
            add(hits, "evasion", MEDIUM, f"Многократное URL-кодирование ({layers}×)", target[:60])
        if "%00" in target.lower() or "\\x00" in req:
            add(hits, "evasion", MEDIUM, "Null-byte в запросе", "%00")
        for r in RULES:
            mt = r.rx.search(norm)
            if mt:
                add(hits, r.cat, r.sev, r.name, mt.group(0)[:80])

        
        for raw_h, tag in ((ua, "User-Agent"), (ref, "Referer")):
            if raw_h != "-":
                for cat, sev, name, ev in scan_header(raw_h):
                    add(hits, cat, sev, f"{name} [{tag}]", ev)
        cu = classify_ua(ua)
        if cu:
            key = (ip, ua)                          
            if key not in self.ua_seen:             
                if len(self.ua_seen) < 200_000:
                    self.ua_seen.add(key)
                add(hits, cu[0], cu[1], cu[2], cu[3])
            if cu[0] == "scanner":
                rec = self.tool_ua.get(ua)
                if rec is None and len(self.tool_ua) < 500:
                    rec = self.tool_ua[ua] = [0, set()]
                if rec is not None:
                    rec[0] += 1
                    if len(rec[1]) < 1000:
                        rec[1].add(ip)

        
        ts_ok = ts is not None
        if ts_ok and ((method == "POST" and LOGIN_RE.search(path_only)) or status == 401):
            dq = self.login_hits[ip]
            dq.append(ts)
            while dq and ts - dq[0] > self.brute_window:
                dq.popleft()
            self.login_total[ip] += 1
            bf = self.brute.get(ip)
            if len(dq) >= self.brute_threshold:
                if bf is None:
                    bf = self.brute[ip] = Brute(first=dq[0], last=ts)
                bf.peak = max(bf.peak, len(dq))
            if bf is not None:
                bf.last, bf.total = ts, self.login_total[ip]
                bf.paths[path_only[:80]] += 1
                if method == "POST" and status in (302, 303):
                    bf.redirects += 1      

        if status == 404:
            self.ip_404[ip] += 1
            paths = self.ip_404_paths[ip]
            if len(paths) < 500:
                paths.add(path_only)

        
        for cat, (sev, rules, ev) in hits.items():
            rule = " + ".join(rules[:3])
            if cat == "recon" and sev >= HIGH and 200 <= status < 300:
                sev, rule = CRITICAL, rule + " — ФАЙЛ ОТДАН (2xx)"
            self._record(Finding(ts, ip, method, target, status, cat, sev, rule, ev))

    
    def finalize(self) -> None:
        for ip, bf in self.brute.items():
            top = ", ".join(p for p, _ in bf.paths.most_common(2)) or "—"
            ev = f"пик {bf.peak} попыток за {self.brute_window}с · всего {bf.total} · {top}"
            sev = HIGH
            if bf.redirects:
                sev, ev = CRITICAL, ev + f" · ⚠ {bf.redirects}× 302/303 после серии (возможный успешный вход)"
            self._record(Finding(bf.last, ip, "POST", top, 0, "brute", sev, "Подбор пароля", ev))

        for ip, n in self.ip_404.items():
            if n >= self.scan_threshold:
                sev = HIGH if n >= self.scan_threshold * 5 else MEDIUM
                ev = f"{n} ответов 404, {len(self.ip_404_paths[ip])} уникальных путей"
                self._record(Finding(self.last_ts, ip, "", "—", 0, "scan404", sev, "Перебор путей", ev))

        for ip, cats in list(self.ip_cats.items()):
            vectors = sorted(c for c in cats if c in MULTI_VECTOR_CATS)
            if len(vectors) >= 3:
                sev = HIGH if len(vectors) >= 4 else MEDIUM
                ev = "векторы: " + ", ".join(CATS[c][1] for c in vectors)
                self._record(Finding(self.last_ts, ip, "", "—", 0, "anomip", sev, "Мульти-векторная активность", ev))

        for ip, uas in self.ip_uas.items():
            if len(uas) >= 8 and self.ip_requests[ip] >= 20:
                self._record(Finding(self.last_ts, ip, "", "—", 0, "anomip", LOW,
                                     "Ротация User-Agent", f"{len(uas)}+ разных UA с одного IP"))



_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def safe(s, limit: int = 80) -> str:
    """Данные из лога — недоверенные: вычищаем управляющие символы (ANSI-инъекции, RLO)."""
    s = _CTRL.sub("·", str(s))
    return s if len(s) <= limit else s[: limit - 1] + "…"


def fmt_ts(ts, fmt="%m-%d %H:%M:%S") -> str:
    return "—" if ts is None else datetime.fromtimestamp(ts, timezone.utc).strftime(fmt)


def bar(value: float, maximum: float, width: int = 20) -> str:
    return "" if maximum <= 0 or value <= 0 else "█" * max(1, round(width * value / maximum))


def status_style(code: int) -> str:
    if code == 0:
        return "dim"
    if 200 <= code < 300:
        return "bold red"          
    if code >= 500:
        return "bold magenta"      
    if 300 <= code < 400:
        return "yellow"
    return "green"                 


def render(console, an: Analyzer, args, files, elapsed: float) -> None:
    from rich import box
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    def T(s, style="", limit=80):
        return Text(safe(s, limit), style=style)

    
    console.print()
    console.print(Panel(
        Text.assemble(("◆  S O C   S E N T I N E L  ◆", "bold cyan"), "\n",
                      ("SQLi · XSS · SSRF · LFI · RCE · Brute-force · сканеры · аномальные IP", "dim"),
                      justify="center"),
        box=box.DOUBLE, border_style="cyan", padding=(0, 2)))

    
    names = ", ".join("stdin" if f == "-" else Path(f).name for f in files)
    ov = Table.grid(padding=(0, 2))
    ov.add_column(style="dim")
    ov.add_column()
    ov.add_row("Источник", T(names, "bold", 60))
    ov.add_row("Строк", f"{an.total_lines:,}  (не распознано: {an.unparsed:,})")
    ov.add_row("Уникальных IP", f"{len(an.ip_requests):,}")
    ov.add_row("Период (UTC)", f"{fmt_ts(an.first_ts, '%Y-%m-%d %H:%M')} → {fmt_ts(an.last_ts, '%Y-%m-%d %H:%M')}")
    sc = an.status_count
    ov.add_row("Коды ответа", Text.assemble(
        (f"2xx {sc[2]:,}", "green"), "  ", (f"3xx {sc[3]:,}", "yellow"), "  ",
        (f"4xx {sc[4]:,}", "red"), "  ", (f"5xx {sc[5]:,}", "magenta")))
    ov.add_row("Время анализа", f"{elapsed:.2f} c  ({an.total_lines / max(elapsed, 1e-9):,.0f} строк/с)")

    sev_grid = Table.grid(padding=(0, 2))
    mx = max(an.sev_count.values(), default=0)
    for s in (CRITICAL, HIGH, MEDIUM, LOW):
        sev_grid.add_row(Text(f" {SEV_NAME[s]:<8}", style=SEV_STYLE[s]),
                         Text(f"{an.sev_count[s]:>7,}", style="bold"),
                         Text(bar(an.sev_count[s], mx, 22), style=SEV_BAR[s]))

    top = Table.grid(expand=True, padding=(0, 1))
    top.add_column(ratio=1)
    top.add_column(ratio=1)
    top.add_row(Panel(ov, title="Обзор", border_style="blue"),
                Panel(sev_grid, title="Находки по уровню", border_style="blue"))
    console.print(top)

    if not an.findings:
        console.print(Panel(Text("Подозрительной активности не обнаружено.", style="bold green"),
                            border_style="green", title="ВЕРДИКТ"))
        _bad_samples(console, an)
        return

    
    t = Table(title="Типы угроз", title_justify="left", box=box.ROUNDED, header_style="bold magenta", expand=True)
    t.add_column("Тип")
    t.add_column("Срабатываний", justify="right")
    t.add_column("IP", justify="right")
    t.add_column("Макс.", no_wrap=True)
    t.add_column("Доля", ratio=1)
    cmax = max(an.cat_count.values())
    for cat in sorted(an.cat_count, key=lambda c: (-an.cat_maxsev[c], -an.cat_count[c])):
        ms = an.cat_maxsev[cat]
        t.add_row(CATS[cat][0], f"{an.cat_count[cat]:,}", f"{len(an.cat_ips[cat]):,}",
                  Text(f" {SEV_NAME[ms]} ", style=SEV_STYLE[ms]),
                  Text(bar(an.cat_count[cat], cmax, 30), style=SEV_BAR[ms]))
    console.print(t)


    ips = sorted(an.ip_sev, key=lambda i: (-an.risk(i), -an.ip_requests[i]))[: args.top]
    t = Table(title=f"Топ-{len(ips)} подозрительных IP", title_justify="left", box=box.ROUNDED,
              header_style="bold magenta", expand=True)
    for col, kw in (("#", {"justify": "right"}), ("IP", {"no_wrap": True, "style": "bold"}), ("Адрес", {}),
                    ("Запросов", {"justify": "right"}), ("Находок", {"justify": "right"}),
                    ("Риск", {"no_wrap": True}), ("Векторы", {"overflow": "fold", "ratio": 1})):
        t.add_column(col, **kw)
    for n, ip in enumerate(ips, 1):
        score = an.risk(ip)
        style = "bold red" if score >= 70 else "bold yellow" if score >= 40 else "cyan"
        vec = ", ".join(CATS[c][1] for c, _ in an.ip_cats[ip].most_common())
        t.add_row(str(n), T(ip, limit=45), an.ip_kind.get(ip, "?"), f"{an.ip_requests[ip]:,}",
                  f"{sum(an.ip_sev[ip].values()):,}",
                  Text.assemble((f"{score:>3} ", style), (bar(score, 100, 12), style)),
                  Text(vec, style="yellow"))
    console.print(t)

    if an.brute:
        t = Table(title="Brute-force / подбор паролей", title_justify="left", box=box.ROUNDED,
                  header_style="bold magenta", expand=True)
        for col, kw in (("IP", {"no_wrap": True, "style": "bold"}),
                        (f"Пик за {an.brute_window}с", {"justify": "right"}),
                        ("Всего", {"justify": "right"}), ("Цель", {"overflow": "fold", "ratio": 1}),
                        ("Период (UTC)", {"no_wrap": True}), ("Заметка", {"overflow": "fold", "ratio": 1})):
            t.add_column(col, **kw)
        for ip, bf in sorted(an.brute.items(), key=lambda kv: -kv[1].peak)[: args.top]:
            note = (Text(f"⚠ {bf.redirects}× 302/303 после серии — проверьте, не вошли ли", style="bold red")
                    if bf.redirects else Text("—", style="dim"))
            t.add_row(T(ip, limit=45), f"{bf.peak:,}", f"{bf.total:,}",
                      T(", ".join(p for p, _ in bf.paths.most_common(2)), limit=60),
                      f"{fmt_ts(bf.first, '%H:%M:%S')} → {fmt_ts(bf.last, '%H:%M:%S')}", note)
        console.print(t)

    
    if an.tool_ua:
        t = Table(title="Сканеры и скрипты по User-Agent", title_justify="left", box=box.ROUNDED,
                  header_style="bold magenta", expand=True)
        t.add_column("User-Agent", overflow="fold", ratio=1)
        t.add_column("Запросов", justify="right")
        t.add_column("IP", justify="right")
        for ua, (cnt, uips) in sorted(an.tool_ua.items(), key=lambda kv: -kv[1][0])[:8]:
            t.add_row(T(ua, "yellow", 90), f"{cnt:,}", f"{len(uips):,}")
        console.print(t)

    
    min_sev = SEV_BY_NAME[args.min_severity]
    shown = sorted((f for f in an.findings if f.sev >= min_sev), key=lambda f: (-f.sev, f.ts or 0))
    t = Table(title=f"Находки (топ-{min(args.limit, len(shown))} из {len(shown):,}, по убыванию опасности)",
              title_justify="left", box=box.SIMPLE_HEAD, header_style="bold", expand=True, pad_edge=False)
    t.add_column("Время (UTC)", no_wrap=True, style="dim")
    t.add_column("Уровень", no_wrap=True)
    t.add_column("Тип", no_wrap=True)
    t.add_column("IP", no_wrap=True, style="bold")
    t.add_column("Запрос", overflow="fold", ratio=3)
    t.add_column("Код", justify="right", no_wrap=True)
    t.add_column("Сработало", overflow="fold", ratio=2)
    for f in shown[: args.limit]:
        t.add_row(fmt_ts(f.ts), Text(f" {SEV_NAME[f.sev]} ", style=SEV_STYLE[f.sev]), CATS[f.cat][1],
                  T(f.ip, limit=45), T(f"{f.method} {f.target}".strip(), limit=110),
                  Text(str(f.status) if f.status else "—", style=status_style(f.status)),
                  Text.assemble((safe(f.rule, 70), "white"), "\n", (safe(f.evidence, 70), "dim italic")))
    console.print(t)
    hidden = len(shown) - args.limit
    if hidden > 0:
        console.print(Text(f"  … ещё {hidden:,} находок скрыто (--limit, --min-severity)", style="dim"))
    if an.overflow:
        console.print(Text(f"  ⚠ лимит хранения: {an.overflow:,} находок учтены в счётчиках, но не показаны "
                           f"(--max-findings)", style="dim yellow"))
    console.print(Text.assemble(
        ("  Код ответа:  ", "dim"), ("2xx", "bold red"), (" прошло  ", "dim"), ("5xx", "bold magenta"),
        (" ошибка сервера  ", "dim"), ("3xx", "yellow"), (" редирект  ", "dim"), ("4xx", "green"), (" отбито", "dim")))


    hot = [f for f in shown if 200 <= f.status < 300 and f.sev >= HIGH and f.cat in INJECTION_CATS]
    if hot:
        t = Table(title=f"⚠ Требуют проверки: сервер ответил 2xx на атаку ({an.hit_2xx:,})",
                  title_justify="left", title_style="bold red", box=box.HEAVY_HEAD, border_style="red",
                  header_style="bold red", expand=True)
        t.add_column("IP", no_wrap=True, style="bold")
        t.add_column("Запрос", overflow="fold", ratio=1)
        t.add_column("Код", justify="right")
        t.add_column("Тип", no_wrap=True)
        for f in hot[:8]:
            t.add_row(T(f.ip, limit=45), T(f"{f.method} {f.target}", limit=110),
                      Text(str(f.status), style="bold red"), CATS[f.cat][1])
        console.print(t)

    if an.sev_count[CRITICAL]:
        level, style = "КРИТИЧЕСКИЙ", "bold white on red"
    elif an.sev_count[HIGH]:
        level, style = "ВЫСОКИЙ", "bold red"
    elif an.sev_count[MEDIUM]:
        level, style = "СРЕДНИЙ", "bold yellow"
    else:
        level, style = "НИЗКИЙ", "bold cyan"

    lines: list = [Text.assemble(("Уровень угрозы: ", "bold"), (f" {level} ", style))]
    todo = []
    if an.hit_2xx:
        todo.append("Проверьте запросы с ответом 2xx из таблицы выше — возможна успешная эксплуатация.")
    if any(bf.redirects for bf in an.brute.values()):
        todo.append("После brute-force были 302/303 на login — проверьте аккаунты и сессии этих IP.")
    elif an.brute:
        todo.append("Включите rate-limit на login (nginx limit_req / fail2ban) и 2FA.")
    if "sqli" in an.cat_count:
        todo.append("SQLi: параметризованные запросы, WAF (ModSecurity + OWASP CRS).")
    if "ssrf" in an.cat_count:
        todo.append("SSRF: запретите исходящий доступ приложения к внутренним сетям и metadata (IMDSv2).")
    if "rce" in an.cat_count:
        todo.append("RCE/Log4Shell: проверьте версии зависимостей и сразу ищите следы в логах приложения.")
    if "recon" in an.cat_count and an.cat_maxsev["recon"] >= HIGH:
        todo.append("Закройте доступ к .env/.git/бэкапам на уровне веб-сервера.")
    for item in todo:
        lines.append(Text(f"  • {item}"))

    block = [ip for ip in ips if an.risk(ip) >= 40 and an.ip_kind.get(ip) == "public"][:10]
    if block:
        lines.append(Text("\nКандидаты на блокировку (nginx):", style="bold"))
        for ip in block:
            lines.append(Text(f"  deny {ip};", style="green"))
    console.print(Panel(Group(*lines), title="ВЕРДИКТ", border_style=style.split()[-1] if "on" not in style else "red"))
    _bad_samples(console, an)


def _bad_samples(console, an: Analyzer) -> None:
    from rich.text import Text
    if an.unparsed:
        console.print(Text(f"Не распознано строк: {an.unparsed:,} (ожидается формат combined). Примеры:", style="dim yellow"))
        for s in an.bad_samples:
            console.print(Text("  " + safe(s, 120), style="dim"))



def collect_files(paths: list[str]) -> list:
    files: list = []
    for p in paths:
        if p == "-":
            files.append("-")
            continue
        pp = Path(p)
        if pp.is_dir():
            found = [f for f in pp.iterdir() if f.is_file() and "access" in f.name and "error" not in f.name]
            files.extend(sorted(found, key=lambda f: f.stat().st_mtime))   # старые ротации — первыми
        else:
            files.append(pp)
    return files


def read_file(path, an: Analyzer, console) -> None:
    from rich.markup import escape
    from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn, TimeElapsedColumn

    if path == "-":
        stream, raw, size, name = sys.stdin.buffer, None, None, "stdin"
    else:
        raw = open(path, "rb")
        size = os.fstat(raw.fileno()).st_size
        stream = gzip.GzipFile(fileobj=raw) if str(path).endswith(".gz") else raw
        name = Path(path).name

    progress = Progress(TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(),
                        TextColumn("{task.fields[lines]:,} строк"), TimeElapsedColumn(),
                        console=console, transient=True)
    n = 0
    try:
        with progress:
            task = progress.add_task(f"[cyan]Анализ[/] {escape(name)}", total=size, lines=0)
            for n, chunk in enumerate(stream, 1):
                an.feed(chunk.decode("utf-8", "replace"))
                if n % 4000 == 0:
                    progress.update(task, completed=raw.tell() if raw else 0, lines=n)
            progress.update(task, completed=size or 0, lines=n)
    finally:
        if raw:
            raw.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="soc-sentinel", description="Анализатор access-логов веб-сервера для SOC")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="проанализировать access-лог")
    a.add_argument("paths", nargs="+", metavar="PATH", help="файл(ы), каталог с логами или '-' для stdin")
    a.add_argument("--top", type=int, default=10, help="сколько IP показывать в топе (10)")
    a.add_argument("--limit", type=int, default=25, help="сколько находок показать в таблице (25)")
    a.add_argument("--min-severity", choices=list(SEV_BY_NAME), default="low", help="мин. уровень для таблицы находок")
    a.add_argument("--brute-threshold", type=int, default=10, help="попыток входа для brute-force (10)")
    a.add_argument("--brute-window", type=int, default=60, help="окно brute-force, сек (60)")
    a.add_argument("--scan-threshold", type=int, default=30, help="404 с одного IP для 'перебора путей' (30)")
    a.add_argument("--max-findings", type=int, default=50_000, help="лимит хранимых находок (память)")
    a.add_argument("--force-color", action="store_true", help="цвета даже без TTY (но лучше docker run -t)")
    return p


def main(argv=None) -> int:
    from rich.console import Console
    from rich.text import Text

    args = build_parser().parse_args(argv)
    console = Console(force_terminal=True if args.force_color else None, highlight=False)

    try:
        files = collect_files(args.paths)
        if not files:
            console.print(Text("Не найдено файлов access-логов — укажите файл явно.", style="bold red"))
            return 2
        an = Analyzer(args.brute_threshold, args.brute_window, args.scan_threshold, args.max_findings)
        t0 = time.perf_counter()
        for f in files:
            read_file(f, an, console)
        an.finalize()
        render(console, an, args, files, time.perf_counter() - t0)
    except PermissionError as e:
        console.print(Text(f"Нет доступа: {e}", style="bold red"))
        console.print(Text("Логи nginx обычно 0640 www-data:adm — запустите контейнер от root или добавьте "
                           "нужную группу (--group-add).", style="yellow"))
        return 2
    except OSError as e:
        console.print(Text(f"Ошибка чтения: {e}", style="bold red"))
        return 2
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())

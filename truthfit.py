#!/usr/bin/env python3
"""
truthfit — tailor a resume to a job for ATS and AI screeners, using only the truth.

The model proposes; deterministic executed checks own the verdict.

  1. Reads your base resume (.docx / .md / .txt / .pdf) and the job (URL and/or file).
     Greenhouse, Lever, Ashby and Workday are read through their public JSON APIs;
     Eightfold (Netflix, NVIDIA, Microsoft) and most other pages through JSON-LD.
  2. Reads your evidence files (portfolio, notes, old resumes) — the only other
     place a line may come from.
  3. Builds a tailored resume with moves that cannot invent a claim: reorder bullets
     and skills, add a JD keyword only when your own files state it (never in a
     negated sentence), pull verbatim evidence lines aimed at weak qualifications,
     add the posting's spelling of a skill you already list, add a "Target role" line.
  4. Optional AI rewrite: a model may rephrase a bullet; a deterministic gate rejects
     new numbers (digits or words), names, skills, scope words and buzzwords, then a
     second model call rejects anything that claims more than the original.
  5. FAIL-CLOSED VERIFIER: every line of the output (and of the .docx round-tripped
     back to text) must be verbatim from your files or a gated rewrite of such a line.
     Optional --identity and --forbidden checks. Any failure writes nothing but the report.
  6. Grades the result the way AI screeners do (HiredScore-style A–D per qualification),
     then has a real model screen it with every quoted line verified.
  7. Parser checks from Textkernel's published resume-quality codes, a PDF round trip,
     Word-file layout traps, hidden-text detection, and notes for the engine that will
     read this application (Eightfold, Workday, Greenhouse, Ashby, Lever, iCIMS, Taleo,
     Dice, LinkedIn, Indeed, ZipRecruiter, HireVue, ...).

Usage:
  python3 truthfit.py                                  # interactive
  python3 truthfit.py --resume base.docx --url https://jobs.ashbyhq.com/acme/123 --evidence notes.md
  python3 truthfit.py --check-file my_resume.pdf       # parseability audit only
  python3 truthfit.py --ats-map applications.jsonl     # which engine reads each job link
"""

import argparse, datetime, html, html.parser, json, os, re, shutil, subprocess, sys, tempfile
import urllib.parse, urllib.request
from collections import OrderedDict

# Terms that must never appear in output (private project names, NDA'd clients...).
# Loaded at run time from --forbidden FILE or $TRUTHFIT_FORBIDDEN — never stored in this repo.
FORBIDDEN_LEAKS = []

SKILL_TAXONOMY = {
    "AI & Agentic Systems": [
        "llm", "large language models", "agent", "agents", "agentic", "multi-agent",
        "agent orchestration", "tool use", "function calling", "model context protocol",
        "mcp", "rag", "retrieval augmented generation", "vector database", "embeddings",
        "prompt engineering", "few-shot", "fine-tuning", "rlhf", "dpo", "langchain",
        "llamaindex", "hugging face", "pytorch", "transformers", "openai api",
        "anthropic api", "gemini", "claude", "deepseek", "copilot"
    ],
    "Evaluation, Alignment & Red-Teaming": [
        "evaluation", "evals", "eval harness", "benchmarking", "llm-as-judge",
        "red teaming", "adversarial testing", "adversarial", "jailbreak",
        "prompt injection", "contamination", "ground truth", "inter-rater",
        "rubric", "golden set", "truthfulness", "hallucination", "alignment",
        "audit trail", "deterministic verification"
    ],
    "Systems, Cloud & Infrastructure": [
        "linux", "linux kernel", "cgroups", "docker", "kubernetes", "k8s",
        "distributed systems", "microservices", "rest api", "fastapi", "flask",
        "ci/cd", "github actions", "aws", "azure", "gcp", "asyncio", "concurrency",
        "ipc", "socket", "state management", "atomic", "slurm", "mlops", "llmops"
    ],
    "Hardware & GPU Systems": [
        "nvidia", "hgx", "dgx", "a100", "h100", "b200", "gpu", "gpu cluster",
        "nvlink", "nvswitch", "infiniband", "nccl", "cuda", "hardware bring-up",
        "firmware", "fpga", "retimer", "fault isolation", "diagnostics"
    ],
    "Security & Sandbox": [
        "security", "appsec", "application security", "threat modeling",
        "sandbox", "sandbox confinement", "tee", "enclave", "penetration testing",
        "owasp", "static analysis", "vulnerability management", "splunk", "siem",
        "soc", "incident response", "security+", "network+"
    ],
    "Programming Languages": [
        "python", "typescript", "javascript", "rust", "go", "golang", "c++",
        "solidity", "sql", "bash", "shell"
    ]
}

ADDED_SECTION = "Additional Relevant Work"
# Background model calls: no tools, no saved session, and NO HOOKS — a user Stop hook firing
# inside the sub-session makes it keep talking and the real answer gets buried.
CLAUDE_CMD = ["claude", "-p", "--output-format", "json", "--no-session-persistence", "--tools", "",
              "--settings", '{"disableAllHooks": true}']
ADDED_SKILLS_LABEL = "Additional Skills"

# Terms the base taxonomy lacks. Lower-case; matched case-insensitively.
EXTRA_TERMS = [
    "java", "c#", ".net", "node.js", "react", "next.js", "vue", "angular", "svelte",
    "django", "graphql", "grpc", "postgresql", "mysql", "mongodb", "redis", "kafka",
    "rabbitmq", "spark", "airflow", "snowflake", "databricks", "elasticsearch",
    "terraform", "ansible", "helm", "prometheus", "grafana", "opentelemetry",
    "datadog", "nginx", "jenkins", "gitlab", "git", "github", "jira", "agile", "scrum",
    "unit testing", "integration testing", "test automation", "pytest", "foundry",
    "machine learning", "deep learning", "nlp", "natural language processing",
    "computer vision", "tensorflow", "scikit-learn", "pandas", "numpy", "jupyter",
    "data pipelines", "etl", "observability", "monitoring", "logging", "tracing",
    "networking", "tcp/ip", "dns", "tls", "oauth", "saml", "sso", "iam", "zero trust",
    "cryptography", "encryption", "pki", "devsecops", "sast", "dast", "fuzzing",
    "secure code review", "code review", "vulnerability", "cve", "mitre att&ck",
    "soar", "edr", "forensics", "malware analysis", "reverse engineering",
    "smart contracts", "ethereum", "blockchain", "web3", "defi",
    "macos", "windows", "unix", "embedded systems", "hardware", "asr", "speech recognition",
    "whisper", "sdk", "api design", "system design", "scalability", "reliability",
    "sre", "on-call", "serverless", "lambda", "s3", "ec2", "containers",
    "virtualization", "gvisor", "firecracker", "wasm", "webassembly",
    "customer-facing", "technical writing", "documentation", "mentoring",
    "isolation", "secrets management", "identity and access management", "access control", "detection",
    "detection engineering", "product security", "infrastructure security", "cloud security", "web security",
    "network security", "compliance", "soc 2", "iso 27001", "multi-tenant", "design review", "supply chain security",
    "least privilege", "container security", "hardening", "untrusted code", "runtime",
    "authentication", "authorization", "audit logging", "threat detection", "security tooling", "automation",
    "python scripting", "debugging", "troubleshooting", "root cause analysis", "performance optimization",
    "data analysis", "sql queries", "excel", "data entry", "customer service", "project management",
]

# Gap → related things you might genuinely have. A JD term with no exact match in your files
# is NEVER written into the resume; instead your closest real line (verbatim) is moved up and
# named in the report as a talking point. No related line → the gap is just a gap.
ADJACENT = {
    "kubernetes": ["docker", "containers", "container", "cgroups", "sandbox", "orchestration", "microservices"],
    "golang": ["rust", "c++", "typescript", "systems programming"],
    "go": ["rust", "c++", "typescript"],
    "java": ["typescript", "c#", "python"], "c#": ["typescript", "java"], "c++": ["rust", "c"],
    "application security": ["owasp", "secure sdlc", "threat modeling", "penetration testing", "static analysis", "vulnerability"],
    "appsec": ["owasp", "secure sdlc", "threat modeling", "penetration testing", "static analysis"],
    "product security": ["threat modeling", "secure sdlc", "owasp", "vulnerability"],
    "web security": ["owasp", "xss", "penetration testing", "web vulnerability"],
    "infrastructure security": ["sandbox", "cgroups", "linux", "network+", "firmware", "enclave"],
    "cloud security": ["aws", "azure", "gcp", "iam", "sandbox"],
    "secrets management": ["secret", "enclave", "tee", "credential", "key management"],
    "multi-tenant": ["sandbox", "isolation", "concurrent", "sessions"],
    "untrusted code": ["sandbox", "isolation", "untrusted", "prompt injection", "confinement"],
    "isolation": ["sandbox", "confinement", "enclave", "tee", "cgroups"],
    "security tooling": ["enforcement", "scanner", "detection", "static analysis", "splunk"],
    "design review": ["threat modeling", "architecture", "code review"],
    "terraform": ["ci/cd", "github actions", "docker", "infrastructure"],
    "ansible": ["bash", "automation", "ci/cd"],
    "postgresql": ["sql", "database"], "mysql": ["sql", "database"], "mongodb": ["sql", "database", "json"],
    "kafka": ["zmq", "message bus", "streaming", "queue"], "redis": ["cache", "state management"],
    "react": ["typescript", "javascript", "frontend"], "svelte": ["react", "typescript", "frontend"],
    "fine-tuning": ["evaluation", "pytorch", "training data", "rlhf"], "rlhf": ["rubric", "reference-answer", "alignment"],
    "observability": ["opentelemetry", "monitoring", "logging", "audit trail", "telemetry"],
    "monitoring": ["telemetry", "detection", "splunk", "alerts"],
    "incident response": ["forensics", "triage", "detection", "splunk"],
    "detection": ["splunk", "spl", "anomaly", "siem"],
    "compliance": ["audit trail", "policy", "deterministic policy", "audit"],
    "distributed systems": ["multi-agent", "concurrent", "orchestration", "cluster"],
    "gpu": ["hgx", "dgx", "a100", "h100", "nvidia"], "cuda": ["gpu", "nccl", "hgx", "dgx"],
    "machine learning": ["llm", "pytorch", "evaluation", "whisper", "embeddings"],
}

# Same skill, different spelling. If the JD says any of these and your files say any
# other, the claim is the same — the JD's spelling is used.
ALIASES = [
    ["kubernetes", "k8s"], ["javascript", "js"], ["golang", "go lang", "go"],
    ["postgresql", "postgres"], ["ci/cd", "continuous integration", "ci cd"],
    ["llm", "llms", "large language model", "large language models"],
    ["rag", "retrieval augmented generation", "retrieval-augmented generation"],
    ["mcp", "model context protocol"], ["security+", "security plus"],
    ["network+", "network plus"], ["a+", "a plus"], ["aws", "amazon web services"],
    ["gcp", "google cloud", "google cloud platform"], ["ml", "machine learning"],
    ["nlp", "natural language processing"], ["rest api", "rest apis", "restful api", "restful apis"],
    ["red teaming", "red-teaming", "red team"], ["evals", "evaluations", "evaluation"],
    ["llm-as-judge", "llm as judge", "llm-as-a-judge"], ["node.js", "nodejs", "node"],
    ["c++", "cpp"], ["asr", "speech recognition", "automatic speech recognition"],
    ["wasm", "webassembly"], ["appsec", "application security"],
    ["ai", "artificial intelligence"], ["tee", "trusted execution environment"],
]
CASE_SENSITIVE = {t: t.upper() for t in ("ai", "ml", "js", "tee", "sso", "iam", "dns", "tls", "etl", "cve", "sre", "asr", "edr", "pki")}
CASE_SENSITIVE.update({"a+": "A+", "node": "Node", "go": "Go"})
DROP_TERMS = {"go", "agent", "agents", "atomic", "socket", "security", "diagnostics", "adversarial"}  # too generic / ambiguous alone

ALLCAPS_STOP = {"US", "USA", "EEO", "EOE", "PTO", "HR", "CEO", "CTO", "CFO", "COO", "LLC", "INC", "OR",
                "AND", "THE", "WE", "YOU", "IT", "OF", "TO", "IN", "ON", "AT", "BY", "NA", "TBD", "FAQ",
                "VP", "EST", "BS", "MS", "BA", "MA", "PHD", "MBA", "BSC", "MSC", "PST", "CST", "UTC", "ADA", "DE", "NM", "TX", "CA", "NY", "LA", "SF", "W2", "C2C",
                "FT", "PT", "OK", "ID", "AM", "PM", "II", "III", "IV", "Q1", "Q2", "Q3", "Q4", "401K"}

NEGATION = re.compile(r"\b(never|not|without|lack|lacks|lacking|unfamiliar|no (?:experience|exposure|background|production)|"
                      r"\w+n't|cannot|zero experience|have yet to)\b", re.I)

SECTION_KINDS = [
    ("summary", r"summary|profile|objective|about me|overview"),
    ("skills", r"skill|competenc|technolog|tools|tech stack|expertise"),
    ("education", r"education|certif|training|licen|degree"),
    ("experience", r"experience|employment|work history|career|professional background"),
    ("projects", r"project|portfolio|selected|proof|publication|open source|evidence|work"),
]
KNOWN_HEADINGS = re.compile(r"^(professional |technical |work |selected |relevant |core )?(summary|profile|objective|skills|"
                            r"experience|employment|education|certifications?|projects|technical skills|"
                            r"education and certifications|proof of work|open source)$", re.I)
META = re.compile(r"~/|/Users/|\.(?:md|pdf|docx|json|py|txt)\b|r[ée]sum[ée]|readme|\bcite\b|\bstale\b|source of record|"
                  r"\bclaim(?:s|ed)?\b|\bstatus\b|\bnote:|\bverified by\b|\bsee (?:above|below)\b", re.I)
BULLET_RE = re.compile(r"^\s*(?:[-*+•●▪◦‣–]|\d+[.)])\s+")
DATE_HINT = re.compile(r"\b(19|20)\d{2}\b|\bpresent\b", re.I)


# ───────────────────────────── text utilities ─────────────────────────────

def norm(s):
    """Canonical form used for verbatim comparison: no markdown, unified punctuation, single spaces."""
    s = s.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    s = s.replace("–", "-").replace("—", "-").replace(" ", " ").replace("\\", "")
    s = re.sub(r"!\[[^\]]*\]\([^)]*\)", " ", s)
    s = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", s)
    s = re.sub(r"<[^>]+>", " ", s)
    s = s.replace("**", "").replace("__", "").replace("`", "").replace("|", " ")
    s = re.sub(r"(?<![A-Za-z0-9])[*_](?=\S)|(?<=\S)[*_](?![A-Za-z0-9])", "", s)
    s = re.sub(r"^\s*#+\s*", "", s)
    s = BULLET_RE.sub("", s)
    s = re.sub(r"^\s*>\s*", "", s)
    return re.sub(r"\s+", " ", s).strip()


def term_regex(term):
    low = term.lower()
    if low in CASE_SENSITIVE:   # "AI" must not match "ai" inside prose noise; "Node" not "node"
        return re.compile(r"(?<![A-Za-z0-9])" + re.escape(CASE_SENSITIVE[low]) + r"(?![A-Za-z0-9+#])")
    flags = 0 if (term.isupper() and len(term) <= 6) else re.I   # "MS" must not match "822 ms"
    stem = ""
    if flags and len(term) >= 5 and term[-1].isalpha():           # hardening ↔ hardened ↔ harden
        if not re.search(r"(ss|us|is)$", term):
            term = re.sub(r"(ing|ed|es|s)$", "", term) if len(re.sub(r"(ing|ed|es|s)$", "", term)) >= 4 else term
        stem = r"(?:e|s|es|ing|ed|d|e[sd])?"
    return re.compile(r"(?<![A-Za-z0-9])" + re.escape(term) + stem + r"(?![A-Za-z0-9+#])", flags)


_ALIAS_INDEX = {}
for grp in ALIASES:
    for a in grp:
        _ALIAS_INDEX.setdefault(a.lower(), set()).update(grp)


def variants(term):
    return sorted(_ALIAS_INDEX.get(term.lower(), set()) | {term}, key=len, reverse=True)


_RX_CACHE = {}


def has_term(text, term):
    for v in variants(term):
        rx = _RX_CACHE.get(v) or _RX_CACHE.setdefault(v, term_regex(v))
        if rx.search(text):
            return True
    return False


def slug(s):
    return re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_")[:60] or "job"


# ───────────────────────────── reading files ─────────────────────────────

def read_any(path):
    """Return a file's text as markdown-ish lines."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".docx":
        if not shutil.which("pandoc"):
            sys.exit("pandoc is required to read .docx (brew install pandoc)")
        md = subprocess.run(["pandoc", path, "-t", "gfm", "--wrap=none"], capture_output=True, text=True, check=True).stdout
        return tables_to_lines(md)
    if ext == ".pdf":
        try:
            txt = subprocess.run(["pdftotext", path, "-"], capture_output=True, text=True, check=True).stdout
        except Exception:
            import pypdf
            txt = "\n".join(p.extract_text() or "" for p in pypdf.PdfReader(path).pages)
        return plaintext_to_md(txt)
    if ext in (".html", ".htm"):
        return html_to_text(open(path, encoding="utf-8", errors="ignore").read())
    return tables_to_lines(open(path, encoding="utf-8", errors="ignore").read())


def tables_to_lines(md):
    """Markdown table rows become 'Label: cells' lines — ATS parsers mangle tables."""
    out = []
    for line in md.splitlines():
        s = line.strip()
        if s.startswith("|") and s.endswith("|"):
            cells = [c.strip() for c in s.strip("|").split("|")]
            if all(re.fullmatch(r":?-{2,}:?", c) or not c for c in cells):
                continue
            cells = [c for c in cells if c]
            if len(cells) >= 2:
                out.append(f"{cells[0].rstrip(':')}: {' · '.join(cells[1:]) if len(cells) > 2 else cells[1]}")
            elif cells:
                out.append(cells[0])
        else:
            out.append(line)
    return "\n".join(out)


def plaintext_to_md(txt):
    """PDF text → markdown: ALL-CAPS / known headings become '## ', bullet glyphs become '- '."""
    out = []
    for raw in txt.splitlines():
        s = raw.strip()
        if not s:
            out.append("")
            continue
        if (len(s) <= 45 and s.upper() == s and re.search(r"[A-Z]{3}", s) and not re.search(r"[@\d]", s)) \
                or KNOWN_HEADINGS.match(s.rstrip(":")):
            out.append("## " + s.rstrip(":").title())
            continue
        if BULLET_RE.match(s):
            out.append("- " + BULLET_RE.sub("", s))
            continue
        # continuation of a wrapped bullet
        if out and out[-1].startswith("- ") and (s[0].islower() or not re.search(r"[.!?:]$", out[-1])) and not DATE_HINT.search(s):
            out[-1] += " " + s
            continue
        out.append(s)
    return "\n".join(out)


class _Strip(html.parser.HTMLParser):
    BLOCK = {"p", "div", "br", "li", "ul", "ol", "h1", "h2", "h3", "h4", "h5", "h6", "tr", "section", "article", "header"}

    def __init__(self):
        super().__init__()
        self.parts, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript", "svg", "nav", "footer"):
            self.skip += 1
        elif tag in self.BLOCK:
            self.parts.append("\n- " if tag == "li" else ("\n## " if tag in ("h1", "h2", "h3", "h4") else "\n"))

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript", "svg", "nav", "footer"):
            self.skip = max(0, self.skip - 1)
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def html_to_text(h):
    p = _Strip()
    p.feed(h)
    lines = [re.sub(r"[ \t]+", " ", l).strip() for l in "".join(p.parts).splitlines()]
    out = []
    for l in lines:
        if l in ("-", "##"):
            continue
        if l or (out and out[-1]):
            out.append(l)
    return "\n".join(out).strip()


# ───────────────────────────── fetching the job URL ─────────────────────────────

def _get(url, as_json=False):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36",
                                               "Accept": "application/json" if as_json else "text/html,*/*"})
    with urllib.request.urlopen(req, timeout=25) as r:
        body = r.read().decode("utf-8", errors="ignore")
    return json.loads(body) if as_json else body


def fetch_job(url):
    """Return (title, company, text) for a job URL."""
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url.lstrip("/")
    u = urllib.parse.urlparse(url)
    host, parts = u.netloc.lower(), [p for p in u.path.split("/") if p]
    qs = urllib.parse.parse_qs(u.query)

    if "greenhouse.io" in host and ("jobs" in parts or "gh_jid" in qs):
        board = parts[0] if parts and parts[0] != "embed" else qs.get("for", [""])[0]
        jid = qs.get("gh_jid", [None])[0] or parts[parts.index("jobs") + 1]
        j = _get(f"https://boards-api.greenhouse.io/v1/boards/{board}/jobs/{jid}", True)
        return j.get("title", ""), (j.get("company_name") or board), html_to_text(html.unescape(j.get("content", "")))
    if "lever.co" in host and len(parts) >= 2:
        j = _get(f"https://api.lever.co/v0/postings/{parts[0]}/{parts[1]}", True)
        txt = [j.get("descriptionPlain", "")]
        for blk in j.get("lists", []):
            txt.append("## " + blk.get("text", ""))
            txt.append(html_to_text(blk.get("content", "")))
        txt.append(j.get("additionalPlain", ""))
        return j.get("text", ""), parts[0], "\n".join(txt)
    if "ashbyhq.com" in host and len(parts) >= 2:
        j = _get(f"https://api.ashbyhq.com/posting-api/job-board/{parts[0]}?includeCompensation=true", True)
        for job in j.get("jobs", []):
            if parts[1] in (job.get("id", ""), job.get("jobUrl", "")) or job.get("jobUrl", "").endswith(parts[1]):
                return job.get("title", ""), parts[0], job.get("descriptionPlain") or html_to_text(job.get("descriptionHtml", ""))
    if "myworkdayjobs.com" in host:
        tenant = host.split(".")[0]
        site = [p for p in parts if not re.fullmatch(r"[a-z]{2}-[A-Z]{2}", p)]
        if "job" in site:
            i = site.index("job")
            api = f"https://{host}/wday/cxs/{tenant}/{site[i - 1]}/job/{'/'.join(site[i + 1:])}"
            info = _get(api, True).get("jobPostingInfo", {})
            return info.get("title", ""), tenant, html_to_text(info.get("jobDescription", ""))

    page = _get(url)
    for blob in re.findall(r'<script[^>]+application/ld\+json[^>]*>(.*?)</script>', page, re.S | re.I):
        try:
            data = json.loads(blob.strip())
        except Exception:
            continue
        for d in (data if isinstance(data, list) else data.get("@graph", [data])):
            if isinstance(d, dict) and d.get("@type") == "JobPosting":
                org = d.get("hiringOrganization") or {}
                return d.get("title", ""), org.get("name", "") if isinstance(org, dict) else "", html_to_text(html.unescape(d.get("description", "")))
    m = re.search(r"<title>(.*?)</title>", page, re.S | re.I)
    return (html.unescape(m.group(1)).strip() if m else ""), host.replace("www.", "").split(".")[0], html_to_text(page)


# ───────────────────────────── JD keyword extraction ─────────────────────────────

REQ_HEAD = re.compile(r"requirement|qualification|must|what you|you have|you bring|you'll need|you will need|"
                      r"skills|experience|looking for|ideal|responsibilit|what you'll do|the role|about the role", re.I)
PREF_HEAD = re.compile(r"prefer|nice to have|bonus|plus|desired", re.I)
ZERO_HEAD = re.compile(r"benefit|perk|about us|about the company|who we are|compensation|salary|pay range|"
                       r"equal opportunity|eeo|accommodation|privacy|disclaimer|pay transparency|our values", re.I)


def jd_keywords(jd):
    """Return OrderedDict term → weight (requirements ×2, preferred ×1, benefits/EEO ×0)."""
    vocab = {t for terms in SKILL_TAXONOMY.values() for t in terms} | set(EXTRA_TERMS)
    vocab -= DROP_TERMS
    zone, weights, display = 1.0, {}, {}
    for line in jd.splitlines():
        s = norm(line)
        if not s:
            continue
        is_head = line.lstrip().startswith("#") or (not BULLET_RE.match(line) and len(s) <= 70 and (s.endswith(":") or (s[:1].isupper() and not re.search(r"[.!?]$", s) and len(s.split()) <= 8)))
        if is_head:
            if ZERO_HEAD.search(s):
                zone = 0.0
            elif PREF_HEAD.search(s):
                zone = 1.0
            elif REQ_HEAD.search(s):
                zone = 2.0
            elif zone == 0.0:
                zone = 1.0
        if zone == 0.0:
            continue
        found = set()
        for t in vocab:
            if has_term(s, t):
                found.add(t)
        letters = re.sub(r"[^A-Za-z]", "", s)
        shouting = len(s.split()) > 3 and letters and sum(c.isupper() for c in letters) / len(letters) > 0.6
        if re.search(r"(?:,\s*|\band\s+|\bor\s+)Go\b(?!-)|\bGo\s*(?:,|\band\b|\bor\b)", s):
            found.add("golang")
        for tok in ([] if shouting else re.findall(r"(?<![\w.])[A-Za-z.][A-Za-z0-9+#./&-]*[A-Za-z0-9+#]", s)):
            core = tok.rstrip(".")
            techy = (re.search(r"[a-z][A-Z]", core) or re.search(r"\d", core) and re.search(r"[A-Za-z]", core)
                     or re.search(r"[+#]|\.\w", core) or (core.isupper() and 2 <= len(core) <= 6))
            junk = (re.fullmatch(r"(?i)e\.g|i\.e|etc|u\.s|vs|\d+[k+]?|\d+(?:st|nd|rd|th)", core) or "@" in core
                    or re.search(r"(?i)www|\.(com|io|org|net|ai|co)$|/", core) and "ci/cd" not in core.lower())
            if techy and not junk and core.upper() not in ALLCAPS_STOP and len(core) <= 30:
                found.add(core)
        for t in found:
            key = t if (t.isupper() and len(t) <= 6 and t.lower() not in vocab and t.lower() not in _ALIAS_INDEX) else t.lower()
            canon = next((k for k in weights if key.lower() in {v.lower() for v in variants(k)}), None) or key
            weights[canon] = min(weights.get(canon, 0) + zone, 6.0)
            if canon not in display:
                hit = next((m.group(0) for v in variants(t) for m in [term_regex(v).search(s)] if m), t)
                display[canon] = "Go" if canon == "golang" and not re.search(r"(?i)golang", s) else hit
    # drop terms subsumed by a longer matched phrase with equal weight (e.g. "kernel" inside "linux kernel")
    terms = OrderedDict(sorted(weights.items(), key=lambda kv: (-kv[1], kv[0])))
    return terms, display


# ───────────────────────────── source corpus & support check ─────────────────────────────

class Corpus:
    def __init__(self, files):
        self.files = files                                   # [(name, text)]
        self.norm_all = " \n ".join(norm(" ".join(t.splitlines())) for _, t in files)
        self.norm_lines = [norm(l) for _, t in files for l in t.splitlines()]
        self.sentences = []                                  # (name, lineno, sentence)
        for name, text in files:
            for i, line in enumerate(text.splitlines(), 1):
                for sent in re.split(r"(?<=[.!?;])\s+|\s+[·|]\s+", norm(line)):
                    if sent:
                        self.sentences.append((name, i, sent))

    def contains_verbatim(self, s):
        n = norm(s)
        return bool(n) and n in self.norm_all

    def support(self, term):
        """First non-negated sentence that states the term, else None. Second value: True if only negated hits."""
        negated = False
        cs = re.search(r"[A-Z]", term) and term.lower() not in _ALIAS_INDEX
        rx = re.compile(r"(?<![A-Za-z0-9])" + re.escape(term) + r"(?![A-Za-z0-9+#])") if cs else None
        short = len(re.sub(r"[^A-Za-z]", "", term)) <= 3
        langs = [t for t in SKILL_TAXONOMY.get("Programming Languages", []) if t.lower() != term.lower() and len(t) > 2]
        for name, i, sent in self.sentences:
            if (rx.search(sent) if rx else has_term(sent, term)):
                if short and not any(has_term(sent, l) for l in langs):
                    continue
                if NEGATION.search(sent) or "?" in sent:
                    negated = True
                    continue
                return (name, i, sent), False
        return None, negated


# ───────────────────────────── resume model ─────────────────────────────

def section_kind(title):
    t = norm(title).lower()
    for kind, rx in SECTION_KINDS:
        if re.search(rx, t):
            return kind
    return "other"


SKILL_LINE = re.compile(r"^(\s*(?:[-*+•]\s+)?)(\*\*|__)?([^:*]{2,60}?)(?::\s*(?:\*\*|__)|(?:\*\*|__)\s*:|:)\s+(.+)$")


def parse_skill_line(line):
    m = SKILL_LINE.match(line)
    if not m:
        return None
    items = [i.strip() for i in re.split(r"\s*[,;·]\s*", m.group(4)) if i.strip()]
    if len(items) < 2 and norm(m.group(3)) != ADDED_SKILLS_LABEL:
        return None
    sep = ";" if ";" in m.group(4) else ("·" if "·" in m.group(4) else ",")
    return {"prefix": m.group(1), "label": m.group(3).strip(), "items": items, "sep": sep, "bold": bool(m.group(2))}


def parse_resume(md):
    """Header lines, then sections: {title, kind, parts}. parts: ('fixed', line) | ('group', style, [items]) | ('skill', dict)."""
    lines = md.splitlines()
    header, sections, cur, fence = [], [], None, False
    for line in lines:
        s = line.rstrip()
        if s.lstrip().startswith(("```", "~~~")):
            fence = not fence
        h = None if fence or s.lstrip().startswith(("```", "~~~")) else re.match(r"^(#{1,2})\s+(.*)$", s)
        if h and len(h.group(1)) == 1 and not header and not sections:
            header.append(s)          # "# Name" title line
            continue
        if h:
            cur = {"title": s, "kind": section_kind(h.group(2)), "body": []}
            sections.append(cur)
            continue
        (cur["body"] if cur else header).append(s)

    for sec in sections:
        body, parts = sec["body"], []
        has_bullets = any(BULLET_RE.match(l) for l in body)
        para = []

        def flush_para():
            if para:
                text = " ".join(x.strip() for x in para)
                if parts and parts[-1][0] == "group" and parts[-1][1] == "para":
                    parts[-1][2].append(text)
                else:
                    parts.append(["group", "para", [text]])
                para.clear()

        fence = False
        for l in body:
            s = l.strip()
            if s.startswith(("```", "~~~")) or fence or re.match(r"^( {4}|\t)\S", l):
                if s.startswith(("```", "~~~")):
                    fence = not fence
                flush_para()
                parts.append(["fixed", l])
                continue
            if sec["kind"] == "skills":
                sk = parse_skill_line(l)
                if sk:
                    flush_para()
                    parts.append(["skill", sk])
                    continue
            if not s:
                flush_para()
                continue
            if BULLET_RE.match(l) and sec["kind"] not in ("summary", "education"):
                flush_para()
                item = BULLET_RE.sub("", l).strip()
                if parts and parts[-1][0] == "group" and parts[-1][1] == "bullet":
                    parts[-1][2].append(item)
                else:
                    parts.append(["group", "bullet", [item]])
                continue
            is_sub = s.startswith("###") or re.fullmatch(r"(\*\*|__).+(\*\*|__)", s) or re.match(r"^\*\*[^*]+\*\*\s+[—–-]", s)
            if has_bullets or is_sub or sec["kind"] in ("summary", "education", "skills") or DATE_HINT.search(s) and len(s) < 140:
                flush_para()
                parts.append(["fixed", l])
            else:
                para.append(l)
        flush_para()
        sec["parts"] = parts
    return header, sections


# ───────────────────────────── tailoring ─────────────────────────────

def score_text(text, kw):
    return sum(w for t, w in kw.items() if has_term(text, t)) + (0.1 if re.search(r"\d", text) else 0)


NOT_SKILLS = re.compile(r"^(computer science|mathematics|math|engineering|physics|statistics|economics|bachelor'?s?|"
                        r"master'?s?|degree|phd|bs|ms|ba|related field|technical discipline)$", re.I)


def skill_shaped(term, ai_terms=()):
    """A term may go in Skills only if it names a skill/tool, not a degree field or a soft phrase."""
    if NOT_SKILLS.match(term.strip()):
        return False
    if term in ai_terms:   # model-found phrase: must look like a tool/technology, not prose
        return bool(re.search(r"[A-Z]|\d|[+#./]", term)) and len(term.split()) <= 3
    return True


def tailor(header, sections, kw, display, corpus, evidence_files, opts, log, reqs=()):
    resume_text = "\n".join(header + [l for s in sections for l in s["body"]])
    rk = dict(kw)                                    # ranking weights = JD keywords + related-term boosts
    # keywords: present / addable / gap
    log["present"], log["added"], log["gaps"], log["negated"] = [], [], [], []
    for t, w in kw.items():
        if has_term(resume_text, t):
            log["present"].append(t)
            jd_form = display.get(t, t)
            literal = term_regex(jd_form).search(resume_text)
            if not literal and skill_shaped(jd_form, getattr(opts, "ai_terms", ())) and not NOT_SKILLS.match(jd_form):
                # same claim, the posting's spelling: keyword search does not expand abbreviations
                other = next((v for v in variants(t) if v.lower() != jd_form.lower() and has_term(resume_text, v)), None)
                if other:
                    log["added"].append((jd_form, w, ("your resume", 0, f"you wrote '{other}'; the posting spells it '{jd_form}'")))
                    log.setdefault("spelled", []).append((jd_form, other))
            continue
        src, negated = corpus.support(display.get(t, t))
        if src and not skill_shaped(display.get(t, t), getattr(opts, "ai_terms", ())):
            src = None
        if src:
            log["added"].append((display.get(t, t), w, src))
        elif negated:
            log["negated"].append(display.get(t, t))
        else:
            log["gaps"].append((display.get(t, t), w))

    # correlation: closest real line for each gap (never written in; only promoted + reported)
    log["correlated"], log["uncorrelated"] = [], []
    for g, w in log["gaps"]:
        related = ADJACENT.get(g.lower()) or next((v for k, v in ADJACENT.items() if k in {x.lower() for x in variants(g)}), None)
        best = None
        if related:
            for name, i, sent in corpus.sentences:
                if NEGATION.search(sent) or "?" in sent or META.search(sent) or len(sent) < 30:
                    continue
                hits = [r for r in related if has_term(sent, r)]
                rank = len(hits) - (1.5 if parse_skill_line(sent) else 0)   # a real bullet beats a skills list
                if hits and (best is None or rank > best[4]):
                    best = (name, i, sent, hits, rank)
        if best:
            log["correlated"].append((g, w, best))
            for r in best[3]:
                rk[r] = max(rk.get(r, 0), w * 0.5)   # promote related bullets; coverage ignores these
        else:
            log["uncorrelated"].append((g, w))


    for sec in sections:
        if sec["kind"] in ("summary", "education") or norm(sec["title"]) == norm(DL_HEADING):
            continue
        new_parts = []
        for p in sec["parts"]:
            if p[0] == "group":
                items = p[2]
                pinned = [i for i, it in enumerate(items) if re.match(r"^(\*\*)?(technolog|tools|stack|environment|tech)[^:]{0,20}:", it, re.I)]
                ranked = sorted((i for i in range(len(items)) if i not in pinned), key=lambda i: (-score_text(items[i], rk), i)) + pinned
                if opts.max_bullets and len(ranked) > opts.max_bullets:
                    keep = ranked[:opts.max_bullets]
                    for i in ranked[opts.max_bullets:]:
                        log["trimmed"].append(items[i])
                    ranked = keep
                if ranked and ranked[0] != 0:
                    log["reordered"].append((sec["title"], items[ranked[0]]))
                new_parts.append(["group", p[1], [items[i] for i in ranked]])
            elif p[0] == "skill":
                sk = dict(p[1])
                sk["items"] = sorted(sk["items"], key=lambda it: (-score_text(it, rk), sk["items"].index(it)))
                new_parts.append(["skill", sk])
            else:
                new_parts.append(p)
        # skills lines: strongest line first, non-skill lines keep position
        if sec["kind"] == "skills":
            idx = [i for i, p in enumerate(new_parts) if p[0] == "skill"]
            ordered = sorted((new_parts[i] for i in idx), key=lambda p: -sum(score_text(it, rk) for it in p[1]["items"]))
            for i, p in zip(idx, ordered):
                new_parts[i] = p
        sec["parts"] = new_parts

    if log["added"]:
        skills = next((s for s in sections if s["kind"] == "skills"), None)
        if not skills:
            skills = {"title": "## Skills", "kind": "skills", "parts": [], "body": []}
            edu = next((i for i, s in enumerate(sections) if s["kind"] == "education"), len(sections))
            sections.insert(edu, skills)
        existing = next((p[1] for p in skills["parts"] if p[0] == "skill"), None)
        skills["parts"].append(["skill", {"prefix": existing["prefix"] if existing else "",
                                          "label": ADDED_SKILLS_LABEL, "items": [a[0] for a in log["added"]],
                                          "sep": existing["sep"] if existing else ",",
                                          "bold": existing["bold"] if existing else False, "added": True}])

    # verbatim evidence bullets
    log["evidence"] = []
    if opts.max_evidence and evidence_files:
        have = [set(re.findall(r"[a-z0-9]+", norm(l).lower())) for l in resume_text.splitlines() if len(l) > 30]
        pool = []
        for name, text in evidence_files:
            for i, line in enumerate(text.splitlines(), 1):
                if not BULLET_RE.match(line):
                    continue
                s_ = norm(line)
                if not (40 <= len(s_) <= 300) or s_.endswith(":") or "?" in s_ or re.search(
                        r"\b(todo|tbd|never mention|do not|don't|confidential|private|internal only|draft)\b", s_, re.I):
                    continue
                if any(re.search(r"\b" + re.escape(x) + r"\b", s_, re.I) for x in FORBIDDEN_LEAKS):
                    continue
                if META.search(s_) or NEGATION.search(s_) or not s_[0].isupper():
                    continue
                toks = set(re.findall(r"[a-z0-9]+", s_.lower()))
                if any(len(toks & h) / max(1, len(toks | h)) > 0.5 for h in have):
                    continue
                pool.append((name, i, s_, toks))
        chosen, seen = [], []

        def take(item, why):
            if any(len(item[3] & t) / max(1, len(item[3] | t)) > 0.5 for t in seen):
                return False
            seen.append(item[3])
            chosen.append((score_text(item[2], kw), item[0], item[1], item[2], why))
            return True

        # 1) targeted: what an AI screener would mark partial / gap / skills-list-only on a qualification
        cur_md = render(header, sections)
        weak = [r for r in screen(cur_md, [q for q in reqs if q["tier"] in ("basic", "preferred")], kw, getattr(opts, "ai_terms", ()))[0]
                if r["status"] != "meets" or r["note"].startswith("only in the Skills")]
        weak.sort(key=lambda r: r["tier"] != "basic")
        for r in weak:
            words = _content_words(r["text"])
            best, best_sc = None, 0
            for item in pool:
                hits = [t for t in r["terms"] if has_term(item[2], t)]
                overlap = len(words & _content_words(item[2])) / max(1, len(words))
                sc = len(hits) * 2 + overlap * 3
                if hits and overlap >= 0.12 and sc > best_sc:
                    best, best_sc = item, sc
            if best and len(chosen) < opts.max_evidence and take(best, r["text"][:80]):
                log.setdefault("targeted", []).append((r["text"], best[0], best[1], best[2]))
        # 2) fill: strongest keyword lines
        for item in sorted(pool, key=lambda it: -score_text(it[2], kw)):
            if len(chosen) >= opts.max_evidence:
                break
            if sum(1 for t in kw if has_term(item[2], t)) >= 2 and score_text(item[2], kw) >= opts.min_evidence_score:
                take(item, "keywords")
        log["evidence"] = [(c[0], c[1], c[2], c[3]) for c in chosen]
        if log["evidence"]:
            sec = {"title": "## " + ADDED_SECTION, "kind": "added", "body": [],
                   "parts": [["group", "bullet", [e[3] for e in log["evidence"]]]]}
            edu = next((i for i, s in enumerate(sections) if s["kind"] == "education"), len(sections))
            sections.insert(edu, sec)
    return header, sections


# ───────────────────────────── live download counts ─────────────────────────────
# The only lines truthfit writes that are not in your files. Every number comes from a public registry
# fetched at run time, and the URL and raw totals behind it go in downloads_receipt.json next to the output.

# numbers are patched in place, so bold, backticks and inline " - " bullets around them survive
DL_SUMMARY = re.compile(r"[\d,]+\+?(?=(?:\*\*|__)? lifetime downloads(?:\*\*|__)? across \d+ published packages)", re.I)
DL_REGISTRY = re.compile(r"\b(PyPI|npm) \([\d,]+\+? installs\)(:?(?:\*\*|__)?:?)(.*?)(?=\s+-\s+[*_]|$)", re.I)
DL_APPENDIX = re.compile(r"\bpackage telemetry\b|package metrics|telemetry output", re.I)
DL_HEADING = "## Verified Package Telemetry"


def _get_retry(url, tries=4):
    for i in range(tries):
        try:
            return _get(url, as_json=True)
        except urllib.error.HTTPError as e:
            if e.code != 429 or i == tries - 1:
                raise
            import time
            time.sleep(3 * (i + 1))


def fetch_downloads(cfg):
    """Live counts for {"pypi": [...], "npm": [...]}. Any failed fetch raises — a stale number never reaches a resume."""
    today = datetime.date.today().isoformat()
    pkgs = []
    for name in cfg.get("pypi", []):
        rel = _get_retry(f"https://pypi.org/pypi/{name}/json")["releases"]
        first = min(f["upload_time_iso_8601"][:10] for files in rel.values() for f in files)
        url = f"https://pypistats.org/api/packages/{name}/overall"
        rows = sorted((r for r in _get_retry(url)["data"] if r["category"] == "with_mirrors"), key=lambda r: r["date"])
        pkgs.append({"registry": "PyPI", "package": name, "first_release": first, "source": url,
                     "lifetime": sum(r["downloads"] for r in rows), "last_30_days": sum(r["downloads"] for r in rows[-30:]),
                     # pypistats keeps 180 days; once the first release is older, the sum is a floor
                     "floor": not rows or rows[0]["date"] > first,
                     "verify": f"curl -s {url} | jq '[.data[] | select(.category==\"with_mirrors\") | .downloads] | add'"})
    for name in cfg.get("npm", []):
        first = _get_retry(f"https://registry.npmjs.org/{name}")["time"]["created"][:10]
        url = f"https://api.npmjs.org/downloads/range/{first}:{today}/{name}"
        days = _get_retry(url)["downloads"]
        pkgs.append({"registry": "npm", "package": name, "first_release": first, "source": url,
                     "lifetime": sum(d["downloads"] for d in days), "last_30_days": sum(d["downloads"] for d in days[-30:]),
                     "floor": False, "verify": f"curl -s {url} | jq '[.downloads[].downloads] | add'"})
    return {"fetched": datetime.datetime.now().isoformat(timespec="seconds"), "date": today, "packages": pkgs}


def _count(pkgs):
    return f"{sum(p['lifetime'] for p in pkgs):,}" + ("+" if any(p["floor"] for p in pkgs) else "")


def _k(n):
    return f"{n / 1000:.1f}k" if n >= 1000 else str(n)


def apply_downloads(md, stats, descriptions=None):
    """Swap the resume's download lines for live counts and rebuild the telemetry appendix.
    Returns (new_md, [(old line or None, new line)])."""
    pkgs = stats["packages"]
    by = {r: sorted((p for p in pkgs if p["registry"] == r), key=lambda p: -p["lifetime"]) for r in ("PyPI", "npm")}

    def registry(m):
        r = "PyPI" if m.group(1).lower() == "pypi" else "npm"
        seg = m.group(3)
        for p in by[r]:
            seg = re.sub(r"(?<![\w-])(`?" + re.escape(p["package"]) + r"`?)(?: \([\d.,]+k?\))?(?![\w-])",
                         lambda x: f"{x.group(1)} ({_k(p['lifetime'])})", seg)
        return f"{m.group(1)} ({_count(by[r])} installs){m.group(2)}{seg}"

    changes, out = [], []
    for line in md.splitlines():
        if DL_APPENDIX.search(line):
            break                                        # the old appendix is replaced whole, below
        new = DL_REGISTRY.sub(registry, DL_SUMMARY.sub(_count(pkgs), line))
        if new != line:
            changes.append((line, new))
            line = new
        out.append(line)
    app = [DL_HEADING, "",
           f"Live registry counts as of {stats['date']}. PyPI counts are pypistats.org daily totals including mirrors; "
           "npm counts are api.npmjs.org daily totals since first publish.", ""]
    for r in ("PyPI", "npm"):
        for p in by[r]:
            desc = (descriptions or {}).get(p["package"])
            app.append(f"- {p['package']} ({r}): {p['lifetime']:,}{'+' if p['floor'] else ''} lifetime · "
                       f"{p['last_30_days']:,} in the last 30 days · first release {p['first_release']}" + (f" — {desc}" if desc else ""))
    app += ["", f"Totals: PyPI {_count(by['PyPI'])} · npm {_count(by['npm'])} · all {len(pkgs)} packages {_count(pkgs)}.", "",
            "Check any count yourself, nothing to install. PyPI: add up the with_mirrors rows. npm: add up the daily downloads.", ""]
    # plain URLs: code spans break apart in a PDF text layer; the exact jq commands are in the receipt
    app += [f"- {p['package']}: {p['source']}" for r in ("PyPI", "npm") for p in by[r]]
    changes += [(None, l) for l in app if l.strip()]
    return "\n".join(out).rstrip() + "\n\n" + "\n".join(app) + "\n", changes


TARGET_PREFIX = "Target role: "


def render(header, sections, target=None):
    out = []
    for i, l in enumerate(header):
        if l.strip():
            out += [l.rstrip(), ""]
            if target and i == 0:
                out += [TARGET_PREFIX + target, ""]
    for sec in sections:
        out += [sec["title"].rstrip(), ""]
        for p in sec["parts"]:
            if p[0] == "fixed":
                out += [p[1].rstrip(), ""]
            elif p[0] == "skill":
                sk = p[1]
                label = f"**{sk['label']}:**" if sk["bold"] else f"{sk['label']}:"
                out += [f"{sk['prefix']}{label} {(sk['sep'] + ' ').join(sk['items'])}", ""]
            elif p[1] == "bullet":
                out += [f"- {it}" for it in p[2]] + [""]
            else:
                for it in p[2]:
                    out += [it, ""]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip() + "\n"


# ───────────────────────────── the verifier (owns the verdict) ─────────────────────────────

def verify(md, base_md, corpus, identity, rewrites=None, vocab=(), target=None):
    """Every line traced to a source, or the run fails. Returns list of failures."""
    fails = []
    base_headings, f = set(), False
    for l in base_md.splitlines():
        if l.strip().startswith(("```", "~~~")):
            f = not f
        elif not f and re.match(r"^ {0,3}#{1,6}\s", l):
            base_headings.add(norm(l).lower())
    base_skills = [parse_skill_line(l) for l in base_md.splitlines()]
    base_skills = [s for s in base_skills if s]
    in_skills, fence = False, False
    for n, line in enumerate(md.splitlines(), 1):
        s = line.strip()
        if s.startswith(("```", "~~~")):
            fence = not fence
            continue
        if not s:
            continue
        if not fence and re.match(r"^ {0,3}#{1,6}\s", line):
            h = norm(s).lower()
            in_skills = section_kind(h) == "skills"
            if h not in base_headings and h != ADDED_SECTION.lower():
                fails.append(f"line {n}: heading not in base resume: {s}")
            continue
        sk = parse_skill_line(line) if in_skills and not fence else None
        if sk:
            if norm(sk["label"]) == ADDED_SKILLS_LABEL:
                for it in sk["items"]:
                    src, _ = corpus.support(it) if not NOT_SKILLS.match(it.strip()) else (None, False)
                    if not src and not NOT_SKILLS.match(it.strip()) and any(
                            v.lower() != it.lower() and corpus.support(v)[0] for v in variants(it)):
                        src = "alias"
                    if not src:
                        fails.append(f"line {n}: added skill '{it}' has no non-negated source sentence")
                continue
            match = [b for b in base_skills if norm(b["label"]) == norm(sk["label"])
                     and sorted(map(norm, b["items"])) == sorted(map(norm, sk["items"]))]
            if not match:
                fails.append(f"line {n}: skills line is not a permutation of a base skills line: {s[:90]}")
            continue
        if target and norm(s) == norm(TARGET_PREFIX + target):
            continue
        if not corpus.contains_verbatim(s):
            orig = (rewrites or {}).get(norm(s))
            if orig and corpus.contains_verbatim(orig) and not rewrite_gate(orig, s, vocab):
                continue
            fails.append(f"line {n}: NOT VERBATIM in any source: {s[:110]}")
    low = md.lower()
    for m in INJECTION.finditer(md):
        fails.append(f"AI-directed text in output: '{m.group(0)}'")
    for word in FORBIDDEN_LEAKS:
        if re.search(r"\b" + re.escape(word) + r"\b", low):
            fails.append(f"CONFIDENTIAL NAME IN OUTPUT: '{word}'")
    if identity:
        if identity.get("email", "").lower() not in low:
            fails.append(f"contact: email {identity.get('email')} missing")
        if identity.get("phoneRaw") and identity["phoneRaw"] not in re.sub(r"\D", "", md):
            fails.append(f"contact: phone {identity.get('phoneFormatted')} missing")
    return fails


INJECTION = re.compile(r"ignore (all |any )?(previous|prior|above) (instructions|prompts)|you are (an? )?(ai|llm|language model)|"
                       r"(rank|rate|score|grade|mark) (this|the) (candidate|applicant|resume)|strong hire|"
                       r"(chatgpt|gpt|claude|gemini|ai|llm)[:,]? (please )?(recommend|select|shortlist|rank)|"
                       r"hidden instruction", re.I)


def hidden_text_findings(path, text):
    """White/tiny/invisible text and prompt-injection phrases. Recruiters treat these as cheating."""
    found = [f"prompt-injection phrase: '{m.group(0)}'" for m in INJECTION.finditer(text)]
    if path.lower().endswith(".docx"):
        import zipfile
        try:
            xml = zipfile.ZipFile(path).read("word/document.xml").decode("utf-8", "ignore")
        except Exception:
            xml = ""
        for run in re.findall(r"<w:r[ >].*?</w:r>", xml, re.S):
            t = "".join(re.findall(r"<w:t[^>]*>([^<]*)</w:t>", run)).strip()
            if not t:
                continue
            if re.search(r'<w:color w:val="(FFFFFF|FEFEFE|FDFDFD)"', run, re.I):
                found.append(f"white text: '{t[:60]}'")
            elif "<w:vanish/>" in run:
                found.append(f"hidden (vanish) text: '{t[:60]}'")
            else:
                m = re.search(r'<w:sz w:val="(\d+)"', run)
                if m and int(m.group(1)) < 10:   # half-points: < 5pt
                    found.append(f"microscopic {int(m.group(1)) / 2:g}pt text: '{t[:60]}'")
    return found


def docx_layout(path):
    """Word-file layout traps (ATSChecker 2026 study: columns 31%, tables 28%, header/footer contact 22%,
    images 19%, text boxes 17%, non-standard fonts 12% parse-failure rates — vendor data, directional)."""
    import zipfile
    out = []
    try:
        z = zipfile.ZipFile(path)
    except Exception:
        return out
    names = z.namelist()
    doc = z.read("word/document.xml").decode("utf-8", "ignore") if "word/document.xml" in names else ""
    if re.search(r'<w:cols [^>]*w:num="([2-9])"', doc):
        out.append(("MAJOR", "multi-column section layout — the #1 parse failure (31%)"))
    t = doc.count("<w:tbl>")
    if t:
        out.append(("MAJOR", f"{t} table(s) — parsers read tables row by row and merge cells (28% failure)"))
    if "w:txbxContent" in doc:
        out.append(("MAJOR", "text box(es) — content is often skipped or read out of order (17% failure)"))
    if re.search(r"<w:drawing>|<w:pict>", doc):
        out.append(("minor", "image/graphic in the body (19% failure; Workday: avoid images)"))
    for n in names:
        if re.match(r"word/(header|footer)\d*\.xml", n):
            hf = re.sub(r"<[^>]+>", " ", z.read(n).decode("utf-8", "ignore"))
            if re.search(r"[\w.+-]+@[\w-]+\.\w+|\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}", hf):
                out.append(("MAJOR", f"contact info inside {n.split('/')[-1]} — many ATSs drop headers/footers (22% failure)"))
    fonts = set(re.findall(r'w:ascii="([^"]+)"', doc))
    odd = fonts - {"Calibri", "Arial", "Helvetica", "Times New Roman", "Georgia", "Garamond", "Cambria", "Aptos",
                   "Verdana", "Tahoma", "Book Antiqua", "Palatino Linotype", "Segoe UI", "Lato", "Roboto", "Open Sans",
                   "Calibri Light", "Arial Narrow", "Courier New", "Consolas", "Liberation Sans", "Helvetica Neue"}
    if odd:
        out.append(("minor", f"non-standard font(s): {', '.join(sorted(odd))} (12% failure)"))
    return out


def coverage(text, kw):
    total = sum(kw.values()) or 1
    return round(100 * sum(w for t, w in kw.items() if has_term(text, t)) / total, 1)


# ───────────────────────────── AI-screener simulation ─────────────────────────────
# Greenhouse Talent Matching, Ashby AI-Assisted Review and Workday HiredScore do not count
# keywords: they take each qualification and judge it from evidence in the parsed resume
# (meets / gap / undecided). Basic qualifications decide A/B vs C/D (HiredScore).
# This section reproduces that shape deterministically, then runs a real model as the
# screener with every evidence quote it cites checked verbatim against the resume.

QUAL_HEAD = re.compile(r"requirement|qualification|must|you have|you bring|you'll need|you will need|looking for|"
                       r"ideal|exceptional candidates|demonstrated|who you are|what we're looking|minimum|basic", re.I)
DUTY_HEAD = re.compile(r"responsibilit|what you'll do|what you will do|accomplish|the role|day to day|you will|your impact", re.I)
STOP = set("""a an the and or of to in on for with without by at from as is are be been being this that these those
your you we our us their they it its into across over under within per via about more most least very strong
experience experienced ability able skills skill knowledge understanding working work works proficiency proficient
familiarity familiar years year plus preferred required including include includes such using use used etc
both other others any all some new hands-on deep high highly well good great excellent solid real world
""".split())


def jd_requirements(jd):
    """Each requirement line with its tier: basic (qualifications), preferred, duty."""
    tier, reqs = "duty", []
    for line in jd.splitlines():
        s = norm(line)
        if not s:
            continue
        is_head = line.lstrip().startswith("#") or (not BULLET_RE.match(line) and len(s) <= 70 and
                  (s.endswith(":") or (s[:1].isupper() and not re.search(r"[.!?]$", s) and len(s.split()) <= 8)))
        if is_head:
            tier = ("skip" if ZERO_HEAD.search(s) else "preferred" if PREF_HEAD.search(s) else
                    "basic" if QUAL_HEAD.search(s) else "duty" if DUTY_HEAD.search(s) else tier)
            continue
        if tier == "skip" or len(s) < 25 or not (BULLET_RE.match(line) or tier in ("basic", "preferred")):
            continue
        t = "preferred" if tier == "basic" and PREF_HEAD.search(s[:40]) else tier
        m = re.search(r"(\d+)\s*\+?\s*(?:-\s*\d+\s*)?(?:years|yrs)", s, re.I)
        reqs.append({"text": s, "tier": t, "years": int(m.group(1)) if m else None})
    return reqs


def _content_words(s):
    return {w for w in re.findall(r"[a-z][a-z0-9+#.-]{2,}", s.lower()) if w not in STOP}


def resume_lines(md):
    """(section_kind, line) for every content line of a rendered resume."""
    out, kind = [], "header"
    for line in md.splitlines():
        if re.match(r"^ {0,3}#{1,2}\s", line):
            kind = section_kind(line)
            continue
        if line.strip() and not line.strip().startswith("#"):
            out.append((kind, norm(line)))
    return out


def parse_experience(text):
    """
    Parses experience blocks and dates.
    Calculates raw tenure and software/systems engineering tenure.
    """
    roles = []
    
    # Known experience patterns in resumes
    # Looks for year ranges like 2021 to 2024, 2024 – 2025, Jan 2024 to Apr 2025, 2025 to Present
    date_pat = re.compile(
        r'(?:([A-Za-z]{3}\s+)?(\d{4}))\s*(?:to|–|-)\s*(Present|(?:[A-Za-z]{3}\s+)?\d{4})',
        re.IGNORECASE
    )
    
    lines = text.split("\n")
    current_role = None
    
    # Look for known headers or lines containing dates
    for idx, line in enumerate(lines):
        line_clean = line.strip()
        m = date_pat.search(line_clean)
        if m:
            start_str = m.group(2)
            end_str = m.group(3)
            
            start_year = int(start_str)
            if "present" in end_str.lower():
                end_year = datetime.datetime.now().year + (datetime.datetime.now().month / 12.0)
            else:
                m_end_yr = re.search(r'\d{4}', end_str)
                end_year = int(m_end_yr.group(0)) if m_end_yr else start_year + 1
            
            duration_yrs = max(0.2, round(end_year - start_year, 1))
            
            # Find the title/company line above or around it
            title_line = lines[idx-1].strip() if idx > 0 and len(lines[idx-1].strip()) > 3 else line_clean
            # Clean up ### or markdown
            title_line = re.sub(r'^[#*\s-]+', '', title_line)
            
            # Classification
            is_swe = any(w in title_line.lower() or w in line_clean.lower() for w in ["engineer", "architect", "developer", "founder", "systems", "eval", "red team"])
            is_non_tech = any(w in title_line.lower() for w in ["claims", "insurance", "evaluator", "clerk", "retail", "waiter"])
            if is_non_tech:
                is_swe = False
            
            roles.append({
                "header": title_line,
                "date_str": m.group(0),
                "duration_years": duration_yrs,
                "is_technical_swe": is_swe
            })
            
    total_tenure = sum(r["duration_years"] for r in roles)
    swe_tenure = sum(r["duration_years"] for r in roles if r["is_technical_swe"])
    
    return roles, round(total_tenure, 1), round(swe_tenure, 1)


def tenure_years(md):
    try:
        _, total, swe = parse_experience(md)
        return total, swe
    except Exception:
        return None, None


def screen(md, reqs, kw, ai_terms=()):
    """Deterministic screener: meets / partial / gap per requirement + HiredScore-style grade.
    Model-found prose phrases ("adversarial thinking") are not literal requirements, so they are left out here."""
    orig_case = {t.lower(): t for t in ai_terms}
    kw = {k: v for k, v in kw.items() if k not in orig_case or skill_shaped(orig_case[k], ai_terms)}
    lines = resume_lines(md)
    total, tech = tenure_years(md)
    results = []
    for r in reqs:
        terms = [t for t in kw if has_term(r["text"], t)]
        words = _content_words(r["text"])
        best, best_sc = None, 0.0
        for kind, l in lines:
            if kind == "header":
                continue
            hit_t = [t for t in terms if has_term(l, t)]
            overlap = len(words & _content_words(l)) / max(1, len(words))
            sc = len(hit_t) * 2 + overlap * 3 + (0.5 if kind in ("experience", "projects", "other", "added") else 0)
            if sc > best_sc:
                best, best_sc = (kind, l, hit_t, overlap), sc
        matched = set()
        for _, l in lines:
            matched |= {t for t in terms if has_term(l, t)}
        frac = len(matched) / len(terms) if terms else (best[3] if best else 0)
        status = "meets" if frac >= 0.6 else "partial" if frac > 0.2 or (best and best[3] >= 0.3) else "gap"
        note = ""
        in_work = {t for k, l in lines if k not in ("skills", "header") for t in terms if has_term(l, t)}
        if status == "meets" and terms and not in_work and not (best and best[0] != "skills" and best[3] >= 0.4):
            status = "partial"
            note = "only in the Skills list — AI screeners mark listed-only skills partial; it needs to appear inside a dated job"
        if r["years"]:
            have = tech if tech is not None else total
            if have is not None and have < r["years"]:
                status = "partial" if status == "meets" else status
                note = f"posting asks {r['years']}+ yrs; parser reads ~{have} technical from your dates"
        results.append({**r, "status": status, "terms": terms, "missing": [t for t in terms if t not in matched],
                        "evidence": best[1] if best and best_sc > 1 else "", "note": note})
    basic = [x for x in results if x["tier"] == "basic"]
    pref = [x for x in results if x["tier"] == "preferred"]
    if basic:
        met = sum(x["status"] == "meets" for x in basic)
        if met == len(basic):
            grade = "A" if not pref or sum(x["status"] == "meets" for x in pref) >= len(pref) / 2 else "B"
        else:
            grade = "C" if met + 0.5 * sum(x["status"] == "partial" for x in basic) >= len(basic) / 2 else "D"
    else:
        grade = "?"
    return results, grade


def ai_screen(md, results, model="sonnet"):
    """A real model plays the ATS screener. Every quote it cites must be verbatim in the resume or it is rejected."""
    if not shutil.which("claude"):
        return None, "claude CLI not found"
    crit = [{"id": i, "tier": r["tier"], "criterion": r["text"]} for i, r in enumerate(results) if r["tier"] != "duty"] or \
           [{"id": i, "tier": r["tier"], "criterion": r["text"]} for i, r in enumerate(results)]
    prompt = ("You are an applicant-tracking-system AI screener, like Workday HiredScore, Greenhouse Talent Matching or Ashby "
              "AI-Assisted Application Review. Judge ONLY from the resume text. For each criterion answer meets, partial, gap, "
              "or undecided. For meets or partial, quote the exact resume text (copied character for character, max 200 chars) "
              "that proves it. Be strict: adjacent experience is not the same skill. Then grade: A (all basic + most preferred), "
              "B (all basic), C (some basic), D (few or no basic).\n"
              "Return ONLY JSON: {\"criteria\":[{\"id\":0,\"status\":\"meets\",\"quote\":\"...\",\"reason\":\"<15 words\"}],"
              "\"grade\":\"B\",\"summary\":\"<40 words\"}\n\n"
              "CRITERIA:\n" + json.dumps(crit, ensure_ascii=False) + "\n\nRESUME:\n<<<\n" + md + "\n>>>")
    try:
        r = subprocess.run(CLAUDE_CMD + ["--model", model],
                           input=prompt, capture_output=True, text=True, timeout=300, cwd=tempfile.gettempdir())
        data = first_json(json.loads(r.stdout).get("result", ""))
    except Exception as e:
        return None, f"AI screen failed: {e}"
    flat = norm(" ".join(md.splitlines()))
    for c in data.get("criteria", []):
        q = norm(c.get("quote", "") or "").rstrip(".…")
        c["verified"] = (not q) or (q in flat) or all(part.strip() in flat for part in re.split(r"\.\.\.|…", q) if part.strip())
    return data, None


def lint(md, base_path, kw, display):
    """Parser-quality checks, from Textkernel's (Sovren's) published resume-quality codes."""
    issues = []
    lines = md.splitlines()
    top = "\n".join(lines[:12])
    emails = re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", top)
    phones = re.findall(r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}", top)
    if not emails or not phones:
        issues.append(("441/211/212", "FATAL", "email and phone must both be at the top of the resume"))
    if len(set(emails)) > 1 or len(set(re.sub(r"\D", "", p) for p in phones)) > 1:
        issues.append(("132/133", "minor", "more than one email/phone at the top — keep one of each"))
    heads = [(norm(l), section_kind(l)) for l in lines if re.match(r"^ {0,3}#{2}\s", l)]
    kinds = [k for _, k in heads]
    if "experience" not in kinds:
        issues.append(("413", "FATAL", "no section a parser recognises as WORK HISTORY (use 'Experience' / 'Professional Experience')"))
    if "education" not in kinds:
        issues.append(("414", "FATAL", "no EDUCATION section"))
    for h, k in heads:
        if not KNOWN_HEADINGS.match(h) and h != ADDED_SECTION:
            issues.append(("417/325", "minor", f"non-standard heading '{h}' — parsers may not classify it; content may be lumped into the wrong section"))
    sizes, cur = {}, None
    for l in lines:
        if re.match(r"^ {0,3}#{2}\s", l):
            cur = norm(l)
            sizes[cur] = 0
        elif cur:
            sizes[cur] += len(l)
    core = sum(v for h, v in sizes.items() if section_kind(h) in ("experience", "education"))
    for h, v in sizes.items():
        if section_kind(h) not in ("experience", "education") and v > core:
            issues.append(("303", "MAJOR", f"'{h}' is longer than Experience + Education combined — parsers then mis-assign sections"))
    in_exp, years_seen = False, []
    for i, l in enumerate(lines):
        if re.match(r"^ {0,3}#{2}\s", l):
            in_exp = section_kind(l) == "experience"
            continue
        if in_exp and re.match(r"^ {0,3}#{3}\s", l):
            nxt = " ".join(lines[i:i + 3])
            rng = re.search(r"((?:[A-Z][a-z]{2,8}\.?\s+)?(?:19|20)\d{2})\s*(?:-|–|to)\s*((?:[A-Z][a-z]{2,8}\.?\s+)?(?:(?:19|20)\d{2})|Present|Current)", nxt, re.I)
            if not rng:
                issues.append(("224/225", "MAJOR", f"job '{norm(l)}' has no start–end date range a parser can read"))
            else:
                if not re.match(r"[A-Z]", rng.group(1)):
                    issues.append(("dates", "minor", f"'{norm(l)}': year-only dates; 'Mon YYYY – Mon YYYY' gives parsers exact months"))
                years_seen += [int(y) for y in re.findall(r"(?:19|20)\d{2}", rng.group(0))] + \
                              ([datetime.date.today().year] if re.search(r"present|current", rng.group(0), re.I) else [])
    if years_seen and max(years_seen) < datetime.date.today().year - 1:
        issues.append(("226", "MAJOR", "no job within the past year"))
    if base_path.lower().endswith(".pdf"):
        issues.append(("300", "MAJOR", "base was a PDF; Textkernel flags PDF itself as a major issue — upload the .docx where allowed"))
    rl = resume_lines(md)
    only_skills = [display.get(t, t) for t in kw
                   if any(k == "skills" and has_term(l, t) for k, l in rl) and not any(k != "skills" and has_term(l, t) for k, l in rl)]
    if only_skills:
        issues.append(("112", "info", "JD skills that appear ONLY in your Skills list, not inside a dated job (parsers compute "
                                      "months-of-experience per skill from the jobs it appears in): " + ", ".join(only_skills[:20])))
    words = len(re.findall(r"\w+", md))
    if words > 1300:
        issues.append(("length", "info", f"{words} words (~{words // 500 + 1} pages); long documents risk truncation (code 408) and skimming"))
    return issues


# ───────────────────────────── AI rewrite (model proposes, gates decide) ─────────────────────────────
# The model may rephrase a bullet so it lands harder for this job. It may not add anything.
# Gate 1 (deterministic): no new numbers, names, tools, skills, scope words or AI-speak.
# Gate 2 (a second model call, a skeptic): rejects any rewrite that claims more than the original.
# Gate 3 (the verifier, at the end): re-runs gate 1 on every rewritten line in the finished file.
# Anything rejected falls back to the original words.

SCOPE_WORDS = re.compile(r"\b(led|lead|leads|leading|managed|manage|manages|managing|owned|own|owns|owning|directed|headed|"
                         r"spearhead\w*|oversaw|oversee\w*|supervis\w*|mentor\w*|team of|architect\w*|founded|pioneer\w*|"
                         r"first|only|sole|solely|world-class|expert|enterprise-grade|production-grade|at scale|"
                         r"million\w*|billion\w*|thousand\w*|dozens|hundreds)\b", re.I)
AI_SPEAK = re.compile(r"\b(leverag\w*|synerg\w*|passionate|utiliz\w*|cutting-edge|robust|seamless\w*|innovative|dynamic|"
                      r"results-driven|best-in-class|state-of-the-art|delv\w*|tapestry|showcas\w*|empower\w*|"
                      r"streamlin\w*|transformative|holistic|game-chang\w*|unlock\w*|elevat\w*)\b", re.I)


NUM_WORDS = re.compile(r"\b(zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|"
                       r"sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|"
                       r"thousand|million|billion|trillion|single|double|twice|triple|dozen|half|quarter|percent|x)\b", re.I)


def _nums(s):
    """Every quantity, in digits or words: 'eight' and 'eighty' are different claims."""
    return {n.replace(",", "").rstrip(".") for n in re.findall(r"\d[\d,.]*", s)} | {w.lower() for w in NUM_WORDS.findall(s)}


def _named(s):
    """Tokens that carry a specific claim: capitalised mid-sentence, digits, symbols."""
    out = set()
    for m in re.finditer(r"[A-Za-z][A-Za-z0-9+#./_-]*", s):
        t = m.group(0)
        sentence_start = not s[:m.start()].strip() or re.search(r"[.!?:;]\s*$", s[:m.start()])
        if (t[0].isupper() and not sentence_start) or re.search(r"[0-9+#_]|[a-z][A-Z]|\.\w", t):
            out.add(t.lower().rstrip("."))
    return out


def rewrite_gate(orig, new, vocab):
    """Return '' if `new` claims nothing beyond `orig`, else the reason it is rejected."""
    o, n = norm(orig), norm(new)
    if not n or re.sub(r"[^a-z0-9]", "", n.lower()) == re.sub(r"[^a-z0-9]", "", o.lower()):
        return "unchanged"
    if not (0.5 * len(o) <= len(n) <= 1.3 * len(o) + 20):
        return "length"
    if _nums(n) - _nums(o):
        return f"new number {sorted(_nums(n) - _nums(o))}"
    ol = o.lower()
    for t in _named(n):
        if t not in ol and not any(v.lower() in ol for v in variants(t)):
            return f"new name/term '{t}'"
    for t in vocab:
        if has_term(n, t) and not has_term(o, t):
            return f"new skill '{t}'"
    added_scope = {w.lower() for w in SCOPE_WORDS.findall(n)} - {w.lower() for w in SCOPE_WORDS.findall(o)}
    if added_scope:
        return f"scope inflation {sorted(added_scope)}"
    if AI_SPEAK.search(n) and not AI_SPEAK.search(o):
        return f"AI-speak '{AI_SPEAK.search(n).group(0)}'"
    if ("—" in n or " - " in n) and not ("—" in o or " - " in o):
        return "dash"
    if bool(NEGATION.search(n)) != bool(NEGATION.search(o)):
        return "negation changed"
    if any(re.search(r"\b" + re.escape(x) + r"\b", n, re.I) for x in FORBIDDEN_LEAKS):
        return "confidential name"
    return ""


def claude_json(prompt, model, timeout=300):
    r = subprocess.run(CLAUDE_CMD + ["--model", model],
                       input=prompt, capture_output=True, text=True, timeout=timeout, cwd=tempfile.gettempdir())
    txt = json.loads(r.stdout).get("result", "")
    return first_json(txt)


def first_json(txt):
    txt = re.sub(r"```(?:json)?", "", txt)
    dec = json.JSONDecoder()
    for i, ch in enumerate(txt):
        if ch in "[{":
            try:
                return dec.raw_decode(txt[i:])[0]
            except ValueError:
                continue
    raise ValueError("no JSON in model reply")


def all_vocab(kw):
    return ({t for terms in SKILL_TAXONOMY.values() for t in terms} | set(EXTRA_TERMS) | set(kw)) - DROP_TERMS


def ai_rewrite(sections, reqs, kw, display, model, log):
    """Propose rewrites for every movable bullet/paragraph; keep only those that pass both gates."""
    items = []
    for sec in sections:
        if sec["kind"] in ("summary", "education", "skills", "added"):
            continue
        for p in sec["parts"]:
            if p[0] == "group":
                for j, it in enumerate(p[2]):
                    if len(norm(it)) >= 30 and not parse_skill_line(it):
                        items.append((p, j, it))
    if not items:
        return {}
    quals = [r["text"] for r in reqs if r["tier"] in ("basic", "preferred")][:25]
    prompt = ("Rewrite resume bullets so an ATS AI screener and a recruiter see their relevance to this job faster.\n"
              "HARD RULES (a program rejects any rewrite that breaks one):\n"
              "- Keep every fact. Add NOTHING: no new numbers, names, tools, skills, technologies, employers, outcomes.\n"
              "- Do not strengthen scope: never add led, managed, owned, architected, spearheaded, mentored, first, only, expert, at scale.\n"
              "- You may reorder clauses, lead with the result, cut filler, and use the job's wording ONLY where it names the "
              "exact same thing the bullet already says.\n"
              "- Plain blunt voice. Short. No dashes. No buzzwords (leverage, robust, seamless, innovative, utilize, passionate).\n"
              "- If a bullet is already strong or cannot be improved without adding, return it unchanged.\n"
              "Return ONLY a JSON array: [{\"id\":0,\"text\":\"...\"}]\n\n"
              "JOB QUALIFICATIONS:\n" + "\n".join("- " + q for q in quals) +
              "\n\nJOB KEYWORDS: " + ", ".join(display.get(t, t) for t in list(kw)[:40]) +
              "\n\nBULLETS:\n" + json.dumps([{"id": i, "text": norm(it)} for i, (_, _, it) in enumerate(items)], ensure_ascii=False))
    try:
        props = claude_json(prompt, model)
    except Exception as e:
        log["rewrite_err"] = f"rewrite call failed: {e}"
        return {}
    vocab = all_vocab(kw)
    cands = {}
    for pr in props if isinstance(props, list) else []:
        i = pr.get("id")
        if not isinstance(i, int) or i >= len(items):
            continue
        orig, new = norm(items[i][2]), norm(pr.get("text", ""))
        why = rewrite_gate(orig, new, vocab)
        if why == "unchanged":
            continue
        if why:
            log.setdefault("rewrite_rejected", []).append((orig, new, why))
        else:
            cands[i] = new
    if not cands:
        return {}
    # Gate 2: skeptic
    pairs = [{"id": i, "original": norm(items[i][2]), "rewrite": t} for i, t in cands.items()]
    skeptic = ("You are a strict fact-checker for resumes. For each pair, does the REWRITE claim anything the ORIGINAL does not "
               "support: a bigger role, more ownership, a stronger result, a different scope, a different technology, or any "
               "new fact? Paraphrase with the same meaning is fine. Return ONLY JSON: [{\"id\":0,\"adds_claim\":true,\"why\":\"<12 words\"}]\n\n"
               + json.dumps(pairs, ensure_ascii=False))
    try:
        verdicts = {v.get("id"): v for v in claude_json(skeptic, model)}
    except Exception as e:
        log["rewrite_err"] = f"skeptic call failed, all rewrites dropped: {e}"
        return {}
    accepted = {}
    for i, new in cands.items():
        v = verdicts.get(i)
        orig = norm(items[i][2])
        if not v or v.get("adds_claim") is not False:
            log.setdefault("rewrite_rejected", []).append((orig, new, "skeptic: " + (v.get("why", "") if v else "no verdict")))
            continue
        p, j, _ = items[i]
        p[2][j] = new
        accepted[new] = orig
        log.setdefault("rewrites", []).append((orig, new))
    return accepted


def ai_jd_terms(jd, model):
    """Model lists the JD's skills/tools/qualification phrases; each must appear literally in the JD."""
    prompt = ("List every skill, tool, technology, certification, domain and qualification phrase an ATS would search for in "
              "this job posting. Copy each EXACTLY as written in the posting, 1 to 5 words. No company names, no benefits. "
              "Return ONLY a JSON array of strings.\n\nPOSTING:\n" + jd[:15000])
    try:
        terms = claude_json(prompt, model)
    except Exception:
        return []
    low = jd.lower()
    out = []
    for t in terms if isinstance(terms, list) else []:
        t = str(t).strip().strip(".,;:")
        if 2 <= len(t) <= 40 and len(t.split()) <= 5 and t.lower() in low and t.upper() not in ALLCAPS_STOP:
            out.append(t)
    return out


# ───────────────────────────── which ATS engine reads this application ─────────────────────────────
# Host rules first; page fingerprints second. Each engine carries what its own vendor documents
# about how it reads and ranks, so the report can say what matters for THIS application.

ENGINE_HOSTS = [
    ("eightfold", r"eightfold\.ai|explore\.jobs\.netflix\.net|jobs\.netflix\.com|jobs\.nvidia\.com|jobs\.careers\.microsoft\.com|apply\.careers\.microsoft\.com"),
    ("workday", r"myworkdayjobs\.com|myworkdaysite\.com|wd\d+\.myworkday"),
    ("greenhouse", r"greenhouse\.io"),
    ("ashby", r"ashbyhq\.com"),
    ("lever", r"lever\.co"),
    ("icims", r"icims\.com"),
    ("taleo", r"taleo\.net"),
    ("oracle", r"oraclecloud\.com"),
    ("successfactors", r"successfactors\.|sapsf\.|jobs\.sap\.com"),
    ("smartrecruiters", r"smartrecruiters\.com"),
    ("workable", r"workable\.com"),
    ("jobvite", r"jobvite\.com"),
    ("bamboohr", r"bamboohr\.com"),
    ("rippling", r"rippling\.com"),
    ("recruitee", r"recruitee\.com"),
    ("dover", r"dover\.com"),
    ("wellfound", r"wellfound\.com|angel\.co"),
    ("linkedin", r"linkedin\.com"),
    ("welcome to the jungle", r"welcometothejungle\.com|otta\.com"),
    ("dice", r"dice\.com"),
    ("hirevue", r"hirevue\.com"),
    ("robert half", r"roberthalf\.com"),
    ("indeed", r"indeed\.com"),
    ("ziprecruiter", r"ziprecruiter\.com"),
    ("staffing agency", r"teksystems|akkodis|randstad|motionrecruitment|insightglobal|kforce|aerotek|apexsystems|modis|jobot\.com"),
    ("in-house (Apple/Amazon/Meta/Google)", r"jobs\.apple\.com|amazon\.jobs|metacareers\.com|careers\.google\.com|google\.com/about/careers"),
    ("job board (forwards to the employer's ATS)", r"hiringcafe|workatastartup|ycombinator|glassdoor|builtin"),
]
ENGINE_FINGERPRINTS = [
    ("eightfold", r"eightfold"), ("workday", r"myworkdayjobs|workday"), ("greenhouse", r"greenhouse\.io|boards\.greenhouse"),
    ("ashby", r"ashbyhq"), ("lever", r"lever\.co"), ("icims", r"icims"), ("smartrecruiters", r"smartrecruiters"),
    ("successfactors", r"successfactors"), ("taleo", r"taleo"), ("phenom", r"phenompeople|phenom\.com"), ("avature", r"avature"),
]

ENGINE_NOTES = {
    "eightfold": [
        "Eightfold match score: 0–5 stars in half steps; the recruiter sees skill relevance, work relevance and JOB TITLE relevance (Eightfold NYC LL144 disclosure).",
        "It embeds your skills, titles, past companies and experiences and compares them to 'ideal candidate' profiles the team calibrates — ideal candidates move the score most.",
        "It models career trajectory from the SEQUENCE of titles, skills and tenure: keep every job's dates complete and the most recent role first.",
        "Skill phrases are embedded one by one, so the Skills list counts here (unlike Textkernel's advice).",
        "On the career site, the resume you upload builds your profile and personalises every match — upload this tailored file, not an old one.",
        "It also weighs industry similarity and company history, and credits 'skill learnability' (adjacent skills) — your related real work counts here; the report's correlation section is your evidence.",
        "Smart Apply: the uploaded resume becomes a profile matched against EVERY open role at that company, so it follows you across reqs.",
        "Some Eightfold employers run an AI Interviewer first round and fraud checks (ID.me/CLEAR identity, tab-switch alerts) — resume, LinkedIn and form answers must agree.",
    ],
    "workday": [
        "Workday rejects on knockout questions — answer them from the 'Knockout-style requirements' section below.",
        "Workday does NOT auto-fill Skills or Languages from the resume (Workday docs) — type them in by hand from this resume's Skills.",
        "Parsing results 'vary based on resume format and order of words'; avoid images (Workday docs). Check the autofilled job history field by field before submitting.",
        "Recruiters can see every role you have applied to at that company, with dates — keep applications to related roles (no evidence of an automatic score penalty).",
        "If HiredScore is on: basic qualifications decide A/B vs C/D — see the screener grades.",
    ],
    "greenhouse": [
        "Talent Matching (if enabled) reads ONLY the resume — skills, titles, years, dates, companies — with synonym-aware embeddings; form answers are not used.",
        "Tiers: Strong / Good / Partial / Limited match / Needs manual review. No automatic rejection; recruiters can override (Greenhouse support docs).",
        "Recruiters calibrate each role with 4–6 key skills, each rated for importance — the screener section's basic requirements are your best guess at those skills.",
        "'Needs manual review' = the AI could not process the resume. A clean parse (see the PDF round trip) keeps you in the scored pile.",
        "Recruiters also keyword-search the parsed profile — the posting's exact spellings matter.",
    ],
    "ashby": [
        "AI-Assisted Application Review judges each written criterion meets / gap / undecided from the resume AND long-form application answers.",
        "Fill every long-text answer with evidence — Ashby's AI reads those too. Ashby flags automated submissions (reCAPTCHA v3): click Submit yourself.",
    ],
    "lever": [
        "Recruiter keyword search with stemming but no abbreviation expansion — both 'MCP' and 'Model Context Protocol' must appear if either is searched.",
        "Recruiters scan the parsed profile (current title, company, skills, education), not the PDF.",
    ],
    "icims": [
        "Role Fit ranks per job; iCIMS builds its skills tags from the FULL resume text, not just the Skills section.",
    ],
    "taleo": [
        "Taleo ranks on prescreening answers (Required + Asset criteria → ACE candidates), not resume keyword counts. Answer every question to match the resume.",
    ],
    "oracle": [
        "Oracle Recruiting Cloud (Taleo's successor): prescreening questions and parsed profile drive ranking; check the autofilled history.",
    ],
    "successfactors": ["SAP SuccessFactors: parsed profile + screening questions; review autofilled fields before submitting."],
}
ENGINE_NOTES["dice"] = [
    "Dice Candidate Match (employer side) scores your tech skills plus your PAST, PRESENT and DESIRED job titles, in 5 tiers Unlikely → Excellent; recruiters see it next to your name and sort by it (Dice employer support docs).",
    "Set your Dice profile's DESIRED title to the posting's title — it is a stated preference, not a claim, and it feeds the score.",
    "Dice Easy Apply sends your PROFILE resume — upload this tailored file to the profile before applying, or the old one goes out.",
]
ENGINE_NOTES["linkedin"] = [
    "LinkedIn Job Match compares your PROFILE and RESUME with the hirer's required and preferred qualifications (LinkedIn Help a7120158).",
    "Your match level and Top Applicant rating are Premium-only and hirers do NOT see them; recruiters search the skills and experience on your profile.",
    "So the profile's Skills and Experience must carry the same words as this resume. 'Open to Work' members are ~35% more likely to answer recruiters (LinkedIn Talent blog).",
]
ENGINE_NOTES["robert half"] = [
    "Three engines (Robert Half): Profile Match compares you with the job AND with profiles of candidates they placed successfully (28M+ profiles); "
    "Job Search Signals = your recent profile updates and job applies; Recruiter Interactions = prior placements, evaluations, vetting interviews.",
    "Resume words become weighted ML features — keep skills, certifications and dates explicit and consistent between the resume and the app profile.",
    "Activity counts: update the profile with this tailored resume and apply through their app so the signals engine sees you.",
]
ENGINE_NOTES["staffing agency"] = [
    "A recruiter reads it first and re-submits it to the client, often reformatted onto their template — send the .docx so their edits keep your text intact.",
    "Agency databases are searched by keyword months later: the posting's exact spellings in Skills matter here.",
]
ENGINE_NOTES["indeed"] = [
    "Indeed Smart Screening gives a Smart Fit Score 0–100 against the employer's criteria, from your resume AND your answers to Indeed's AI Recruiter (text, chat or video follow-ups).",
    "Indeed data: applications scoring 80+ are 17x more likely to be hired than those under 30. Protected-class data is not used.",
    "Prepare the AI Recruiter answers from the screener section of this report: each basic requirement with the exact resume line that proves it.",
]
ENGINE_NOTES["ziprecruiter"] = [
    "ZipRecruiter shows Great / Good / Fair / Not a Match, from models trained on billions of employer–job-seeker interactions (ZipRecruiter press release).",
    "Candidate Calibration: employers thumbs-up/down sample profiles before applicants arrive; the model weighs skills, titles, years of experience, title RECENCY, location, resume LENGTH and application rate.",
    "Keep your most recent title relevant and the resume tight — recency and length are explicit features.",
]
ENGINE_NOTES["welcome to the jungle"] = [
    "Automatic Candidate Screening checks up to 5 employer criteria and reads ONLY the resume — custom form answers are ignored (WTTJ help center).",
    "No automatic rejection; the score sorts the pipeline. Every one of the 5 criteria must be provable from resume text alone.",
]
ENGINE_NOTES["hirevue"] = [
    "HireVue scores ONLY the words you say: speech → transcript (Rev.ai) → NLP against competency models from expert raters; no face, tone or video analysis (HireVue explainability statement).",
    "Say the posting's exact terms out loud and tie each to a real result — the transcript is what gets scored.",
]
GENERIC_NOTES = ["Unknown engine: the parser checks, keyword spellings and AI-screener grade below cover all of them."]


def detect_engines(url, page=""):
    """All engines that touch this application (NVIDIA = Eightfold front end + Workday back end)."""
    found = []
    u = (url or "").strip()
    host = urllib.parse.urlparse(u if re.match(r"^https?://", u, re.I) else "https://" + u.lstrip("/")).netloc.lower() if u else ""
    for name, rx in ENGINE_HOSTS:
        if re.search(rx, host):
            found.append(name)
    for name, rx in ENGINE_FINGERPRINTS:
        if name not in found and page and re.search(rx, page, re.I):
            found.append(name)
    if re.search(r"jobs\.nvidia\.com", host) and "workday" not in found:
        found.append("workday")   # NVIDIA applications submit into nvidia.wd5.myworkdayjobs.com
    return found


# ───────────────────────────── PDF round trip (what an ATS will extract) ─────────────────────────────
# Idea credit: srbhr/Resume-Matcher's ats_parse checks (text layer, garbled glyphs, columns,
# order fidelity). Independent implementation on pdftotext.

GARBLED = re.compile(r"\(cid:\d+\)|�|[-]|[ﬀ-ﬆ]")


def _kendall(positions):
    n = len(positions)
    if n < 2:
        return 1.0
    c = d = 0
    for i in range(n):
        for j in range(i + 1, n):
            c += positions[j] > positions[i]
            d += positions[j] < positions[i]
    return round(((c - d) / (n * (n - 1) / 2) + 1) / 2, 3)


def pdf_roundtrip(pdf_path, md=None):
    """Extract the PDF as an ATS would and grade it. Returns list of (severity, message)."""
    out = []
    try:
        plain = subprocess.run(["pdftotext", pdf_path, "-"], capture_output=True, text=True, check=True).stdout
        layout = subprocess.run(["pdftotext", "-layout", pdf_path, "-"], capture_output=True, text=True, check=True).stdout
    except Exception as e:
        return [("FATAL", f"pdftotext could not read the PDF: {e}")]
    visible = len(re.sub(r"\s", "", plain))
    if visible < 200:
        out.append(("FATAL", f"almost no text layer ({visible} chars) — scanned/image PDF; an ATS reads nothing"))
    g = len(GARBLED.findall(plain))
    if g and g / max(1, visible) > 0.005:
        out.append(("MAJOR" if g / visible > 0.05 else "minor", f"{g} garbled glyphs (cid codes / ligatures / private-use chars) in extracted text"))
    lines = [l for l in layout.splitlines() if l.strip()]
    gutters = [l for l in lines if re.search(r"\S\s{6,}\S", l.strip()) and len(l.strip()) > 40]
    if lines and len(gutters) / len(lines) > 0.15:
        out.append(("MAJOR", f"{len(gutters)}/{len(lines)} lines look two-column — parsers read columns across and scramble them"))
    pages = plain.split("\f")
    if len([p for p in pages if p.strip()]) > 1:
        firsts = [next((l.strip() for l in p.splitlines() if l.strip()), "") for p in pages if p.strip()]
        lasts = [next((l.strip() for l in reversed(p.splitlines()) if l.strip()), "") for p in pages if p.strip()]
        for edge in (firsts, lasts):
            rep_ = [l for l in set(edge) if l and edge.count(l) > 1 and not re.fullmatch(r"\d+", l)]
            if rep_:
                out.append(("minor", f"repeated header/footer line on every page: '{rep_[0][:60]}' — ATSs often drop header/footer content"))
    try:
        imgs = subprocess.run(["pdfimages", "-list", pdf_path], capture_output=True, text=True).stdout.splitlines()[2:]
        if imgs:
            out.append(("minor", f"{len(imgs)} image(s) in the PDF — Workday: 'use resumes that don't have images'"))
    except Exception:
        pass
    if md:
        flat = norm(" ".join(plain.split()))
        wanted = [norm(l) for l in md.splitlines() if len(norm(l)) > 25 and not l.lstrip().startswith("#")]
        pos, missing = [], 0
        for w in wanted:
            probe = " ".join(w.split()[:7])
            i = flat.find(probe)
            if i < 0:
                missing += 1
            else:
                pos.append(i)
        recall = 1 - missing / max(1, len(wanted))
        fid = _kendall(pos)
        sev = "MAJOR" if recall < 0.9 or fid < 0.9 else "ok"
        out.append((sev, f"round trip: {recall:.0%} of lines extracted intact, reading-order fidelity {fid:.2f} (≥0.90 needed)"))
    return out


# ───────────────────────────── CLI ─────────────────────────────

def check_file(path):
    """Parseability audit of a resume you already have — no job needed."""
    path = clean_path(path)
    md = read_any(path)
    print(f"Checking {path}")
    hidden = hidden_text_findings(path, md)
    for h in hidden:
        print(f"  ⛔ {h}")
    for code, sev, msg in lint(md, path, {}, {}):
        if code != "112":
            print(f"  [{sev}] ({code}) {msg}")
    if path.lower().endswith(".docx"):
        for a, b in docx_layout(path):
            print(f"  DOCX [{a}] {b}")
    if path.lower().endswith(".pdf"):
        for a, b in pdf_roundtrip(path, md):
            print(f"  PDF [{a}] {b}")
    return 1 if hidden else 0


def ats_map(files, out):
    """Every job link in the given JSON/JSONL files, grouped by the engine that will read the application."""
    from collections import defaultdict
    groups = defaultdict(set)
    def walk(o, company="?"):
        if isinstance(o, dict):
            company = o.get("company") or o.get("Company") or company
            for v in o.values():
                walk(v, company)
        elif isinstance(o, list):
            for v in o:
                walk(v, company)
        elif isinstance(o, str) and o.startswith("http"):
            for e in detect_engines(o) or ["other"]:
                groups[e].add((str(company)[:40], urllib.parse.urlparse(o).netloc))
    for fp in files:
        if not os.path.isfile(fp):
            continue
        txt = open(fp, encoding="utf-8", errors="ignore").read()
        try:
            walk(json.loads(txt))
        except Exception:
            for line in txt.splitlines():
                try:
                    walk(json.loads(line))
                except Exception:
                    pass
    lines = ["# ATS map — which engine reads each application", "",
             f"Generated {datetime.date.today()} by truthfit --ats-map from {', '.join(os.path.basename(f) for f in files)}.", ""]
    for e in sorted(groups, key=lambda k: (k == "other", -len(groups[k]))):
        comps = sorted({c for c, _ in groups[e]})
        lines += [f"## {e} — {len(comps)} companies", ""]
        lines += [f"- {n}" for n in ENGINE_NOTES.get(e, [])[:3]]
        lines += ["", ", ".join(comps), ""]
    open(out, "w").write("\n".join(lines) + "\n")
    print(f"Wrote {out}")
    for e in sorted(groups, key=lambda k: -len(groups[k])):
        print(f"  {e:15} {len({c for c, _ in groups[e]})} companies")
    return 0


def clean_path(p):
    p = p.strip().strip("'\"")
    return os.path.expanduser(p.replace("\\ ", " "))


def interactive(args):
    print("ATS Tailor — drag files into this window to paste their paths. Enter to skip.\n")
    args.resume = clean_path(input("Base resume (.docx/.md/.pdf): "))
    args.url = input("Job posting URL (optional): ").strip() or None
    jd = clean_path(input("Job description file (optional if URL given): ") or "")
    args.jd_file = jd or None
    ev = []
    while True:
        e = clean_path(input("Evidence file to pull from (Enter when done): ") or "")
        if not e:
            break
        ev.append(e)
    args.evidence = ev
    args.company = input("Company name (optional): ").strip() or args.company
    return args


def main(defaults=None):
    ap = argparse.ArgumentParser(description="Tailor a resume to a job for ATS — verbatim sources only, fail-closed.")
    ap.add_argument("--resume", help="base resume (.docx .md .txt .pdf)")
    ap.add_argument("--jd-file", help="job description file (.txt .md .html .pdf)")
    ap.add_argument("--jd-text", help="job description as a string")
    ap.add_argument("--url", help="job posting URL (Greenhouse/Lever/Ashby/Workday/any page)")
    ap.add_argument("--evidence", action="append", default=[], help="extra source file to pull from (repeatable)")
    ap.add_argument("--company", help="company name (for file names / report)")
    ap.add_argument("--title", help="job title (for the report)")
    ap.add_argument("--out", help="output folder (default tailored/<date>_<company>_<title>/)")
    ap.add_argument("--max-bullets", type=int, default=0, help="keep at most N bullets per job/project (0 = keep all)")
    ap.add_argument("--max-evidence", type=int, default=6, help="max verbatim bullets pulled from evidence files (0 = none)")
    ap.add_argument("--min-evidence-score", type=float, default=4.0, help="JD-match score an evidence bullet needs")
    ap.add_argument("--pdf", action="store_true", help="also write a PDF (pandoc + typst)")
    ap.add_argument("--no-target-line", action="store_true", help="omit the 'Target role: <posting title>' line under your name")
    ap.add_argument("--no-ai", action="store_true", help="skip every model step (keyword extraction, rewrite, screener)")
    ap.add_argument("--no-rewrite", action="store_true", help="keep your exact words; no AI rephrasing")
    ap.add_argument("--no-ai-screen", action="store_true", help="skip the real-model screener pass (it runs by default)")
    ap.add_argument("--ai-model", default="sonnet", help="model for the AI screener (default sonnet)")
    ap.add_argument("--identity", help="JSON with your real 'email' and 'phoneRaw'; output must contain both")
    ap.add_argument("--forbidden", help="file of terms that must never appear in output (one per line); also $TRUTHFIT_FORBIDDEN")
    ap.add_argument("--name-prefix", help="output file name prefix (default: base resume file name)")
    ap.add_argument("--out-root", default=os.path.join(os.getcwd(), "tailored"), help="parent folder for run folders")
    ap.add_argument("--default", action="store_true", help="a general resume tailored to no job: your lines in your order, verified the same way")
    ap.add_argument("--downloads", metavar="PACKAGES.json", help='update the resume\'s download counts live from PyPI/npm; '
                    'file is {"pypi": [...], "npm": [...], "descriptions": {...}}')
    ap.add_argument("--drop", action="append", default=[], metavar="TEXT",
                    help="remove every base line containing TEXT (repeatable); a TEXT that matches nothing stops the run")
    ap.add_argument("--check-file", help="audit an existing resume file (PDF/DOCX) for parseability and exit")
    ap.add_argument("--ats-map", nargs="*", metavar="FILE", help="classify every job link in these JSON/JSONL files by ATS engine")
    ap.add_argument("--ats-map-out", default="ATS_MAP.md", help="where --ats-map writes its table")
    ap.set_defaults(**{"ats_map_default": [], **(defaults or {})})
    args = ap.parse_args()
    for src in [args.forbidden, os.environ.get("TRUTHFIT_FORBIDDEN")]:
        if src and os.path.isfile(os.path.expanduser(src)):
            FORBIDDEN_LEAKS.extend(t.strip() for t in open(os.path.expanduser(src)) if t.strip() and not t.startswith("#"))
    if args.check_file:
        sys.exit(check_file(args.check_file))
    if args.ats_map is not None:
        sys.exit(ats_map(args.ats_map or args.ats_map_default, args.ats_map_out))
    if not args.resume:
        args = interactive(args)
    args.ai_terms = []
    args.page_text = ""
    if args.no_ai or not shutil.which("claude"):
        args.no_ai_screen = args.no_rewrite = args.no_ai = True

    for p in [args.resume] + args.evidence + ([args.jd_file] if args.jd_file else []) + ([args.downloads] if args.downloads else []):
        if not os.path.isfile(p):
            sys.exit(f"File not found: {p}")
    if args.default:
        sys.exit(default_run(args))
    if not (args.url or args.jd_file or args.jd_text):
        sys.exit("Give the job: --url, --jd-file or --jd-text (or --default for a resume tailored to no job)")

    # ── the job
    title, company, jd_parts = args.title or "", args.company or "", []
    if args.url:
        try:
            t, c, txt = fetch_job(args.url)
            args.page_text = txt
            title, company = title or t, company or c
            jd_parts.append(txt)
            print(f"Fetched {len(txt):,} chars from {args.url}")
            if len(txt) < 400:
                print("  ⚠ very little text came back — the page is probably JavaScript-rendered. Paste the JD into a file and pass --jd-file too.")
        except Exception as e:
            print(f"  ⚠ could not fetch the URL ({e}). Paste the JD into a file and pass --jd-file.")
            if not (args.jd_file or args.jd_text):
                sys.exit(1)
    if args.jd_file:
        jd_parts.append(read_any(args.jd_file))
    if args.jd_text:
        jd_parts.append(args.jd_text)
    jd = "\n".join(jd_parts)
    kw, display = jd_keywords(jd)
    reqs = jd_requirements(jd)
    ai_terms = []
    if not args.no_ai:
        print("Extracting the posting's skills with the model...")
        for t in ai_jd_terms(jd, args.ai_model):
            if any(has_term(t, k) or has_term(k, t) for k in kw):
                continue
            kw[t.lower()] = 2.0 if any(r["tier"] == "basic" and has_term(r["text"], t) for r in reqs) else 1.0
            display[t.lower()] = t
            ai_terms.append(t)
    args.ai_terms = ai_terms
    if not kw:
        sys.exit("No keywords found in the job description — check the input.")

    base_md, evidence_files, corpus, identity, dl = load_sources(args)
    log = {"reordered": [], "trimmed": []}
    header, sections = parse_resume(base_md)
    header, sections = tailor(header, sections, kw, display, corpus, evidence_files, args, log, reqs)
    target = None if args.no_target_line or not title else re.sub(r"\s+", " ", title).strip()[:90]
    md_verbatim = render(header, sections, target)
    rewrites = {}
    if not args.no_rewrite:
        print("Rewriting bullets (model proposes, gates decide)...")
        rewrites = ai_rewrite(sections, reqs, kw, display, args.ai_model, log)
    md = render(header, sections, target)
    vocab = all_vocab(kw)

    # ── output folder
    date = datetime.date.today().isoformat()
    out = args.out or os.path.join(args.out_root, f"{date}_{slug(company or 'job')}_{slug(title or 'role')}")
    os.makedirs(out, exist_ok=True)
    base_name = (args.name_prefix or slug(os.path.splitext(os.path.basename(args.resume))[0])) + (f"_{slug(company)}" if company else "")

    # ── verdict
    fails = verify(md, base_md, corpus, identity, rewrites, vocab, target)
    if not fails:
        fails += write_docx(md, out, base_name, args, lambda back: verify(back, base_md, corpus, identity, rewrites, vocab, target))

    before, after = coverage(base_md, kw), coverage(md, kw)
    scr_before, grade_before = screen(base_md, reqs, kw, args.ai_terms)
    scr, grade = screen(md, reqs, kw, args.ai_terms)
    issues = lint(md, args.resume, kw, display)
    ai, ai_err = (None, None)
    if not args.no_ai_screen and not fails:
        print(f"Running the AI screener ({args.ai_model}) on the finished resume...")
        ai, ai_err = ai_screen(md, scr, args.ai_model)
    report = [f"# ATS Tailor Report — {company or '?'} · {title or '?'}", "",
              f"- Generated: {datetime.datetime.now():%Y-%m-%d %H:%M}",
              f"- Base resume: `{args.resume}`",
              f"- Job URL: {args.url or '—'}", f"- JD file: {args.jd_file or '—'}",
              f"- Evidence files: {', '.join(f'`{p}`' for p in args.evidence) or '—'}", ""]
    report += downloads_report(dl, out)
    report += [f"## Verdict: {'✅ PASS — every line traced to your sources (verbatim or gated rewrite)' if not fails else '⛔ FAIL — resume NOT written'}", ""]
    report += [f"- {f}" for f in fails] + ([""] if fails else [])
    report += [f"## JD keyword coverage (weighted): {before}% → {after}%", "",
               "Top JD keywords (weight): " + ", ".join(f"{display.get(t, t)} ({w:g})" for t, w in list(kw.items())[:30]), "",
               f"## Added to Skills ({len(log['added'])}) — each backed by your own words", ""]
    report += [f"- **{t}** ← `{src[0]}:{src[1]}` — \"{src[2][:140]}\"" for t, w, src in log["added"]] or ["- none"]
    report += ["", f"## Pulled verbatim from evidence files ({len(log['evidence'])}) — section \"{ADDED_SECTION}\"", ""]
    report += [f"- `{n}:{i}` (score {sc:g}) {s}" for sc, n, i, s in log["evidence"]] or ["- none"]
    report += ["", f"## Bullets rewritten ({len(log.get('rewrites', []))} accepted, {len(log.get('rewrite_rejected', []))} rejected)", ""]
    if log.get("rewrite_err"):
        report.append(f"- ⚠ {log['rewrite_err']}")
    for o, n in log.get("rewrites", []):
        report += [f"- WAS: {o}", f"  NOW: {n}"]
    if log.get("rewrite_rejected"):
        report += ["", "Rejected (original words kept):"]
        report += [f"- [{why}] {n[:140]}" for o, n, why in log["rewrite_rejected"]]
    if rewrites:
        report += ["", "Your exact-words version is saved next to it as *_verbatim.md / .docx."]
    titles = [norm(l) for sec in sections if sec["kind"] == "experience" for pt in sec["parts"]
              if pt[0] == "fixed" and pt[1].lstrip().startswith("###") for l in [pt[1]]]
    report += ["", "## Job title", "", f"- Posting: **{title or '?'}**",
               f"- Added under your name: \"{TARGET_PREFIX + target}\" (55% of recruiters filter by title; it names the job "
               "you are applying for and changes no title you held)" if target else "- No target-role line (no title found or --no-target-line)",
               f"- Your titles (never changed): {'; '.join(titles) or '—'}"]
    if ai_terms:
        report += ["", f"## Keywords the model found in the posting (each verified literally in the JD): {', '.join(ai_terms)}"]
    report += ["", "## Pulled to answer a specific qualification the AI screener would flag", ""]
    report += [f"- for \"{q[:90]}\" ← `{n}:{i}`: {t}" for q, n, i, t in log.get("targeted", [])] or ["- none"]
    report += ["", "## GAPS — the JD asks for these and none of your files say you have them (NOT added)", ""]
    seen_g = set()
    report += [f"- {t} (weight {w:g})" for t, w in sorted(log["gaps"], key=lambda g: -g[1])
               if not (t.lower() in seen_g or seen_g.add(t.lower()))] or ["- none"]
    report += ["", "## Gaps with a RELATED real match — your verbatim line was moved up; use as a talking point, not a claim", ""]
    report += [f"- JD wants **{g}** → closest you have (`{b[0]}:{b[1]}`, shares: {', '.join(b[3])}): \"{b[2][:160]}\""
               for g, w, b in log["correlated"]] or ["- none"]
    report += ["", "## Gaps with NO related evidence — skipped", ""]
    report += [f"- {g} (weight {w:g})" for g, w in log["uncorrelated"]] or ["- none"]
    if log["negated"]:
        report += ["", "## Your files say you DON'T have these (NOT added)", ""] + [f"- {t}" for t in log["negated"]]
    if log["trimmed"]:
        report += ["", f"## Trimmed (--max-bullets {args.max_bullets})", ""] + [f"- {t}" for t in log["trimmed"]]
    report += ["", "## Bullet groups re-ordered (new top bullet shown)", ""]
    report += [f"- {norm(sec)}: {top[:120]}" for sec, top in log["reordered"]] or ["- none"]
    icon = {"meets": "✅", "partial": "🟡", "gap": "❌"}
    report += ["", f"## AI-screener simulation (deterministic) — estimated grade {grade_before} → {grade}", "",
               "How Greenhouse / Ashby / Workday HiredScore screen: each qualification is judged from evidence "
               "in the parsed resume; basic qualifications decide A/B vs C/D.", ""]
    for tier in ("basic", "preferred", "duty"):
        rows = [x for x in scr if x["tier"] == tier]
        if rows:
            report += [f"### {tier.title()} ({sum(x['status'] == 'meets' for x in rows)}/{len(rows)} met)", ""]
            for x in rows:
                report.append(f"- {icon[x['status']]} {x['text'][:150]}")
                if x["evidence"]:
                    report.append(f"    - evidence: \"{x['evidence'][:160]}\"")
                if x["missing"]:
                    report.append(f"    - not found: {', '.join(display.get(t, t) for t in x['missing'])}")
                if x["note"]:
                    report.append(f"    - ⚠ {x['note']}")
            report.append("")
    if not args.no_ai_screen:
        report += [f"## Real AI screener ({args.ai_model}) — every quote checked verbatim against the resume", ""]
        if ai_err or not ai:
            report += [f"- {ai_err or 'not run (verifier failed)'}"]
        else:
            report += [f"**Grade: {ai.get('grade', '?')}**", "", f"What the recruiter's AI summary will likely say: \"{ai.get('summary', '')}\"", ""]
            for c in ai.get("criteria", []):
                i = c.get("id")
                crit = scr[i]["text"][:110] if isinstance(i, int) and i < len(scr) else str(i)
                v = "" if c.get("verified") else " ⛔ QUOTE NOT IN RESUME — model claim rejected"
                report.append(f"- **{c.get('status')}** — {crit}{v}")
                if c.get("quote"):
                    report.append(f"    - quote: \"{c['quote'][:180]}\"")
                if c.get("reason"):
                    report.append(f"    - why: {c['reason']}")
            unv = [c for c in ai.get("criteria", []) if not c.get("verified")]
            report += ["", f"Quotes verified: {len(ai.get('criteria', [])) - len(unv)}/{len(ai.get('criteria', []))}"]
    ko = [r for r in reqs if re.search(r"\d+\s*\+?\s*(?:-\s*\d+\s*)?(?:years|yrs)|degree|bachelor|master|ph\.?d|clearance|"
                                       r"authori[sz]ed to work|sponsorship|visa|citizen|relocat|on-?site|in-?office|"
                                       r"hybrid|located in|certif", r["text"], re.I)]
    report += ["", "## Knockout-style requirements — answer these screening questions from what your resume shows", "",
               "Taleo ranks applicants on prescreening answers, and Workday rejects on knockout questions, "
               "so each answer must match the resume.", ""]
    ko_rx = [(r"authori[sz]ed to work|sponsorship|visa|citizen", r"citizen|authori[sz]ed|sponsorship|green card|permanent resident"),
             (r"degree|bachelor|master|ph\.?d", r"bachelor|master|ph\.?d|\bb\.?s\.?\b|\bm\.?s\.?\b|degree|university|college"),
             (r"clearance", r"clearance|secret|ts/sci"),
             (r"relocat|on-?site|in-?office|hybrid|located in", r"relocat|remote|hybrid|on-?site|[A-Z][a-z]+, [A-Z]{2}\b"),
             (r"certif", r"certif|comptia|security\+|security plus|network\+|\\bcissp\\b|\\boscp\\b|aws certified|\\bckad?\\b"),
             (r"years|yrs", r"(?:19|20)\d{2}\s*(?:-|–|to)\s*(?:(?:[A-Z][a-z]+\s+)?(?:19|20)\d{2}|present)")]
    all_lines = [norm(l) for l in md.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    for r in ko:
        ev = ""
        for want, look in ko_rx:
            if re.search(want, r["text"], re.I):
                hits = [l for l in all_lines if re.search(look, l, re.I)]
                if hits:
                    ev = " | ".join(hits[:3])
                break
        ev = ev or next((x["evidence"] for x in scr if x["text"] == r["text"] and x["evidence"]), "")
        report.append(f"- {r['text'][:160]}")
        report.append(f"    - your resume shows: \"{ev[:240]}\"" if ev else "    - your resume shows: nothing direct")
    if not ko:
        report.append("- none detected")
    engines = detect_engines(args.url, args.page_text)
    report += ["", f"## Which systems read this application: {', '.join(engines) or 'unknown'}", ""]
    for e in engines or ["generic"]:
        for n in ENGINE_NOTES.get(e, GENERIC_NOTES):
            report.append(f"- **{e}** — {n}")
    if args.resume.lower().endswith(".docx"):
        dl = docx_layout(args.resume)
        report += ["", "## Your BASE Word file's layout (the tailored output is single-column, no tables/text boxes)", ""]
        report += [f"- [{a}] {b}" for a, b in dl] or ["- clean"]
    plain_bullets = [norm(l) for sec in sections if sec["kind"] in ("experience", "projects", "other")
                     for pt in sec["parts"] if pt[0] == "group" for l in pt[2]
                     if not re.match(r"(technolog|tools|stack|environment|tech)[^:]{0,20}:", norm(l), re.I)
                     and not re.search(r"\d|\b(one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|zero|half|twice)\b", norm(l), re.I)]
    report += ["", f"## Bullets with no number ({len(plain_bullets)}) — LLM recruiter summaries quote results; add a REAL number in your base resume if you have one", ""]
    report += [f"- {b[:150]}" for b in plain_bullets[:15]] or ["- none"]
    gh_user = re.search(r"github\.com/([A-Za-z0-9-]+)", md)
    if gh_user and shutil.which("gh"):
        try:
            u = json.loads(subprocess.run(["gh", "api", f"users/{gh_user.group(1)}"], capture_output=True, text=True, timeout=20).stdout)
            bio = u.get("bio") or ""
            report += ["", f"## Public footprint — GitHub @{gh_user.group(1)} (SeekOut indexes 40M+ GitHub profiles and merges them with your resume data)", "",
                       f"- name: {u.get('name') or 'MISSING'} · location: {u.get('location') or 'MISSING'} · public repos: {u.get('public_repos')}",
                       f"- bio: \"{bio or 'MISSING'}\""]
            if target and not any(w.lower() in bio.lower() for w in re.findall(r"[A-Za-z]{4,}", target)):
                report.append(f"- the bio shares no word with the target role \"{target}\" — aggregators match titles across your profiles")
            if not u.get("location"):
                report.append("- no location set — sourcing tools filter by location")
        except Exception:
            pass
    report += ["", "## Parser-quality checks (Textkernel/Sovren resume-quality codes)", ""]
    report += [f"- [{sev}] ({code}) {msg}" for code, sev, msg in issues] or ["- none"]
    report += ["", "## Job description used", "", "```", jd.strip()[:20000], "```"]
    open(os.path.join(out, "REPORT.md"), "w").write("\n".join(report) + "\n")

    if fails:
        print(f"\n⛔ FAIL-CLOSED — {len(fails)} check(s) failed. No resume written. See {out}/REPORT.md")
        for f in fails[:15]:
            print("   ", f)
        sys.exit(2)

    write_files(md, md_verbatim if rewrites else None, out, base_name, args)

    print(f"\n✅ PASS — every line traces to your files ({'verbatim' if not rewrites else f'verbatim, or one of {len(rewrites)} gated rewrites of a verbatim line'}).")
    print(f"   JD keyword coverage: {before}% → {after}%   added to skills: {len(log['added'])}   "
          f"evidence bullets: {len(log['evidence'])}   gaps (not added): {len(log['gaps'])}")
    print(f"   Rewrites: {len(log.get('rewrites', []))} accepted, {len(log.get('rewrite_rejected', []))} rejected by the gates")
    print(f"   Screener grade (simulated): {grade_before} → {grade}   basic met: "
          f"{sum(x['status'] == 'meets' for x in scr if x['tier'] == 'basic')}/{sum(x['tier'] == 'basic' for x in scr)}"
          + (f"   real AI grade: {ai.get('grade')}" if ai else (f"   AI: {ai_err}" if ai_err else "")))
    finish(issues, out, dl)


def load_sources(args):
    """Base resume (with live download counts swapped in when --downloads is given), evidence, corpus, identity."""
    base_md = read_any(args.resume)
    hidden = hidden_text_findings(args.resume, base_md)
    if hidden:
        print("⛔ Your base resume contains hidden or AI-directed text. ATSs and recruiters treat this as cheating:")
        for h in hidden[:10]:
            print("   ", h)
        sys.exit("Remove it from the base resume, then re-run.")
    if args.drop:
        base_md, dropped = drop_lines(base_md, args.drop)
        for d in dropped:
            print(f"  dropped: {d[:110]}")
    dl = None
    if args.downloads:
        cfg = json.load(open(args.downloads))
        print(f"Fetching live download counts for {len(cfg.get('pypi', [])) + len(cfg.get('npm', []))} packages...")
        try:
            stats = fetch_downloads(cfg)
        except Exception as e:
            sys.exit(f"⛔ FAIL-CLOSED — a registry fetch failed ({e}). No resume written; stale counts never go out.")
        base_md, changes = apply_downloads(base_md, stats, cfg.get("descriptions"))
        dl = {"stats": stats, "changes": changes}
    evidence_files = [(os.path.basename(p), read_any(p)) for p in args.evidence]
    # with --downloads the base is your resume plus the receipt-backed lines; everything else is still verbatim
    corpus = Corpus([(os.path.basename(args.resume), base_md)] + evidence_files)
    identity = json.load(open(args.identity)) if args.identity and os.path.isfile(args.identity) else None
    return base_md, evidence_files, corpus, identity, dl


def drop_lines(md, texts):
    """Remove lines (a wrapped paragraph or bullet counts as one) containing any of texts. Only removes, so verbatim holds."""
    out, dropped, hit = [], [], set()
    for line in md.splitlines():
        found = [t for t in texts if t.lower() in norm(line).lower()]
        if found:
            hit.update(found)
            dropped.append(norm(line))
        else:
            out.append(line)
    missing = [t for t in texts if t not in hit]
    if missing:
        sys.exit(f"⛔ --drop matched nothing for: {', '.join(missing)} — check the spelling; nothing written.")
    return "\n".join(out) + "\n", dropped


def downloads_report(dl, out):
    if not dl:
        return []
    json.dump(dl["stats"], open(os.path.join(out, "downloads_receipt.json"), "w"), indent=1)
    rep = [f"## Download counts — live from the registries {dl['stats']['fetched']} (receipt: downloads_receipt.json)", ""]
    for old, new in dl["changes"]:
        rep += [f"- WAS: {old.strip()}", f"  NOW: {new.strip()}"] if old else [f"- ADDED: {new.strip()}"]
    if any(p["floor"] for p in dl["stats"]["packages"]):
        rep.append("- '+' marks a floor: pypistats keeps 180 days and that package is older")
    return rep + [""]


def write_docx(md, out, base_name, args, check):
    """Write the .docx, read it back to text, and run the verifier on what Word will actually hold."""
    if not shutil.which("pandoc"):
        return []
    docx_path = os.path.join(out, base_name + ".docx")
    tmp_md = os.path.join(out, ".verify.md")
    open(tmp_md, "w").write(md)
    cmd = ["pandoc", tmp_md, "-o", docx_path]
    if args.resume.lower().endswith(".docx"):
        cmd += ["--reference-doc", args.resume]
    subprocess.run(cmd, check=True)
    os.remove(tmp_md)
    back = tables_to_lines(subprocess.run(["pandoc", docx_path, "-t", "gfm", "--wrap=none"],
                                          capture_output=True, text=True, check=True).stdout)
    fails = [f"[docx round-trip] {f}" for f in check(back)]
    if fails:
        os.remove(docx_path)
    return fails


def default_run(args):
    """--default: the resume tailored to no job. Same sources, same verifier, same file outputs."""
    base_md, _, corpus, identity, dl = load_sources(args)
    header, sections = parse_resume(base_md)
    md = render(header, sections)
    out = args.out or os.path.join(args.out_root, f"{datetime.date.today().isoformat()}_default")
    os.makedirs(out, exist_ok=True)
    base_name = (args.name_prefix or slug(os.path.splitext(os.path.basename(args.resume))[0])) + "_default"
    fails = verify(md, base_md, corpus, identity)
    if not fails:
        fails += write_docx(md, out, base_name, args, lambda back: verify(back, base_md, corpus, identity))
    issues = lint(md, args.resume, {}, {})
    report = [f"# truthfit — default resume (no job)", "", f"- Generated: {datetime.datetime.now():%Y-%m-%d %H:%M}",
              f"- Base resume: `{args.resume}`", ""]
    report += downloads_report(dl, out)
    report += [f"## Verdict: {'✅ PASS — every line traced to your sources' if not fails else '⛔ FAIL — resume NOT written'}", ""]
    report += [f"- {f}" for f in fails] + ([""] if fails else [])
    report += ["## Parser-quality checks (Textkernel/Sovren resume-quality codes)", ""]
    report += [f"- [{sev}] ({code}) {msg}" for code, sev, msg in issues if code != "112"] or ["- none"]
    open(os.path.join(out, "REPORT.md"), "w").write("\n".join(report) + "\n")
    if fails:
        print(f"\n⛔ FAIL-CLOSED — {len(fails)} check(s) failed. No resume written. See {out}/REPORT.md")
        for f in fails[:15]:
            print("   ", f)
        return 2
    write_files(md, None, out, base_name, args)
    print("\n✅ PASS — default resume, every line traces to your files" + (" or the live registry receipt." if dl else "."))
    finish([i for i in issues if i[0] != "112"], out, dl)
    return 0


def finish(issues, out, dl):
    if dl:
        print(f"   Downloads: {_count(dl['stats']['packages'])} lifetime across {len(dl['stats']['packages'])} packages "
              f"(live {dl['stats']['date']}, receipt in downloads_receipt.json)")
    for code, sev, msg in issues:
        if sev in ("FATAL", "MAJOR"):
            print(f"   ⚠ [{sev}] {msg}")
    print(f"   Output: {out}/")
    for f in sorted(os.listdir(out)):
        print(f"     {f}")


def write_files(md, md_verbatim, out, base_name, args):
    open(os.path.join(out, base_name + ".md"), "w").write(md)
    if md_verbatim:
        vb = os.path.join(out, base_name + "_verbatim")
        open(vb + ".md", "w").write(md_verbatim)
        cmd = ["pandoc", vb + ".md", "-o", vb + ".docx"] + (["--reference-doc", args.resume] if args.resume.lower().endswith(".docx") else [])
        subprocess.run(cmd, check=True)
    open(os.path.join(out, base_name + ".txt"), "w").write("\n".join(norm(l) if l.strip() else "" for l in md.splitlines()) + "\n")
    if args.pdf:
        if shutil.which("typst"):
            r = subprocess.run(["pandoc", os.path.join(out, base_name + ".md"), "-o", os.path.join(out, base_name + ".pdf"),
                                "--pdf-engine=typst", "-V", "margin.x=0.6in", "-V", "margin.y=0.5in",
                                "-V", "fontsize=10pt", "-V", "mainfont=Helvetica"], capture_output=True, text=True)
            if r.returncode:
                print("  ⚠ PDF failed (use the .docx):", r.stderr.strip()[:300])
            pdf_text = "" if r.returncode else subprocess.run(["pdftotext", os.path.join(out, base_name + ".pdf"), "-"], capture_output=True, text=True).stdout
            missing = [l for l in md.splitlines() if l.startswith("- ") and norm(l)[:40] not in norm(pdf_text)]
            if missing and not r.returncode:
                print(f"  ⚠ PDF text check: {len(missing)} bullet(s) not found in PDF text layer — use the .docx")
            if not r.returncode:
                rt = pdf_roundtrip(os.path.join(out, base_name + ".pdf"), md)
                with open(os.path.join(out, "REPORT.md"), "a") as f:
                    f.write("\n## PDF round trip — what an ATS extracts from the PDF\n\n" + "\n".join(f"- [{a}] {b}" for a, b in rt) + "\n")
                for a, b in rt:
                    print(f"   PDF {a}: {b}")
        else:
            print("  ⚠ --pdf needs typst (brew install typst); .docx written instead")



if __name__ == "__main__":
    main()

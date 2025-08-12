#!/usr/bin/env python3
import os
import re
import json
import asyncio
import aiohttp
import argparse
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, quote

import pandas as pd
from dotenv import load_dotenv

load_dotenv()

# ==========
# Constants
# ==========
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

def _safe_name(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9._-]+", "_", s)[:80]
    return s or "unknown"

def _log_json(path: str, obj: Any, debug: bool):
    if not debug:
        return
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


MODEL_SUMMARY = "gpt-5-nano"   # summarization step
MODEL_SENTENCE = "gpt-5-mini"  # final sentence generation step


# ===========================================
# YOUR PROFILE (included in every generation)
# ===========================================
PROFILE_PROMPT = """
Cybersecurity professional specialized in security engineering & incident response.
Engineered secure, fault-tolerant blockchain nodes for 8 chains with robust support and
monitoring. Delivered critical projects & training for military organizations, NGOs, &
Educational institutions. Passionate about open source, self hosting and infrastructure
reliability. Looking to scale & lead security initiatives in high-impact environments.
PROFESSIONAL EXPERIENCE
FULL TIME
Luganodes | Cloud Security Engineer 
Python | Docker |IaC | AWS | Proxmox | Prometheus | Grafana | Linux | Nginx | EDR
Completed Computer Engineering degree in 3 years and started working full time during the 4th year.
Scaled cloud infrastructure, deployed fault tolerant monitoring solutions, designed and deployed Internal network.
Build controls & policies; owned audit prep, earning ISO 27001, GDPR, & SOC2 certs in an exceptional 2-month period.
The compliance & scaled infra led to $300M in revenue, onboarding 5 enterprise clients & 9 strategic partnerships.
Carried out company wide threat modeling (STRIDE), remediated 13 vulnerabilities, implemented 19 security controls.
Single-handedly deployed blockchain validators with 100% uptime, providing 24/7 On-Call support without any rotation.
Nebctl (Ansible | Python | PKI | Firewalls | IPTables | DNS | RBAC | Postman)
Led development of open source enterprise mesh-based VPN network, deployed solution at scale.
Cut down hosting costs, network load, compute requirements exponentially, while eliminating single points of failure.
Developed GUIs, CLIs & system daemons for seamless deployment & management of endpoints.
Leveraged encryption systems like AES-256 & TLS 1.3 to deliver end to end encryption throughout the network.
PART TIME
George Washington University |Student Security Specialist 3
Incident Response | SIEM | Azure | Nessus | Tenable | IDAM | EDR | Wireshark | NIST
Worked as a key SOC member while a student at GWU. responded to security incidents across a 30,000+ user network.
Automated email incident response with SOAR Playbooks (Splunk), reducing response time by 400% organization wide.
Leveraged platforms like Cisco Email Security appliance (ESA), Palo alto firewall, Google vault, AWS, Microsoft Azure,
VirusTotal, facilitating organization wide, end to end, accurate & quick Incident response.
CDAC | Cyber Security Intern 
Python | GDB | QEMU | LLVM | C/C++ | Assembly | RFC 7826 | Wireshark | Nmap
Implemented protocol (RTSP) for IoT honeypot, which was deployed nationwide to detect firmware based attacks.
Analyzed nationwide network traffic data from honeypots, contributing to early detection of latest malware.
Optimized sandbox environment by automating dynamic malware analysis. Slashing analysis time by a factor of 8.
Conducted hybrid analysis of botnet malware (Mirai) targeting UNIX based IoT devices on ARM architecture CPUs.
The robotics club of VIT | Advisory Board member 
Arduino | IoT Security | Embedded C | Ethical hacking | Kali Linux | Bash
Balanced nighttime lab work with daytime academics, rising from member to advisory board member within 3 years.
Headed the Cyber Security Department of the club, providing leadership & mentorship to department members.
Orchestrated team efforts to execute successful events, including Hackathons, workshops, robowars, & charity events.
Contributed significantly to team-based research & development projects, actively participating in collaborative efforts.
EDUCATION
The George Washington University, Washington DC 
MS in Cyber Security
Vellore Institute of Technology, Vellore, India 
B.Tech in Computer Science & Engineering
CERTIFICATIONS & ACHIEVEMENTS
CompTIA Security+ 
AWS Certified Cloud Practitioner 
Certified Ethical Hacker (CEHv11) by EC-Council 
Entrepreneurship track & Capture the Flag (CTF) winner at HackPSU 2025 (Pennsylvania State University).
Best Robotics & IOT hack in Access denied hackathon.
Best hardware hack team in Win Hacks Hackathon.
Title winner team in Robowars 2021 at Parul University.
PROJECTS
Audio Streaming Protocol with OAuth Authentication
Python | Auth0 | Cloudflare DDNS | Sockets | Flask | SHA 256
Designed an application layer protocol that controls audio streaming from scratch.
Implemented authentication server (OAuth, AES-256-GCM, PBKDF) and deployed on my doorbell camera.
Created a proprietary 16-bit character encoding scheme for control headers in a custom packet design.
Capture the Flag (CTF) Website (JavaScript | HTML | CSS)
Showcased an array of cybersecurity challenges designed for users to solve & enhance their skills.
Developed for users to improve their web, cryptography, Reverse Engineering & OSINT skills.
self-hosted using Cloudflare DDNS (dynamic DNS) for DHCP address resolution running on a Raspberry Pi.
Cybersecurity Writeups & Articles
Penetration Testing | Bug Bounty | Port Forwarding | Linux Ricing | Github | Markdown
Authored comprehensive write-ups for my CEH preparation, providing valuable resources for others.
Documented walkthroughs for TryHackMe challenges, offering optimal solutions for challenging problems.
Published trending blogs on cybersecurity related issues I was facing & how I solved them on medium.com.
SKILLS
Security Operations: Incident Response | Compliance | SIEM (Splunk) | IDS/IPS | Firewalls | Cisco ESA | Palo Alto
Networking & Security: HTTP/S | TCP/IP | TLS/SSL | BGP | Penetration Testing | Risk Assessment & Mitigation | Threat
Modeling (STRIDE) | Cryptography | Reverse Engineering | Nmap | Wireshark | Burpsuite | VPNs | OWASP top 10
Programming & Automation: Python | Flask | Infrastructure as Code | Bash | Rust | Java | Git/GitHub | Assembly | C/C++
| Ansible | Node.js | JavaScript | Kubernetes | Terraform | GCP
Cloud & DevOps: AWS | Azure | Docker | Proxmox | Prometheus | Grafana | Virtualisation | Containerization | Emulation |
High Availability Infrastructures | DDNS | Cloudflare | CI/CD
Databases & Infrastructure: SQL | MongoDB | Firebase
Miscellaneous: Generative AI | LLMs | Blockchain | Agentic AI | Linux | Microsoft Office | Google Suite
Soft Skills: Leadership | Problem-Solving | Public Speaking | Technical Documentation | Communication
"""
# =====================
# Search query templates
# =====================
SEARCH_QUERIES_WEBSITE = [
    "site:{domain} (About OR Company)",
    "site:{domain} (Team OR Mission OR Our Story OR Product OR Careers OR Docs)",
    "{company_name} official site about",
]
SEARCH_QUERIES_GENERIC = [
    "{company_name} official website",
    "{company_name} product page",
    "{company_name} mission",
]

# ============
# Configuration
# ============
DEFAULT_BATCH_SIZE = 500
CONCURRENCY = 8
CACHE_FILE = "company_cache.json"
TIMEOUT_SECS = 45

TAVILY_SEARCH_URL  = "https://api.tavily.com/search"
TAVILY_EXTRACT_URL = "https://api.tavily.com/extract"
OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"  # Responses API

# =====
# Utils
# =====

def _extract_output_text(data: Dict[str, Any]) -> str:
    # Fast path: convenience field when available
    t = data.get("output_text")
    if isinstance(t, str) and t.strip():
        return t.strip()

    # Fallback: walk the structured output
    texts: List[str] = []
    for item in data.get("output", []):
        if item.get("type") == "message":
            for part in item.get("content", []):
                if part.get("type") in ("output_text", "summary_text", "text"):
                    txt = part.get("text") or ""
                    if isinstance(txt, str) and txt.strip():
                        texts.append(txt.strip())
    return "\n".join(texts).strip()


def normalize_domain(website: str) -> Optional[str]:
    if not isinstance(website, str) or not website.strip():
        return None
    w = website.strip()
    if not w.startswith("http"):
        w = "http://" + w
    try:
        netloc = urlparse(w).netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc or None
    except Exception:
        return None

def safe_company_key(website: Optional[str], name: Optional[str]) -> Optional[str]:
    d = normalize_domain(website) if website else None
    if d:
        return f"domain:{d}"
    if isinstance(name, str) and name.strip():
        return f"name:{re.sub(r'\s+', ' ', name.strip().lower())}"
    return None

def truncate_to_words(text: str, max_words: int) -> str:
    tokens = (text or "").split()
    if len(tokens) <= max_words:
        return (text or "").strip()
    return " ".join(tokens[:max_words]).strip()

def compress_text(s: str, max_chars: int = 1400) -> str:
    s = re.sub(r"\s+", " ", s or "").strip()
    return s[:max_chars]

# =====
# Cache
# =====
def load_cache(path: str) -> Dict[str, Any]:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_cache(path: str, data: Dict[str, Any]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

# ==============================
# Quota / rate-limit detection
# ==============================
class QuotaExhausted(RuntimeError):
    pass

# ---- ADDED: differentiate rate limit vs quota + multi-key rotation ----
class RateLimited(BaseException):
    """Use BaseException so it isn't swallowed by 'except Exception' in main loop."""
    pass

TAVILY_KEYS: List[str] = []
CURRENT_TAVILY_KEY_IDX: int = 0

def _discover_tavily_keys() -> List[str]:
    """Collect numbered Tavily keys from env: TAVILY_API_KEY_1..N (or _0..N). If none, use base."""
    keys: List[Tuple[int, str]] = []
    for k, v in os.environ.items():
        m = re.fullmatch(r"TAVILY_API_KEY_(\d+)", k)
        if m and isinstance(v, str) and v.strip():
            keys.append((int(m.group(1)), v.strip()))
    if keys:
        keys.sort(key=lambda x: x[0])
        return [v for _, v in keys]
    base = (os.environ.get("TAVILY_API_KEY") or "").strip()
    return [base] if base else []

def _classify_tavily_error(status: int, body_text: str) -> str:
    t = (body_text or "").lower()
    if status == 429 or "rate limit" in t or "too many requests" in t:
        return "rate_limit"
    # treat plan/usage/upgrade messages and 402/403/432 as quota
    if (status in (402, 403, 432)) or any(x in t for x in [
        "insufficient_quota", "quota exceeded", "over your current quota",
        "payment required", "out of credits", "no credits", "insufficient balance",
        "exceeds your plan", "plan's set usage limit", "upgrade your plan"
    ]):
        return "quota"
    return "other"

def _current_tavily_key() -> str:
    if not TAVILY_KEYS:
        return ""
    return TAVILY_KEYS[CURRENT_TAVILY_KEY_IDX]

def _advance_tavily_key() -> bool:
    global CURRENT_TAVILY_KEY_IDX
    if not TAVILY_KEYS:
        return False
    if CURRENT_TAVILY_KEY_IDX + 1 < len(TAVILY_KEYS):
        CURRENT_TAVILY_KEY_IDX += 1
        return True
    return False
# ----------------------------------------------------------------------

def looks_like_quota(status: int, body_text: str) -> bool:
    t = (body_text or "").lower()
    return (
        status in (402, 403, 429, 432) or
        any(k in t for k in [
            "insufficient_quota", "quota exceeded", "over your current quota",
            "rate limit", "too many requests", "payment required",
            "out of credits", "no credits", "insufficient balance",
            "exceeds your plan", "plan's set usage limit", "upgrade your plan"
        ])
    )

# ===========================
# Tavily (Search + Extract)
# ===========================
async def tavily_search(session: aiohttp.ClientSession, api_key: str, query: str, company_tag: str, debug: bool = False) -> Dict[str, Any]:
    payload = {
        "api_key": api_key,
        "query": query,
        "search_depth": "advanced",
        "max_results": 5,
        "include_answer": False,
    }
    if debug:
        print(f"\n[DEBUG] Tavily query: {query}")
        print(f"\n[DEBUG] --- RAW REQUEST to {TAVILY_SEARCH_URL} ---")
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        _log_json(os.path.join(LOG_DIR, f"{company_tag}.tavily.search.request.json"), payload, True)

    # ---- MODIFIED: rotate on quota, stop on rate limit ----
    while True:
        use_key = _current_tavily_key()
        payload["api_key"] = use_key
        async with session.post(TAVILY_SEARCH_URL, json=payload, timeout=TIMEOUT_SECS) as resp:
            txt = await resp.text()
            if debug:
                print(f"\n[DEBUG] --- RAW RESPONSE from {TAVILY_SEARCH_URL} ---")
                print(txt)
            if resp.status != 200:
                kind = _classify_tavily_error(resp.status, txt)
                if kind == "rate_limit":
                    raise RateLimited("Tavily rate limited.")
                if kind == "quota":
                    advanced = _advance_tavily_key()
                    if debug:
                        nxt = _current_tavily_key() if advanced else "(none)"
                        print(f"[DEBUG] Tavily quota exhausted; switching={advanced}, new_key={nxt}")
                    if advanced:
                        continue
                    raise QuotaExhausted("All Tavily API keys exhausted.")
                if looks_like_quota(resp.status, txt):
                    raise QuotaExhausted("Tavily quota exhausted or rate limited.")
                resp.raise_for_status()
            data = json.loads(txt)
            break
    # -------------------------------------------------------

    _log_json(os.path.join(LOG_DIR, f"{company_tag}.tavily.search.response.json"), data, debug)

    if debug:
        results = data.get("results") or []
        print("[DEBUG] Tavily results:")
        for i, r in enumerate(results, 1):
            title = r.get("title") or ""
            url = r.get("url") or ""
            snippet = r.get("content") or r.get("snippet") or ""
            print(f"  {i}. {title} — {url}")
            if snippet:
                short = snippet[:220] + ("..." if len(snippet) > 220 else "")
                print(f"     {short}")
    return data

async def tavily_extract(session: aiohttp.ClientSession, api_key: str, urls: List[str], company_tag: str, debug: bool = False) -> Dict[str, Any]:
    payload = {"api_key": api_key, "urls": urls}
    if debug:
        print(f"[DEBUG] Tavily extract URLs: {urls}")
        print(f"\n[DEBUG] --- RAW REQUEST to {TAVILY_EXTRACT_URL} ---")
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        _log_json(os.path.join(LOG_DIR, f"{company_tag}.tavily.extract.request.json"), payload, True)

    # ---- MODIFIED: rotate on quota, stop on rate limit ----
    while True:
        use_key = _current_tavily_key()
        payload["api_key"] = use_key
        async with session.post(TAVILY_EXTRACT_URL, json=payload, timeout=TIMEOUT_SECS) as resp:
            txt = await resp.text()
            if debug:
                print(f"\n[DEBUG] --- RAW RESPONSE from {TAVILY_EXTRACT_URL} ---")
                print(txt)
            if resp.status != 200:
                kind = _classify_tavily_error(resp.status, txt)
                if kind == "rate_limit":
                    raise RateLimited("Tavily rate limited.")
                if kind == "quota":
                    advanced = _advance_tavily_key()
                    if debug:
                        nxt = _current_tavily_key() if advanced else "(none)"
                        print(f"[DEBUG] Tavily quota exhausted; switching={advanced}, new_key={nxt}")
                    if advanced:
                        continue
                    raise QuotaExhausted("All Tavily API keys exhausted.")
                if looks_like_quota(resp.status, txt):
                    raise QuotaExhausted("Tavily quota exhausted or rate limited.")
                resp.raise_for_status()
            data = json.loads(txt)
            break
    # -------------------------------------------------------

    _log_json(os.path.join(LOG_DIR, f"{company_tag}.tavily.extract.response.json"), data, debug)

    if debug:
        bodies = data.get("results", [])
        print(f"[DEBUG] Extracted {len(bodies)} pages.")
    return data

def pick_about_urls(search_json: Dict[str, Any], company_domain: Optional[str]) -> List[str]:
    """
    Choose About-like URLs; if none, fall back to the homepage on the same domain.
    Skip LinkedIn (often blocked -> empty extract).
    """
    results = search_json.get("results") or []
    about_like = []
    homepage_candidate = None

    for r in results:
        url_raw = r.get("url") or ""
        url = url_raw.lower()
        title = (r.get("title") or "").lower()
        if not url:
            continue
        if "linkedin.com" in url:
            continue  # skip

        # record homepage candidate on same domain
        if company_domain and company_domain in url:
            parsed = urlparse(url_raw)
            if parsed.netloc and (parsed.path in ("", "/")):
                homepage_candidate = url_raw

        # about-like
        if company_domain and company_domain in url and any(k in url for k in ["about", "company", "team", "mission"]):
            about_like.append(url_raw)
        elif any(k in url for k in ["about", "company", "mission"]) or "about" in title:
            about_like.append(url_raw)

    if not about_like and homepage_candidate:
        about_like.append(homepage_candidate)

    # Dedup preserve order
    seen, out = set(), []
    for u in about_like:
        if u not in seen:
            out.append(u)
            seen.add(u)
    return out[:2]

# ===========================
# OpenAI (Responses API)
# ===========================
async def openai_generate(session: aiohttp.ClientSession, api_key: str, model: str,
                          company_name: str, about_text: str, domain: Optional[str],
                          company_tag: str, debug: bool = False) -> Tuple[str, str]:
    system = (
        "You write two concise, humble outreach sentences for a cold email to a company."
        "\n take context from my profile & the company details. Try to explain Intention and alignment with the goals and work of the company using my experiences and/or relavant skillset. Try to inculcate the fact that I am looking for a growth, scale, development etc oriented company. Try to express how I can contribute to the success of the company. project what results/success my actions would bring to the company. keep each line under 20 words. Stay kind & humble. Do not come across as overconfident or cocky."
    )

    user_prompt = f"""
My profile:
{PROFILE_PROMPT.strip()}

Company: {company_name}
Website domain: {domain or "N/A"}

About text (may be empty):
{about_text[:1100]}

Write the final output:
Line 1: specific quality that is unique & impressive, start sentence with "I'm impressed by", including something specific about the company that shows effort and research.
Line 2: how I can help, start with "I'd love to", mentioning tangible benefit(s). It should be relevant to the company. At least 1 benefit should be related to cybersecurity. Rest may be related to any other skill/experience or cybersecurity if required. 

Rules:
- Exactly two lines.
- Each ≤20 words.
- Kind, humble, concrete.
- no emojis, no exclamation marks.
"""

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "input": [
            {"role": "system", "content": [{"type": "input_text", "text": system}]},
            {"role": "user", "content": [{"type": "input_text", "text": user_prompt}]}
        ],
        "temperature": 1,
        "reasoning": {"effort": "low"}, 
        "max_output_tokens": 1500
    }

    if debug:
        print("\n[DEBUG] Responses prompt:\n" + "-"*60)
        print("SYSTEM:\n" + system + "\n")
        print("USER:\n" + user_prompt)
        print("-"*60)
        _log_json(os.path.join(LOG_DIR, f"{company_tag}.openai.responses.request.json"), payload, True)
        print(f"\n[DEBUG] --- RAW REQUEST to {OPENAI_RESPONSES_URL} ---")
        print(json.dumps(payload, indent=2, ensure_ascii=False))

    async with session.post(OPENAI_RESPONSES_URL, headers=headers, json=payload, timeout=TIMEOUT_SECS) as resp:
        txt = await resp.text()
        if debug:
            print(f"\n[DEBUG] --- RAW RESPONSE from {OPENAI_RESPONSES_URL} ---")
            print(txt)
        if resp.status != 200:
            if looks_like_quota(resp.status, txt):
                raise QuotaExhausted("OpenAI quota exhausted or rate limited.")
            resp.raise_for_status()
        data = json.loads(txt)
        raw = _extract_output_text(data)


    _log_json(os.path.join(LOG_DIR, f"{company_tag}.openai.responses.response.json"), data, debug)

    # Prefer convenience field if present
    # raw = data.get("output_text") or ""
    if not raw:
        # Fallback to first output message text
        try:
            raw = (data.get("output") or [])[0].get("content", [])[0].get("text", "") or ""
        except Exception:
            raw = ""

    if debug:
        print("\n[DEBUG] Raw Responses output:\n" + "-"*60)
        print(raw)
        print("-"*60)

    # Parse exactly two lines
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if len(lines) < 2:
        parts = re.split(r"[\.!\?]\s+", raw)
        parts = [p.strip() for p in parts if p.strip()]
        lines = [parts[0] if parts else "", parts[1] if len(parts) > 1 else ""]

    def clip(s: str) -> str:
        return " ".join((s or "").split()[:20]).strip()

    return clip(lines[0]), clip(lines[1] if len(lines) > 1 else "")

# ======
# Worker
# ======
async def fetch_company_about(session: aiohttp.ClientSession,
                              tavily_key: str,
                              company_name: str,
                              website: Optional[str],
                              company_tag: str,
                              debug: bool = False) -> Tuple[str, List[str], Optional[str]]:
    domain = normalize_domain(website) if website else None

    # Build search queries
    queries: List[str] = []
    if domain:
        queries += [q.format(company_name=company_name, domain=domain) for q in SEARCH_QUERIES_WEBSITE]
        queries.append(f"{company_name} {domain} homepage")
    queries += [q.format(company_name=company_name, domain=domain or "") for q in SEARCH_QUERIES_GENERIC]
    queries += [
        f"site:linkedin.com {company_name} about",
        f"site:crunchbase.com {company_name}",
        f"site:wikipedia.org {company_name}"
    ]

    about_urls = []
    # Search until we find at least 3 relevant URLs
    for q in queries:
        sres = await tavily_search(session, tavily_key, q, company_tag, debug=debug)
        about_urls.extend(pick_about_urls(sres, domain))
        if len(about_urls) >= 3:
            break

    if not about_urls and domain:
        about_urls = [f"http://{domain}"]

    urls_to_extract = list(dict.fromkeys(about_urls[:3]))  # up to 3 pages
    extracted_texts, source_urls = [], []

    if urls_to_extract:
        eres = await tavily_extract(session, tavily_key, urls_to_extract, company_tag, debug=debug)
        for r in eres.get("results", []):
            content = r.get("content") or r.get("extracted_content") or ""
            if content:
                extracted_texts.append(content.strip())
                source_urls.append(r.get("url") or "")

    # Merge & clean
    merged_text = " ".join(extracted_texts)
    merged_text = re.sub(r"\s+", " ", merged_text).strip()

    if not merged_text:
        if debug:
            print("[DEBUG] No extracted content found.")
        return "", source_urls, domain

    # Summarize to keep high-value details before feeding to GPT
    summary_prompt = f"""
    Summarize the following company information into a concise 8–10 bullet points,
    prioritizing: mission, product, customers, growth, technology stack, scale, and market.
    Ignore fluff and marketing language. Keep it factual.

    --- COMPANY CONTENT START ---
    {merged_text[:6000]}  # limit to ~6k chars for safety
    --- COMPANY CONTENT END ---
    """

    headers = {"Authorization": f"Bearer {(os.environ.get('OPENAI_API_KEY') or '').strip()}", "Content-Type": "application/json"}
    payload = {
        "model": MODEL_SUMMARY,
        "input": [
            {"role": "system", "content": [{"type": "input_text", "text": "You are a concise summarizer for lead enrichment."}]},
            {"role": "user", "content": [{"type": "input_text", "text": summary_prompt}]}
        ],
        "temperature": 1,
        "reasoning": {"effort": "low"}, 
        "max_output_tokens": 1500
    }

    if debug:
        _log_json(os.path.join(LOG_DIR, f"{company_tag}.openai.responses.summary.request.json"), payload, True)
        print(f"\n[DEBUG] --- RAW REQUEST to {OPENAI_RESPONSES_URL} (summarization) ---")
        print(json.dumps(payload, indent=2, ensure_ascii=False))

    async with session.post(OPENAI_RESPONSES_URL, headers=headers, json=payload, timeout=TIMEOUT_SECS) as resp:
        txt = await resp.text()
        if debug:
            print(f"\n[DEBUG] --- RAW RESPONSE from {OPENAI_RESPONSES_URL} (summarization) ---")
            print(txt)
        if resp.status != 200:
            resp.raise_for_status()
        summary_data = json.loads(txt)
        about_summary = _extract_output_text(summary_data)


    # about_summary = summary_data.get("output_text") or ""
    if not about_summary:
        try:
            about_summary = (summary_data.get("output") or [])[0].get("content", [])[0].get("text", "") or ""
        except Exception:
            about_summary = ""

    if debug:
        print("\n[DEBUG] Merged about text length:", len(merged_text))
        print("[DEBUG] Summarized context for GPT input:\n", about_summary)

    return about_summary, source_urls, domain


async def process_one(company_row: Dict[str, Any],
                      session: aiohttp.ClientSession,
                      tavily_key: str,
                      openai_key: str,
                      model: str,
                      cache: Dict[str, Any],
                      force_refresh: bool = False,
                      debug: bool = False) -> Dict[str, Any]:
    name = (company_row.get("Company name") or "").strip()
    website = company_row.get("Website") or ""
    tag = _safe_name(name or website)

    key = safe_company_key(website, name)
    if not key:
        return {"personalized_1": "", "personalized_2": "", "sources": ""}

    if key in cache and not force_refresh:
        cached = cache[key]
        s1, s2 = cached.get("s1", ""), cached.get("s2", "")
        srcs = "; ".join(cached.get("sources", []))
        if debug:
            print(f"\n[DEBUG] Cache hit for {name} ({key})")
            print(f"  S1: {s1}\n  S2: {s2}\n  Sources: {srcs}")
        return {"personalized_1": s1, "personalized_2": s2, "sources": srcs}

    about_text, sources, domain = await fetch_company_about(session, tavily_key, name, website, tag, debug=debug)
    s1, s2 = await openai_generate(session, openai_key, MODEL_SENTENCE, name, about_text, domain, tag, debug=debug)


    cache[key] = {"s1": s1, "s2": s2, "sources": sources}
    if debug:
        print(f"\n[DEBUG] Final sentences for {name}:")
        print(f"  1. {s1}")
        print(f"  2. {s2}")
        print(f"  Sources: {'; '.join(sources)}")
    return {"personalized_1": s1, "personalized_2": s2, "sources": "; ".join(sources)}

# =====
# Main
# =====
async def main_async(args):
    # ---- MODIFIED: discover & initialize Tavily keys from .env as numbered variables ----
    global TAVILY_KEYS, CURRENT_TAVILY_KEY_IDX
    TAVILY_KEYS = _discover_tavily_keys()
    if not TAVILY_KEYS:
        raise SystemExit("Missing TAVILY_API_KEY")
    CURRENT_TAVILY_KEY_IDX = 0
    tavily_key = _current_tavily_key()
    # -----------------------------------------------------------------------

    openai_key = (os.environ.get("OPENAI_API_KEY") or "").strip()
    if not openai_key:
        raise SystemExit("Missing OPENAI_API_KEY")

    model = args.model
    debug_mode = args.test is not None

    df = pd.read_csv(args.input_csv)
    for col in ["personalized_1", "personalized_2", "sources"]:
        if col not in df.columns:
            df[col] = ""

    mask = df["personalized_1"].astype(str).str.strip() == ""
    rows_to_process = df[mask]
    if args.batch_size is not None:
        rows_to_process = rows_to_process.head(args.batch_size)
    if debug_mode:
        rows_to_process = rows_to_process.head(args.test)
        print(f"[DEBUG] Running in TEST MODE for {args.test} companies")

    if rows_to_process.empty:
        print("Nothing to do; all rows already have personalized_1 (or selection is empty).")
        return

    cache = load_cache(CACHE_FILE)
    connector = aiohttp.TCPConnector(limit=CONCURRENCY)
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECS)
    wrote_path = None

    try:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for idx in rows_to_process.index:
                row = rows_to_process.loc[idx]
                try:
                    result = await process_one(
                        row.to_dict(), session, tavily_key, openai_key, model, cache,
                        force_refresh=args.force_refresh, debug=debug_mode
                    )
                except QuotaExhausted as qe:
                    print(f"[STOP] Quota exhausted: {qe}")
                    break
                except Exception as e:
                    if debug_mode:
                        print(f"[DEBUG] Error processing row {idx}: {e}")
                    result = {"personalized_1": "", "personalized_2": "", "sources": ""}

                df.at[idx, "personalized_1"] = result.get("personalized_1", "")
                df.at[idx, "personalized_2"] = result.get("personalized_2", "")
                df.at[idx, "sources"] = result.get("sources", "")

                if len(cache) % 25 == 0:
                    save_cache(CACHE_FILE, cache)

    finally:
        save_cache(CACHE_FILE, cache)
        base, ext = os.path.splitext(args.input_csv)
        out_path = base + ".personalized.csv"
        df.to_csv(out_path, index=False)
        wrote_path = out_path

    print(f"Wrote: {wrote_path}")

def parse_args():
    p = argparse.ArgumentParser(description="Dynamic, personalized 2-line outreach via Tavily About + GPT (responses), with profile context and debug logging.")
    p.add_argument("--input-csv", required=True, help="Path to input CSV.")
    p.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="Max rows to consider this run.")
    p.add_argument("--test", type=int, default=None, help="Verbose debug for X companies (prints & logs API requests/responses).")
    p.add_argument("--force-refresh", action="store_true", help="Ignore cache and call APIs again.")
    p.add_argument("--model", default=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"), help="OpenAI model (mini recommended).")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    asyncio.run(main_async(args))

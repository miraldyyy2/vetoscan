#!/usr/bin/env python3
"""Local MVP: deterministic prompt-injection screening for text and web pages."""

import argparse
import base64
import binascii
import datetime
import html
import os
import http.client
import ipaddress
import json
import re
import socket
import ssl
import unicodedata
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urljoin, urlsplit


MAX_REQUEST_BYTES = 300_000
MAX_TEXT_CHARS = 120_000
MAX_PAGE_BYTES = 1_000_000
MAX_REDIRECTS = 3
MAX_DETECTIONS = 50
REQUEST_TIMEOUT_SECONDS = 5

INVISIBLE = {
    "\u00ad", "\u034f", "\u061c", "\u115f", "\u1160", "\u17b4", "\u17b5",
    "\u180e", "\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\u202a",
    "\u202b", "\u202c", "\u202d", "\u202e", "\u2060", "\u2061", "\u2062",
    "\u2063", "\u2064", "\u2066", "\u2067", "\u2068", "\u2069", "\ufeff",
}
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    "Α": "a", "Β": "b", "Ε": "e", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n",
    "Ο": "o", "Ρ": "p", "Τ": "t", "Χ": "x", "Υ": "y",
})
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})

# The rules intentionally favor transparent, explainable matches over claims of
# comprehensive detection. Scores are priorities for review, not probabilities.
RULES = [
    # Narrowly matches the AgentDojo-style "do this first, then solve the task" priority hijack.
    ("instruction_priority_hijack", "high", 55, re.compile(
        r"\bbefore you can\b(?:\W+\w+){0,4}\W+\b(?:solve|answer|complete|finish)\b"
        r"(?:\W+\w+){0,24}\W+\btask\b(?:\W+\w+){0,14}\W+\bplease do the following first\b"
        r"[\s\S]{1,800}?\bafter you do that\b(?:\W+\w+){0,5}\W+\b(?:solve|answer|complete|finish)\b"
        r"(?:\W+\w+){0,12}", re.I)),
    ("instruction_override", "high", 55, re.compile(
        r"\b(?:ignore|disregard|forget|override|bypass|skip|игнорирай|пренебрегни|забрави|заобиколи)\b"
        r"(?:\W+\w+){0,5}\W+\b(?:all|всички|previous|prior|earlier|above|предишн\w*|по-ранни|горни|"
        r"system|developer|safety|security|системни|безопасност|сигурност)\b"
        r"(?:\W+\w+){0,4}\W+\b(?:instructions?|rules?|polic(?:y|ies)|guardrails?|filters?|"
        r"инструкции|указания|правила|защити|филтри)\b", re.I)),
    ("role_hijack", "high", 45, re.compile(
        r"\b(?:(?:you are now|from now on you are|assume the role of|pretend to be)"
        r"(?:\W+\w+){0,4}\W+(?:DAN|unrestricted|jailbroken|system|developer|administrator|admin|root|assistant|agent)\b|"
        r"switch to (?:DAN|developer|unrestricted|jailbreak|jailbroken)(?:\W+\w+){0,2}\W+mode)\b|"
        r"\bact as\b(?:\W+\w+){0,2}\W+\b(?:DAN|unrestricted|jailbroken|the system|a developer|an administrator)\b", re.I)),
    ("role_hijack", "high", 45, re.compile(
        r"\b(?:сега си|отсега нататък си|престори се на)"
        r"(?:\W+\w+){0,4}\W+(?:неограничен\w*|систем\w*|разработчик\w*|администратор\w*|DAN|root|джейлбрейк\w*)\b|"
        r"\bдействай като\b(?:\W+\w+){0,2}\W+\b(?:системен|разработчик|администратор|неограничен|DAN)\b", re.I)),
    ("prompt_extraction", "high", 50, re.compile(
        r"\b(?:reveal|print|show|repeat|output|disclose|leak|dump|tell me|покажи|разкрий|изведи|повтори|изпрати)\b"
        r"(?:\W+\w+){0,7}\W+\b(?:system|developer|hidden|secret|системн\w*|скрит\w*|тайн\w*)\b"
        r"(?:\W+\w+){0,4}\W+\b(?:prompt|instructions?|message|rules?|промпт|инструкци\w*|"
        r"указани\w*|съобщени\w*)\b", re.I)),
    ("jailbreak", "high", 40, re.compile(
        r"\b(?:DAN mode|developer mode enabled|jailbreak|do anything now|"
        r"bypass (?:the )?safety filters?|disable (?:all )?safeguards?)\b", re.I)),
    ("secret_or_funds_request", "high", 55, re.compile(
        r"\b(?:send|transfer|wire|export|share|reveal|steal)\b"
        r"(?:\W+\w+){0,8}\W+\b(?:passwords?|api keys?|credentials?|private keys?|"
        r"seed phrases?|wallets?|funds?|money)\b", re.I)),
    ("secret_or_funds_request", "high", 55, re.compile(
        r"\b(?:изпрати|прехвърли|изтегли|разкрий|експортирай)\b"
        r"(?:\W+\w+){0,8}\W+\b(?:пароли|паролите|ключове|ключовете|крипто|средства|средствата|пари|данни)\b", re.I)),
    ("data_exfiltration", "high", 50, re.compile(
        r"\b(?:upload|email|send|post|exfiltrate|forward|изпрати|качни|публикувай|препрати)\b"
        r"(?:\W+\w+){0,8}\W+\b(?:files?|documents?|conversation|chat history|browser history|local data|credentials?|"
        r"парол\w*|ключ\w*|файлов\w*|документ\w*|разговор\w*|данн\w*)\b"
        r"(?:\W+\w+){0,8}\W+\b(?:https?://|webhook|external|attacker|my server|email|външ\w*|"
        r"нападател\w*|сървър\w*)\b", re.I)),
    ("data_exfiltration", "high", 50, re.compile(
        r"!\s*\[[^\]]{0,100}\]\s*\(\s*https?://[^\s)]+", re.I)),
    ("tool_misuse", "medium", 30, re.compile(
        r"\b(?:run|execute|call)\b(?:\W+\w+){0,5}\W+\b(?:shell|terminal|browser|"
        r"filesystem|file system|tool|function)\b", re.I)),
    ("template_control_token", "high", 45, re.compile(
        r"(?:<\|(?:im_start|im_sep|im_end|fim_prefix|fim_middle|fim_suffix)\|>|"
        r"\[/?INST\]|<\/?(?:system|developer|assistant)>|###\s*(?:system|developer))", re.I)),
    ("encoded_instruction", "high", 45, re.compile(
        r"\b(?:decode|base64|rot13)\b(?:\W+\w+){0,6}\W+\b(?:execute|follow|instructions?)\b", re.I)),
]
COMPACT_ATTACKS = [
    ("ignoreallpreviousinstructions", "instruction_override", 55),
    ("disregardallpreviousinstructions", "instruction_override", 55),
    ("ignoreallpriorinstructions", "instruction_override", 55),
    ("revealthesystemprompt", "prompt_extraction", 50),
    ("showthesystemprompt", "prompt_extraction", 50),
    ("printthesystemprompt", "prompt_extraction", 50),
    ("игнорирайпредишнитеинструкции", "instruction_override", 55),
    ("покажисистемнияпромпт", "prompt_extraction", 50),
    ("разкрийскрититеинструкции", "prompt_extraction", 50),
]


class ScanError(Exception):
    def __init__(self, status, code, message):
        Exception.__init__(self, message)
        self.status = status
        self.code = code
        self.message = message


def _html_unescape_with_map(text):
    """Decode entities while retaining source offsets for evidence and redaction."""
    output, offsets, cursor = [], [], 0
    entity = re.compile(r"&(?:#[0-9]+|#x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]+);?")
    for match in entity.finditer(text):
        for index in range(cursor, match.start()):
            output.append(text[index])
            offsets.append(index)
        decoded = html.unescape(match.group(0))
        if decoded == match.group(0):
            for index in range(match.start(), match.end()):
                output.append(text[index])
                offsets.append(index)
        else:
            for char in decoded:
                output.append(char)
                offsets.append(match.start())
        cursor = match.end()
    for index in range(cursor, len(text)):
        output.append(text[index])
        offsets.append(index)
    return "".join(output), offsets


def _normalize(text, source_offsets):
    chars, offsets = [], []
    for token_match in re.finditer(r"\w+|\W+", text, re.UNICODE):
        token = token_match.group(0)
        has_ascii = any(char.isascii() and char.isalpha() for char in token)
        has_non_latin = any("\u0400" <= char <= "\u052f" or "\u0370" <= char <= "\u03ff" for char in token)
        mixed_script = has_ascii and has_non_latin
        for relative_index, char in enumerate(token):
            source_index = source_offsets[token_match.start() + relative_index]
            folded = unicodedata.normalize("NFKC", char).casefold()
            if mixed_script:
                folded = folded.translate(CONFUSABLES)
            for item in folded:
                if item in INVISIBLE:
                    continue
                item = item.translate(LEET)
                chars.append(item)
                offsets.append(source_index)
    normalized = "".join(chars)

    # Collapse phrases written with a space between every character, e.g.
    # "i g n o r e a l l ...", without losing the original span mapping.
    spaced = re.compile(r"\b(?:[a-z0-9]\s+){3,}[a-z0-9]\b", re.I)
    out_chars, out_offsets, cursor = [], [], 0
    for match in spaced.finditer(normalized):
        if match.start() > cursor:
            out_chars.extend(normalized[cursor:match.start()])
            out_offsets.extend(offsets[cursor:match.start()])
        for index in range(match.start(), match.end()):
            if normalized[index].isalnum():
                out_chars.append(normalized[index])
                out_offsets.append(offsets[index])
        cursor = match.end()
    out_chars.extend(normalized[cursor:])
    out_offsets.extend(offsets[cursor:])
    return "".join(out_chars), out_offsets


def _merge_matches(matches):
    matches.sort(key=lambda item: (item["start"], item["end"], item["category"]))
    merged = []
    for item in matches:
        if merged and item["start"] < merged[-1]["end"]:
            if item["category"] not in merged[-1]["categories"]:
                merged[-1]["categories"].append(item["category"])
            merged[-1]["end"] = max(merged[-1]["end"], item["end"])
            merged[-1]["severity"] = "high" if "high" in (merged[-1]["severity"], item["severity"]) else "medium"
            merged[-1]["score"] = max(merged[-1]["score"], item["score"])
        else:
            merged.append({
                "start": item["start"], "end": item["end"],
                "categories": [item["category"]], "severity": item["severity"], "score": item["score"],
            })
    return merged


EMAIL_SEND_COMMAND = re.compile(
    r"\b(?:send|issue|trigger|call)\b(?:\W+\w+){0,10}\W+\b(?:email|mail|api_call)\b", re.I
)
EMAIL_ACTION_START = re.compile(r"\b(?:send|email)\b", re.I)
EMAIL_ADDRESS = re.compile(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", re.I)
EMAIL_BODY_MARKER = re.compile(r"\b(?:body|content|confirmation)\b", re.I)


def _email_action_hits(normalized):
    """Flag explicit email side effects in untrusted text without inferring intent."""
    hits = []
    for match in EMAIL_SEND_COMMAND.finditer(normalized):
        end = match.end()
        window_end = min(len(normalized), end + 500)
        boundary = re.search(r"[.!?](?=\s+[a-z<\"']|\s*$)|\n{2,}", normalized[end:window_end])
        if boundary:
            end += boundary.end()
        hits.append({
            "start": match.start(), "end": end, "category": "untrusted_email_action",
            "severity": "medium", "score": 30,
        })

    for match in EMAIL_ACTION_START.finditer(normalized):
        window_end = min(len(normalized), match.start() + 300)
        window = normalized[match.start():window_end]
        address = EMAIL_ADDRESS.search(window)
        body_marker = EMAIL_BODY_MARKER.search(window)
        if address and body_marker:
            end = match.start() + max(address.end(), body_marker.end())
            hits.append({
                "start": match.start(), "end": end, "category": "untrusted_email_action",
                "severity": "medium", "score": 30,
            })
    return hits


def _rule_hits(normalized):
    hits = []
    for category, severity, score, pattern in RULES:
        for match in pattern.finditer(normalized):
            hits.append({
                "start": match.start(), "end": match.end(), "category": category,
                "severity": severity, "score": score,
            })
    for phrase, category, score in COMPACT_ATTACKS:
        for match in re.finditer(re.escape(phrase), normalized, re.I):
            hits.append({
                "start": match.start(), "end": match.end(), "category": category,
                "severity": "high", "score": score,
            })
    hits.extend(_email_action_hits(normalized))
    return hits


def _scan_base64(text, source_offsets):
    hits = []
    for match in re.finditer(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])", text):
        candidate = match.group(0)
        try:
            decoded = base64.b64decode(candidate + "=" * ((-len(candidate)) % 4), validate=True)
            decoded_text = decoded.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if not decoded_text or sum(char.isprintable() or char.isspace() for char in decoded_text) / float(len(decoded_text)) < 0.85:
            continue
        decoded_offsets = list(range(len(decoded_text)))
        decoded_normalized, unused_offsets = _normalize(decoded_text, decoded_offsets)
        if not _rule_hits(decoded_normalized):
            continue
        start = min(source_offsets[match.start():match.end()])
        end = max(source_offsets[match.start():match.end()]) + 1
        hits.append({"start": start, "end": end, "category": "encoded_payload", "severity": "high", "score": 60})
    return hits


def scan_text(text, source_type="text", source_url=None):
    if not isinstance(text, str):
        raise ScanError(400, "invalid_text", "text must be a string")
    if len(text) > MAX_TEXT_CHARS:
        raise ScanError(413, "text_too_large", "text exceeds the 120,000 character limit")
    decoded, entity_offsets = _html_unescape_with_map(text)
    normalized, offsets = _normalize(decoded, entity_offsets)
    normalized_hits = _rule_hits(normalized)
    mapped_hits = []
    for hit in normalized_hits:
        if hit["start"] >= len(offsets) or hit["end"] <= hit["start"]:
            continue
        start = min(offsets[hit["start"]:hit["end"]])
        end = max(offsets[hit["start"]:hit["end"]]) + 1
        mapped_hits.append({
            "start": start, "end": end, "category": hit["category"],
            "severity": hit["severity"], "score": hit["score"],
        })
    mapped_hits.extend(_scan_base64(decoded, entity_offsets))
    merged = _merge_matches(mapped_hits)

    detections = []
    for item in merged[:MAX_DETECTIONS]:
        evidence = text[item["start"]:item["end"]].strip()
        detections.append({
            "categories": item["categories"],
            "severity": item["severity"],
            "evidence": evidence[:500],
            "offset": {"start": item["start"], "end": item["end"]},
        })

    score = min(100, sum(item["score"] for item in merged))
    if any(item["severity"] == "high" for item in merged) or score >= 70:
        verdict, risk = "pattern_detected", "high"
    elif score >= 25:
        verdict, risk = "suspicious", "medium"
    else:
        verdict, risk = "no_known_pattern", "low"

    sanitized = text
    for item in reversed(merged):
        sanitized = sanitized[:item["start"]] + "[REDACTED: possible prompt injection]" + sanitized[item["end"]:]

    result = {
        "schema_version": "1.0",
        "verdict": verdict,
        "risk": risk,
        "risk_score": score,
        "score_note": "A deterministic review-priority score, not a probability.",
        "detections": detections,
        "detection_count": len(merged),
        "detections_truncated": len(merged) > MAX_DETECTIONS,
        "sanitized_text": sanitized,
        "source": {"type": source_type},
        "limitations": [
            "Heuristic rules can miss novel, indirect, multimodal, or context-dependent attacks.",
            "no_known_pattern does not mean safe; review before giving content to a privileged agent.",
            "A match indicates a known pattern, not proven malicious intent; quoted security examples may be flagged.",
            "Requests inside untrusted content to send an email may be flagged as suspicious even when legitimate.",
            "Redaction only removes matched spans and is not a security boundary.",
        ],
    }
    if source_url:
        result["source"]["url"] = source_url
    return result


class VisibleTextParser(HTMLParser):
    IGNORE = {"script", "style", "noscript", "svg", "iframe", "template"}
    TEXT_ATTRIBUTES = {"alt", "title", "aria-label"}

    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.parts = []
        self.ignored = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in self.IGNORE:
            self.ignored += 1
        if self.ignored == 0:
            for name, value in attrs:
                if name.lower() in self.TEXT_ATTRIBUTES and value:
                    self.parts.append(" ")
                    self.parts.append(value)
                    self.parts.append(" ")

    def handle_endtag(self, tag):
        if tag.lower() in self.IGNORE and self.ignored:
            self.ignored -= 1

    def handle_data(self, data):
        if self.ignored == 0 and data.strip():
            self.parts.append(data)
            self.parts.append(" ")


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a DNS-validated IP while preserving TLS hostname verification."""

    def __init__(self, host, port, address):
        http.client.HTTPSConnection.__init__(
            self, host, port=port, timeout=REQUEST_TIMEOUT_SECONDS, context=ssl.create_default_context()
        )
        self.address = address

    def connect(self):
        raw = socket.create_connection((self.address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def _validated_target(url):
    if not isinstance(url, str) or len(url) > 2048:
        raise ScanError(400, "invalid_url", "url must be a public HTTPS URL under 2,048 characters")
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ScanError(400, "invalid_url", "only public HTTPS URLs are accepted")
    if parsed.username or parsed.password:
        raise ScanError(400, "invalid_url", "URLs containing credentials are not accepted")
    try:
        port = parsed.port or 443
    except ValueError:
        raise ScanError(400, "invalid_url", "invalid URL port")
    if port != 443:
        raise ScanError(400, "invalid_url", "only HTTPS port 443 is accepted")
    host = parsed.hostname.rstrip(".").lower()
    try:
        literal_ip = ipaddress.ip_address(host)
        addresses = [str(literal_ip)]
    except ValueError:
        try:
            records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            addresses = list(dict.fromkeys(record[4][0] for record in records))
        except socket.gaierror:
            raise ScanError(400, "url_unresolvable", "the URL host could not be resolved")
    if not addresses:
        raise ScanError(400, "url_unresolvable", "the URL host has no usable addresses")
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            raise ScanError(400, "url_rejected", "the URL resolved to an invalid address")
        if not ip.is_global:
            raise ScanError(400, "url_rejected", "private, local, and reserved network addresses are blocked")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return host, port, addresses[0], path


def fetch_page_text(url):
    current = url
    for redirect_count in range(MAX_REDIRECTS + 1):
        host, port, address, path = _validated_target(current)
        connection = PinnedHTTPSConnection(host, port, address)
        try:
            connection.request("GET", path, headers={
                "Host": host,
                "User-Agent": "VetoScan-MVP/0.1 (+local user-submitted URL scan)",
                "Accept": "text/html, application/xhtml+xml, text/plain;q=0.9",
                "Accept-Encoding": "identity",
                "Connection": "close",
            })
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader("Location")
                if not location or redirect_count >= MAX_REDIRECTS:
                    raise ScanError(400, "redirect_limit", "the page exceeded the safe redirect limit")
                current = urljoin(current, location)
                continue
            if response.status != 200:
                raise ScanError(502, "upstream_status", "the page did not return HTTP 200")
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type not in ("text/html", "application/xhtml+xml", "text/plain"):
                raise ScanError(415, "unsupported_page_type", "only HTML and plain-text pages are supported")
            declared_length = response.getheader("Content-Length")
            if declared_length and declared_length.isdigit() and int(declared_length) > MAX_PAGE_BYTES:
                raise ScanError(413, "page_too_large", "the page exceeds the 1 MB limit")
            payload = response.read(MAX_PAGE_BYTES + 1)
            if len(payload) > MAX_PAGE_BYTES:
                raise ScanError(413, "page_too_large", "the page exceeds the 1 MB limit")
            charset = response.headers.get_content_charset() or "utf-8"
            try:
                body = payload.decode(charset, errors="replace")
            except LookupError:
                body = payload.decode("utf-8", errors="replace")
            if content_type == "text/plain":
                return body, current
            parser = VisibleTextParser()
            parser.feed(body)
            parser.close()
            return "".join(parser.parts), current
        except ScanError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as exc:
            raise ScanError(502, "fetch_failed", "the page could not be fetched safely")
        finally:
            connection.close()
    raise ScanError(400, "redirect_limit", "the page exceeded the safe redirect limit")


def _error_payload(code, message):
    return {"error": {"code": code, "message": message}}


def process_scan_request(request):
    if not isinstance(request, dict):
        raise ScanError(400, "invalid_request", "the JSON body must be an object")
    has_text = "text" in request
    has_url = "url" in request
    if has_text == has_url:
        raise ScanError(400, "invalid_request", "provide exactly one of text or url")
    if has_text:
        return scan_text(request["text"])
    page_text, final_url = fetch_page_text(request["url"])
    return scan_text(page_text, source_type="url", source_url=final_url)


def health_payload():
    return {"ok": True, "mode": "local-development", "payments": "disabled"}


class Handler(BaseHTTPRequestHandler):
    server_version = "VetoScanLocal/0.1"

    def log_message(self, format_string, *args):
        # Avoid logging submitted text, query parameters, or source URLs.
        return

    def _send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            try:
                with open("static/index.html", "rb") as page:
                    body = page.read()
            except OSError:
                self._send_json(500, _error_payload("page_missing", "the local UI file is missing"))
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path in ("/health", "/healthz"):
            self._send_json(200, health_payload())
            return
        for route, filename, content_type in (
            ("/openapi.json", "openapi.json", "application/json; charset=utf-8"),
            ("/service.json", "service.json", "application/json; charset=utf-8"),
            ("/agent-tool.json", "agent-tool.json", "application/json; charset=utf-8"),
            ("/llms.txt", "llms.txt", "text/plain; charset=utf-8"),
        ):
            if self.path == route:
                try:
                    with open(filename, "rb") as artifact:
                        body = artifact.read()
                except OSError:
                    self._send_json(500, _error_payload("artifact_missing", "a discovery file is missing"))
                    return
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
                return
        self._send_json(404, _error_payload("not_found", "route not found"))

    def do_POST(self):
        if self.path != "/v1/scan":
            self._send_json(404, _error_payload("not_found", "route not found"))
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self._send_json(415, _error_payload("unsupported_media_type", "send application/json"))
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = MAX_REQUEST_BYTES + 1
        if length <= 0:
            self._send_json(400, _error_payload("empty_body", "a JSON request body is required"))
            return
        if length > MAX_REQUEST_BYTES:
            self._send_json(413, _error_payload("request_too_large", "the request exceeds the 300 KB limit"))
            return
        try:
            request = json.loads(self.rfile.read(length).decode("utf-8"))
            result = process_scan_request(request)
            self._send_json(200, result)
        except ScanError as exc:
            self._send_json(exc.status, _error_payload(exc.code, exc.message))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, _error_payload("invalid_json", "the request body must be valid UTF-8 JSON"))
        except Exception:
            # Keep internal error details and submitted content out of responses/logs.
            self._send_json(500, _error_payload("internal_error", "the scan could not be completed"))


def main():
    parser = argparse.ArgumentParser(description="Run the local VetoScan MVP API")
    
    default_port = int(os.environ.get("PORT", 8080))
    parser.add_argument("--port", type=int, default=default_port)
    args = parser.parse_args()
    
    if args.port < 1 or args.port > 65535:
        parser.error("--port must be between 1 and 65535")
        
    server = ThreadingHTTPServer(('0.0.0.0', args.port), Handler)
    print("VetoScan local MVP: http://0.0.0.0:{0}".format(args.port))
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    main()

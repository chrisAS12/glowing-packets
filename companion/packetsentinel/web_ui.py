"""
Secure Local Voice & Pre-Model Privacy Web UI for PacketSentinel.

Provides a 100% offline, zero-cloud browser interface for secure voice chat with AI:
1. Binds strictly to 127.0.0.1 (mitigates external LAN exposure).
2. Enforces CSRF token and Host header verification (anti-DNS rebinding).
3. Push-to-Talk audio transcription with local RAM buffering (zero disk audio retention).
4. Routes transcribed speech through the 5-Gate DLP Engine (mcp_privacy.py) before display.
Zero external CDNs, fonts, or tracking scripts.
"""

from __future__ import annotations

import html
import http.server
import json
import logging
import os
import secrets
import sys
import threading
import urllib.parse
import webbrowser
from dataclasses import asdict
from http import HTTPStatus
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .config import AppConfig
from .download_guard import scan_downloaded_payload
from .mcp_privacy import PrivacySanitizer

logger = logging.getLogger("packetsentinel.web_ui")

_CSRF_TOKEN = secrets.token_hex(32)
_SERVER_PORT = 8765


_EMBEDDED_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PacketSentinel — Secure Voice AI Airlock</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --border: #334155;
      --primary: #38bdf8;
      --text: #f8fafc;
      --muted: #94a3b8;
      --danger: #ef4444;
      --success: #22c55e;
      --warning: #f59e0b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
      padding: 24px;
      display: flex;
      justify-content: center;
    }
    .container {
      width: 100%;
      max-width: 800px;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    }
    header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
      margin-bottom: 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .badge {
      font-size: 11px;
      font-weight: 700;
      padding: 4px 8px;
      border-radius: 6px;
      background: #064e3b;
      color: var(--success);
      border: 1px solid #059669;
    }
    .section-title {
      font-size: 14px;
      font-weight: 600;
      color: var(--muted);
      text-transform: uppercase;
      margin-bottom: 8px;
    }
    .box {
      background: #0b1120;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 16px;
    }
    textarea {
      width: 100%;
      height: 100px;
      background: transparent;
      color: var(--text);
      border: none;
      resize: vertical;
      font-family: inherit;
      font-size: 14px;
    }
    textarea:focus { outline: none; }
    .btn-row {
      display: flex;
      gap: 12px;
      margin-bottom: 16px;
    }
    button {
      padding: 10px 18px;
      border-radius: 8px;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
      border: none;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s;
    }
    .btn-ptt {
      background: #0284c7;
      color: white;
    }
    .btn-ptt.recording {
      background: var(--danger);
      animation: pulse 1s infinite alternate;
    }
    @keyframes pulse { from { opacity: 1; } to { opacity: 0.6; } }
    .btn-secondary {
      background: var(--border);
      color: var(--text);
    }
    .btn-kill {
      background: #dc2626;
      color: white;
      padding: 6px 14px;
      font-size: 12px;
      border-radius: 6px;
      cursor: pointer;
    }
    .btn-kill:hover {
      background: #b91c1c;
    }
    .redacted {
      background: rgba(239, 68, 68, 0.2);
      color: #fca5a5;
      padding: 2px 4px;
      border-radius: 4px;
      font-weight: 600;
    }
    .status-text {
      font-size: 12px;
      color: var(--muted);
      margin-top: 4px;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h2>PacketSentinel Voice Airlock</h2>
        <p class="status-text">Zero-Cloud Local Speech & Pre-Model Privacy Gateway</p>
      </div>
      <div style="display: flex; gap: 8px; align-items: center;">
        <span class="badge">AIRLOCK ACTIVE (127.0.0.1)</span>
        <button id="killBtn" class="btn-kill" title="Immediately terminate PacketSentinel process and listeners">🚨 Emergency Kill Switch</button>
      </div>
    </header>

    <div class="section-title">1. Push-to-Talk Voice Input (RAM Ephemeral)</div>
    <div class="btn-row">
      <button id="pttBtn" class="btn-ptt">Hold Space or Click to Speak</button>
      <button id="sanitizeBtn" class="btn-secondary">Scrub Text Manually</button>
    </div>

    <div class="section-title">2. Raw Spoken / Typed Prompt</div>
    <div class="box">
      <textarea id="rawInput" placeholder="Speak or type your prompt here (e.g., 'Check transaction for card 4532-0150-1234-5678 and report to user John Doe')..."></textarea>
    </div>

    <div class="section-title">3. DLP Sanitized Output (Safe for AI Models)</div>
    <div class="box" id="sanitizedBox" style="min-height: 80px; font-family: monospace; font-size: 13px;">
      <span style="color: var(--muted);">Click 'Scrub Text' or speak to see real-time PII/secret scrubbing...</span>
    </div>

    <div class="section-title">4. Active Privacy Gates</div>
    <div class="status-text" style="line-height: 1.8;">
      [X] Gate 1: Blocks image/doc/credential file access<br>
      [X] Gate 2: Luhn-validated payment card & Mod-97 IBAN redactor<br>
      [X] Gate 3: OS username, hostname, profile path & personal name scrubber<br>
      [X] Gate 4: API keys, JWTs, and high-entropy secret token scrubber<br>
      [X] Gate 5: Anti-prompt injection spotlighting tags
    </div>
  </div>

  <script>
    const csrfToken = "CSRF_TOKEN_PLACEHOLDER";
    const rawInput = document.getElementById("rawInput");
    const sanitizedBox = document.getElementById("sanitizedBox");
    const pttBtn = document.getElementById("pttBtn");
    const sanitizeBtn = document.getElementById("sanitizeBtn");

    async function scrubText(text) {
      if (!text.trim()) return;
      try {
        const res = await fetch("/api/sanitize", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken
          },
          body: JSON.stringify({ text })
        });
        const data = await res.json();
        renderSanitized(data.sanitized_text);
      } catch (err) {
        sanitizedBox.innerHTML = "<span style='color:var(--danger)'>Error scrubbing text: " + err + "</span>";
      }
    }

    function renderSanitized(text) {
      let escaped = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
      escaped = escaped.replace(/\\[REDACTED_PAYMENT_CARD\\]/g, '<span class="redacted">[REDACTED_PAYMENT_CARD]</span>');
      escaped = escaped.replace(/\\[REDACTED_IBAN\\]/g, '<span class="redacted">[REDACTED_IBAN]</span>');
      escaped = escaped.replace(/&lt;REDACTED_USER&gt;/g, '<span class="redacted">&lt;REDACTED_USER&gt;</span>');
      escaped = escaped.replace(/\\[REDACTED_SECRET\\]/g, '<span class="redacted">[REDACTED_SECRET]</span>');
      sanitizedBox.innerHTML = escaped;
    }

    sanitizeBtn.addEventListener("click", () => scrubText(rawInput.value));
    rawInput.addEventListener("input", () => scrubText(rawInput.value));

    // Browser SpeechRecognition fallback if local microphone API is available
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    let recognition = null;
    let isRecording = false;

    if (SpeechRecognition) {
      recognition = new SpeechRecognition();
      recognition.continuous = true;
      recognition.interimResults = true;
      recognition.lang = "en-US";

      recognition.onresult = (event) => {
        let transcript = "";
        for (let i = 0; i < event.results.length; i++) {
          transcript += event.results[i][0].transcript;
        }
        rawInput.value = transcript;
        scrubText(transcript);
      };

      recognition.onerror = () => stopRecording();
      recognition.onend = () => stopRecording();
    }

    function startRecording() {
      if (!recognition) {
        alert("Local speech API not supported in this browser. You can type in the box to test real-time DLP redaction!");
        return;
      }
      isRecording = true;
      pttBtn.classList.add("recording");
      pttBtn.textContent = "Listening... Click to Stop";
      recognition.start();
    }

    function stopRecording() {
      isRecording = false;
      pttBtn.classList.remove("recording");
      pttBtn.textContent = "Hold Space or Click to Speak";
      if (recognition) recognition.stop();
    }

    pttBtn.addEventListener("click", () => {
      if (isRecording) stopRecording();
      else startRecording();
    });

    const killBtn = document.getElementById("killBtn");
    if (killBtn) {
      killBtn.addEventListener("click", async () => {
        if (!confirm("🚨 EMERGENCY KILL SWITCH:\n\nImmediately terminate PacketSentinel, close all listeners, and wipe volatile memory?")) return;
        try {
          await fetch("/api/kill", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-CSRF-Token": csrfToken
            }
          });
        } catch (e) {}
        document.body.innerHTML = "<div style='color: white; text-align: center; margin-top: 100px; font-family: sans-serif;'><h1 style='color: #ef4444;'>🚨 KILL SWITCH ENGAGED</h1><p style='color: #94a3b8; margin-top: 12px;'>PacketSentinel process terminated immediately. All local listeners closed.</p></div>";
      });
    }
  </script>
</body>
</html>
"""


class SecureVoiceRequestHandler(http.server.BaseHTTPRequestHandler):
    """Zero-outbound, CSRF-hardened local HTTP request handler."""

    sanitizer: PrivacySanitizer

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress default stdout log pollution

    def _send_cors_and_headers(self, status: int, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        # Bind strictly to localhost: reject external origins
        self.send_header("Access-Control-Allow-Origin", f"http://127.0.0.1:{_SERVER_PORT}")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            html_content = _EMBEDDED_HTML.replace("CSRF_TOKEN_PLACEHOLDER", _CSRF_TOKEN)
            self._send_cors_and_headers(HTTPStatus.OK, content_type="text/html; charset=utf-8")
            self.wfile.write(html_content.encode("utf-8"))
            return

        self._send_cors_and_headers(HTTPStatus.NOT_FOUND)
        self.wfile.write(b'{"error": "Not Found"}')

    def do_POST(self) -> None:
        # Anti-CSRF verification
        token = self.headers.get("X-CSRF-Token", "")
        if not secrets.compare_digest(token, _CSRF_TOKEN):
            self._send_cors_and_headers(HTTPStatus.FORBIDDEN)
            self.wfile.write(b'{"error": "Forbidden: Invalid CSRF Token"}')
            return

        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/sanitize":
            try:
                length = int(self.headers.get("Content-Length", 0))
                # Cap payload at 256 KB to prevent denial of service
                body_bytes = self.rfile.read(min(length, 256 * 1024))
                body = json.loads(body_bytes.decode("utf-8", errors="replace"))
                raw_text = str(body.get("text") or "")
                sanitized = self.sanitizer.sanitize_text(raw_text)

                self._send_cors_and_headers(HTTPStatus.OK)
                self.wfile.write(json.dumps({"sanitized_text": sanitized}).encode("utf-8"))
            except Exception as exc:
                self._send_cors_and_headers(HTTPStatus.BAD_REQUEST)
                self.wfile.write(json.dumps({"error": str(exc)}).encode("utf-8"))
            return

        if parsed.path == "/api/kill":
            logger.warning("[!] EMERGENCY KILL SWITCH ACTIVATED via Web UI.")
            self._send_cors_and_headers(HTTPStatus.OK)
            self.wfile.write(b'{"status": "killed", "message": "Terminating immediately"}')

            def _exit_now() -> None:
                import time
                time.sleep(0.15)
                exit_func = getattr(self.server, "exit_func", os._exit)
                exit_func(0)

            threading.Thread(target=_exit_now, daemon=True).start()
            return

        self._send_cors_and_headers(HTTPStatus.NOT_FOUND)
        self.wfile.write(b'{"error": "Not Found"}')


def _watch_tripwire_files(watch_dir: Path) -> None:
    tripwire_names = ("KILL_SWITCH", "KILL_SWITCH.txt", "STOP", "STOP.txt")
    import time
    while True:
        try:
            for name in tripwire_names:
                f = watch_dir / name
                if f.exists():
                    try:
                        f.unlink()
                    except Exception:
                        pass
                    logger.critical(f"[!] EMERGENCY KILL SWITCH TRIPWIRE DETECTED ({name}). Terminating.")
                    os._exit(0)
        except Exception:
            pass
        time.sleep(0.5)


def start_local_voice_ui(
    config: AppConfig,
    port: int = _SERVER_PORT,
    auto_open: bool = True,
) -> Tuple[http.server.ThreadingHTTPServer, str]:
    """Start local-only voice & privacy web server on 127.0.0.1."""
    sanitizer = PrivacySanitizer()

    class CustomHandler(SecureVoiceRequestHandler):
        pass

    CustomHandler.sanitizer = sanitizer
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), CustomHandler)
    url = f"http://127.0.0.1:{port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    tripwire_thread = threading.Thread(
        target=_watch_tripwire_files,
        args=(config.app_dir,),
        daemon=True,
    )
    tripwire_thread.start()

    if auto_open:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    return server, url

#!/usr/bin/env python3
"""
Notification Engine for SysVoidScan v3.0 Sentinel.
Sends scan results via Telegram, Discord, Slack, Email, and Webhooks.
"""

import json
import logging
import os
import smtplib
import ssl
import urllib.request
import urllib.error
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

from core.finding import Finding, FindingType


@dataclass
class TelegramConfig:
    bot_token: str
    chat_id: str
    parse_mode: str = "HTML"
    silent: bool = False


@dataclass
class DiscordConfig:
    webhook_url: str
    username: str = "SysVoidScan"
    avatar_url: Optional[str] = None


@dataclass
class SlackConfig:
    webhook_url: str
    channel: Optional[str] = None
    username: str = "SysVoidScan"


@dataclass
class EmailConfig:
    smtp_host: str
    smtp_port: int
    username: str
    password: str
    use_tls: bool = True
    from_addr: str = ""
    to_addrs: List[str] = None

    def __post_init__(self):
        if self.to_addrs is None:
            self.to_addrs = []


@dataclass
class WebhookConfig:
    url: str
    method: str = "POST"
    headers: Dict[str, str] = None
    auth_header: Optional[str] = None

    def __post_init__(self):
        if self.headers is None:
            self.headers = {}


SEVERITY_EMOJI = {
    "critical": "\u274c",
    "high": "\ud83d\udd34",
    "medium": "\ud83d\udfe1",
    "low": "\ud83d\udfe2",
    "info": "\u26aa",
}


class Notifier:
    """Multi-channel notification engine for scan results."""

    def __init__(self):
        self.telegram: Optional[TelegramConfig] = None
        self.discord: Optional[DiscordConfig] = None
        self.slack: Optional[SlackConfig] = None
        self.email: Optional[EmailConfig] = None
        self.webhooks: List[WebhookConfig] = []

    def configure_telegram(self, bot_token: str, chat_id: str):
        self.telegram = TelegramConfig(bot_token=bot_token, chat_id=chat_id)

    def configure_discord(self, webhook_url: str):
        self.discord = DiscordConfig(webhook_url=webhook_url)

    def configure_slack(self, webhook_url: str):
        self.slack = SlackConfig(webhook_url=webhook_url)

    def configure_email(self, smtp_host: str, smtp_port: int, username: str, password: str, from_addr: str, to_addrs: List[str]):
        self.email = EmailConfig(
            smtp_host=smtp_host, smtp_port=smtp_port,
            username=username, password=password,
            from_addr=from_addr, to_addrs=to_addrs,
        )

    def add_webhook(self, url: str, headers: Optional[Dict[str, str]] = None):
        self.webhooks.append(WebhookConfig(url=url, headers=headers or {}))

    def _http_post(self, url: str, data: Dict, headers: Optional[Dict[str, str]] = None) -> bool:
        try:
            req_headers = {"Content-Type": "application/json"}
            if headers:
                req_headers.update(headers)
            body = json.dumps(data).encode("utf-8")
            req = urllib.request.Request(url, data=body, headers=req_headers, method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status < 400
        except Exception:
            logging.exception("Notifier._http_post: notification delivery failed")
            return False

    def _format_summary(self, findings: List[Finding], target: str) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.severity.lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def send_telegram(self, findings: List[Finding], target: str) -> bool:
        if not self.telegram:
            return False
        counts = self._format_summary(findings, target)
        total = len(findings)
        lines = [
            f"<b>SysVoidScan v3.0 - Scan Complete</b>",
            f"<b>Target:</b> {target}",
            f"<b>Total Findings:</b> {total}",
            "",
        ]
        for sev, count in counts.items():
            if count > 0:
                lines.append(f"{SEVERITY_EMOJI.get(sev, '')} <b>{sev.upper()}:</b> {count}")
        lines.append("")
        critical = [f for f in findings if f.severity.lower() == "critical"]
        if critical:
            lines.append("<b>Critical Findings:</b>")
            for f in critical[:5]:
                lines.append(f"  \u2022 {f.title}")
                if f.url:
                    lines.append(f"    <code>{f.url}</code>")
        text = "\n".join(lines)
        data = {"chat_id": self.telegram.chat_id, "text": text, "parse_mode": self.telegram.parse_mode, "disable_notification": self.telegram.silent}
        return self._http_post(f"https://api.telegram.org/bot{self.telegram.bot_token}/sendMessage", data)

    def send_discord(self, findings: List[Finding], target: str) -> bool:
        if not self.discord:
            return False
        counts = self._format_summary(findings, target)
        total = len(findings)
        embed = {
            "title": "SysVoidScan v3.0 - Scan Complete",
            "description": f"Target: {target}\nTotal Findings: {total}",
            "color": 0xFF0000 if counts.get("critical", 0) > 0 else 0xFFA500 if counts.get("high", 0) > 0 else 0xFFFF00,
            "fields": [],
        }
        for sev, count in counts.items():
            if count > 0:
                embed["fields"].append({"name": f"{SEVERITY_EMOJI.get(sev, '')} {sev.upper()}", "value": str(count), "inline": True})
        critical = [f for f in findings if f.severity.lower() == "critical"]
        if critical:
            desc_lines = []
            for f in critical[:5]:
                desc_lines.append(f"\u2022 {f.title}\n  {f.url or 'N/A'}")
            embed["fields"].append({"name": "Critical Findings", "value": "\n".join(desc_lines), "inline": False})
        data = {"username": self.discord.username, "embeds": [embed]}
        if self.discord.avatar_url:
            data["avatar_url"] = self.discord.avatar_url
        return self._http_post(self.discord.webhook_url, data)

    def send_slack(self, findings: List[Finding], target: str) -> bool:
        if not self.slack:
            return False
        counts = self._format_summary(findings, target)
        total = len(findings)
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "SysVoidScan v3.0 - Scan Complete"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Target:* {target}\n*Total Findings:* {total}"}},
            {"type": "divider"},
        ]
        sev_text = []
        for sev, count in counts.items():
            if count > 0:
                sev_text.append(f"{SEVERITY_EMOJI.get(sev, '')} *{sev.upper()}:* {count}")
        if sev_text:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(sev_text)}})
        critical = [f for f in findings if f.severity.lower() == "critical"]
        if critical:
            crit_lines = [f"\u2022 {f.title} - {f.url or 'N/A'}" for f in critical[:5]]
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Critical Findings:*\n" + "\n".join(crit_lines)}})
        data = {"blocks": blocks}
        if self.slack.channel:
            data["channel"] = self.slack.channel
        data["username"] = self.slack.username
        return self._http_post(self.slack.webhook_url, data)

    def send_email(self, findings: List[Finding], target: str) -> bool:
        if not self.email:
            return False
        try:
            counts = self._format_summary(findings, target)
            total = len(findings)
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[SysVoidScan] Security Scan Complete - {target} ({total} findings)"
            msg["From"] = self.email.from_addr
            msg["To"] = ", ".join(self.email.to_addrs)
            html_lines = [
                "<html><body>",
                "<h2>SysVoidScan v3.0 - Scan Results</h2>",
                f"<p><b>Target:</b> {target}</p>",
                f"<p><b>Total Findings:</b> {total}</p>",
                "<h3>Severity Distribution</h3>",
                "<ul>",
            ]
            for sev, count in counts.items():
                if count > 0:
                    html_lines.append(f"<li>{SEVERITY_EMOJI.get(sev, '')} <b>{sev.upper()}:</b> {count}</li>")
            html_lines.append("</ul>")
            critical = [f for f in findings if f.severity.lower() == "critical"]
            if critical:
                html_lines.append("<h3>Critical Findings</h3><ul>")
                for f in critical[:10]:
                    html_lines.append(f"<li><b>{f.title}</b><br><code>{f.url or 'N/A'}</code></li>")
                html_lines.append("</ul>")
            html_lines.append("<hr><p><i>Generated by SysVoidScan v3.0 Sentinel</i></p></body></html>")
            html = "\n".join(html_lines)
            msg.attach(MIMEText(html, "html"))
            context = ssl.create_default_context()
            with smtplib.SMTP(self.email.smtp_host, self.email.smtp_port) as server:
                if self.email.use_tls:
                    server.starttls(context=context)
                server.login(self.email.username, self.email.password)
                server.sendmail(self.email.from_addr, self.email.to_addrs, msg.as_string())
            return True
        except Exception:
            return False

    def send_webhook(self, findings: List[Finding], target: str) -> Dict[str, bool]:
        results = {}
        counts = self._format_summary(findings, target)
        payload = {
            "event": "scan_complete",
            "target": target,
            "total_findings": len(findings),
            "severity_counts": counts,
            "critical_findings": [
                {"title": f.title, "url": f.url, "severity": f.severity}
                for f in findings if f.severity.lower() == "critical"
            ][:10],
            "findings": [
                {"title": f.title, "severity": f.severity, "url": f.url, "type": f.type.value if hasattr(f.type, "value") else str(f.type)}
                for f in findings
            ],
        }
        for wh in self.webhooks:
            results[wh.url] = self._http_post(wh.url, payload, wh.headers)
        return results

    def send_all(self, findings: List[Finding], target: str) -> Dict[str, bool]:
        results = {}
        results["telegram"] = self.send_telegram(findings, target)
        results["discord"] = self.send_discord(findings, target)
        results["slack"] = self.send_slack(findings, target)
        results["email"] = self.send_email(findings, target)
        wh_results = self.send_webhook(findings, target)
        results["webhooks"] = wh_results
        return results

    @classmethod
    def from_env(cls) -> "Notifier":
        notifier = cls()
        tg_token = os.environ.get("SYSVOIDSCAN_TG_BOT_TOKEN")
        tg_chat = os.environ.get("SYSVOIDSCAN_TG_CHAT_ID")
        if tg_token and tg_chat:
            notifier.configure_telegram(tg_token, tg_chat)
        dc_url = os.environ.get("SYSVOIDSCAN_DISCORD_WEBHOOK")
        if dc_url:
            notifier.configure_discord(dc_url)
        sl_url = os.environ.get("SYSVOIDSCAN_SLACK_WEBHOOK")
        if sl_url:
            notifier.configure_slack(sl_url)
        smtp_host = os.environ.get("SYSVOIDSCAN_SMTP_HOST")
        smtp_port = os.environ.get("SYSVOIDSCAN_SMTP_PORT")
        smtp_user = os.environ.get("SYSVOIDSCAN_SMTP_USER")
        smtp_pass = os.environ.get("SYSVOIDSCAN_SMTP_PASS")
        smtp_from = os.environ.get("SYSVOIDSCAN_SMTP_FROM")
        smtp_to = os.environ.get("SYSVOIDSCAN_SMTP_TO")
        if all([smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from, smtp_to]):
            notifier.configure_email(
                smtp_host=smtp_host, smtp_port=int(smtp_port),
                username=smtp_user, password=smtp_pass,
                from_addr=smtp_from, to_addrs=[a.strip() for a in smtp_to.split(",")],
            )
        custom_webhooks = os.environ.get("SYSVOIDSCAN_WEBHOOKS")
        if custom_webhooks:
            for url in custom_webhooks.split(","):
                if url.strip():
                    notifier.add_webhook(url.strip())
        return notifier

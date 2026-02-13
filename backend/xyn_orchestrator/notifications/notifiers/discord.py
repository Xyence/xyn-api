from typing import Any, Dict, List

import requests


class DiscordNotifier:
    notifier_type = "discord"

    def __init__(self, config: Dict[str, Any], webhook_url: str):
        self.config = config or {}
        self.webhook_url = webhook_url

    def notify(self, report: Dict[str, Any], attachment_urls: List[str]):
        title = report.get("title") or "Untitled report"
        rtype = report.get("type") or "bug"
        priority = report.get("priority") or "p2"
        context = report.get("context") or {}
        url = context.get("url") or ""
        lines = [
            f"[{priority.upper()}] {rtype.upper()}: {title}",
            f"Report ID: {report.get('id')}",
        ]
        if url:
            lines.append(f"URL: {url}")
        if attachment_urls:
            lines.append("Attachments:")
            lines.extend([f"- {link}" for link in attachment_urls])
        payload: Dict[str, Any] = {
            "content": "\n".join(lines),
        }
        username = str((self.config.get("username") or "")).strip()
        avatar = str((self.config.get("avatar_url") or "")).strip()
        if username:
            payload["username"] = username
        if avatar:
            payload["avatar_url"] = avatar
        requests.post(self.webhook_url, json=payload, timeout=10)

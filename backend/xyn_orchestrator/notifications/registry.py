from typing import Any, Dict, List, Optional

from xyn_orchestrator.models import SecretRef
from xyn_orchestrator.oidc import resolve_secret_ref

from .notifiers.aws_sns import AwsSnsNotifier
from .notifiers.discord import DiscordNotifier


def resolve_secret_ref_value(ref_text: str) -> Optional[str]:
    value = str(ref_text or "").strip()
    if not value:
        return None
    if value.startswith("secret_ref:"):
        ref_id = value.split(":", 1)[1].strip()
        try:
            ref = SecretRef.objects.filter(id=ref_id).first()
        except Exception:
            ref = None
        if not ref:
            return None
        return resolve_secret_ref({"type": "aws.secrets_manager", "ref": ref.external_ref})
    ref = SecretRef.objects.filter(name=value, scope_kind="platform", scope_id__isnull=True).first()
    if ref:
        return resolve_secret_ref({"type": "aws.secrets_manager", "ref": ref.external_ref})
    if value.startswith("aws.secrets_manager:"):
        return resolve_secret_ref({"type": "aws.secrets_manager", "ref": value.split(":", 1)[1]})
    if value.startswith("env:"):
        return resolve_secret_ref({"type": "env", "ref": value.split(":", 1)[1]})
    return None


class NotifierRegistry:
    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}

    def list_enabled_notifiers(self):
        notifications = self.config.get("notifications") if isinstance(self.config.get("notifications"), dict) else {}
        if notifications.get("enabled", True) is False:
            return []
        enabled = []
        for channel in notifications.get("channels") or []:
            if not isinstance(channel, dict):
                continue
            if channel.get("enabled", True) is False:
                continue
            ctype = str(channel.get("type") or "").strip().lower()
            if ctype == "discord":
                discord_cfg = channel.get("discord") if isinstance(channel.get("discord"), dict) else {}
                ref_text = str(discord_cfg.get("webhook_url_ref") or "").strip()
                webhook = resolve_secret_ref_value(ref_text)
                if webhook:
                    enabled.append(DiscordNotifier(discord_cfg, webhook))
            elif ctype == "aws_sns":
                sns_cfg = channel.get("aws_sns") if isinstance(channel.get("aws_sns"), dict) else {}
                if sns_cfg.get("topic_arn") and sns_cfg.get("region"):
                    enabled.append(AwsSnsNotifier(sns_cfg))
        return enabled

    def notify_report_created(self, report: Dict[str, Any], attachment_urls: List[str]) -> List[str]:
        errors: List[str] = []
        for notifier in self.list_enabled_notifiers():
            try:
                notifier.notify(report, attachment_urls)
            except Exception as exc:
                errors.append(f"{getattr(notifier, 'notifier_type', 'unknown')}: {exc.__class__.__name__}")
        return errors

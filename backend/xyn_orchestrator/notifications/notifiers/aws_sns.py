import json
from typing import Any, Dict, List

import boto3


class AwsSnsNotifier:
    notifier_type = "aws_sns"

    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}

    def notify(self, report: Dict[str, Any], attachment_urls: List[str]):
        topic_arn = str(self.config.get("topic_arn") or "").strip()
        if not topic_arn:
            return
        region = str(self.config.get("region") or "").strip()
        prefix = str(self.config.get("subject_prefix") or "").strip()
        message_attributes = self.config.get("message_attributes") if isinstance(self.config.get("message_attributes"), dict) else {}
        client = boto3.client("sns", region_name=region) if region else boto3.client("sns")
        subject = f"{prefix} {report.get('type', 'report')} {report.get('priority', 'p2')}".strip()
        body = {
            "id": report.get("id"),
            "title": report.get("title"),
            "type": report.get("type"),
            "priority": report.get("priority"),
            "url": (report.get("context") or {}).get("url"),
            "attachment_urls": attachment_urls,
        }
        attrs = {
            str(key): {"DataType": "String", "StringValue": str(value)}
            for key, value in message_attributes.items()
        }
        client.publish(TopicArn=topic_arn, Subject=subject[:100], Message=json.dumps(body), MessageAttributes=attrs)

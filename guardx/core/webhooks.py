"""
GuardX Webhook Notifier Module
Send notifications to Slack, Discord, Telegram, and custom webhooks.
"""

import urllib.request
import urllib.parse
import json
import ssl
import os
from typing import Dict, Optional


class WebhookNotifier:
    """Send notifications to various webhook services.

    Supports Slack, Discord, Telegram, and generic webhooks.
    """

    def __init__(self):
        """Initialize webhook notifier from environment variables."""
        self.slack_webhook = os.getenv('GUARDX_WEBHOOK_SLACK')
        self.discord_webhook = os.getenv('GUARDX_WEBHOOK_DISCORD')
        self.generic_webhook = os.getenv('GUARDX_WEBHOOK_GENERIC')
        self.telegram_token = os.getenv('GUARDX_WEBHOOK_TELEGRAM_TOKEN')
        self.telegram_chat_id = os.getenv('GUARDX_WEBHOOK_TELEGRAM_CHAT_ID')

    def is_configured(self) -> bool:
        """Check if any webhook is configured.

        Returns:
            True if at least one webhook is configured
        """
        return bool(
            self.slack_webhook or
            self.discord_webhook or
            self.generic_webhook or
            (self.telegram_token and self.telegram_chat_id)
        )

    def notify(self, event: str, data: dict) -> None:
        """Send notification for an event.

        Args:
            event: Event type (scan_started, finding_critical, finding_high, scan_completed, fix_applied)
            data: Event data dictionary
        """
        if not self.is_configured():
            return

        message = self._format_message(event, data)

        if self.slack_webhook:
            self._send_slack(message, event, data)

        if self.discord_webhook:
            self._send_discord(message, event, data)

        if self.generic_webhook:
            self._send_generic(event, data)

        if self.telegram_token and self.telegram_chat_id:
            self._send_telegram(message)

    def _format_message(self, event: str, data: dict) -> str:
        """Format message based on event type.

        Args:
            event: Event type
            data: Event data

        Returns:
            Formatted message string
        """
        if event == 'scan_started':
            return f"GuardX Scan Started\nTarget: {data.get('target', 'unknown')}\nID: {data.get('scan_id', 'unknown')}"

        elif event == 'finding_critical':
            return f"CRITICAL Finding\n{data.get('title', 'Unknown')}\nTarget: {data.get('target', 'unknown')}"

        elif event == 'finding_high':
            return f"HIGH Severity Finding\n{data.get('title', 'Unknown')}\nTarget: {data.get('target', 'unknown')}"

        elif event == 'scan_completed':
            summary = data.get('summary', {})
            return (f"Scan Completed\nTarget: {data.get('target', 'unknown')}\n"
                   f"Findings: {summary.get('total_findings', 0)}\n"
                   f"Fixed: {summary.get('verified_fixes', 0)}")

        elif event == 'fix_applied':
            return f"Fix Applied\nFinding: {data.get('finding_title', 'Unknown')}\nStatus: {data.get('status', 'applied')}"

        return json.dumps(data)

    def _send_slack(self, message: str, event: str, data: dict) -> None:
        """Send notification to Slack.

        Args:
            message: Formatted message
            event: Event type
            data: Event data
        """
        try:
            color = self._get_color(event)
            payload = {
                'attachments': [{
                    'color': color,
                    'title': event.replace('_', ' ').title(),
                    'text': message,
                    'ts': int(__import__('time').time())
                }]
            }

            body = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                self.slack_webhook,
                data=body,
                headers={'Content-Type': 'application/json'}
            )

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
                response.read()
        except Exception:
            pass  # Silently fail to avoid interrupting scan

    def _send_discord(self, message: str, event: str, data: dict) -> None:
        """Send notification to Discord.

        Args:
            message: Formatted message
            event: Event type
            data: Event data
        """
        try:
            color = self._get_color_int(event)
            payload = {
                'embeds': [{
                    'title': event.replace('_', ' ').title(),
                    'description': message,
                    'color': color
                }]
            }

            body = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                self.discord_webhook,
                data=body,
                headers={'Content-Type': 'application/json'}
            )

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
                response.read()
        except Exception:
            pass

    def _send_telegram(self, message: str) -> None:
        """Send notification to Telegram.

        Args:
            message: Message to send
        """
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            payload = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'Markdown'
            }

            data = urllib.parse.urlencode(payload).encode('utf-8')
            req = urllib.request.Request(url, data=data)

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
                response.read()
        except Exception:
            pass

    def _send_generic(self, event: str, data: dict) -> None:
        """Send notification to generic webhook.

        Args:
            event: Event type
            data: Event data
        """
        try:
            payload = {
                'event': event,
                'data': data,
                'timestamp': __import__('datetime').datetime.utcnow().isoformat()
            }

            body = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                self.generic_webhook,
                data=body,
                headers={'Content-Type': 'application/json'}
            )

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
                response.read()
        except Exception:
            pass

    @staticmethod
    def _get_color(event: str) -> str:
        """Get Slack color for event type.

        Args:
            event: Event type

        Returns:
            Hex color code
        """
        colors = {
            'scan_started': '#0099FF',
            'finding_critical': '#FF0000',
            'finding_high': '#FF6600',
            'scan_completed': '#00CC00',
            'fix_applied': '#00FF00'
        }
        return colors.get(event, '#999999')

    @staticmethod
    def _get_color_int(event: str) -> int:
        """Get Discord color for event type.

        Args:
            event: Event type

        Returns:
            Decimal color value
        """
        colors = {
            'scan_started': 39423,    # Blue
            'finding_critical': 16711680,  # Red
            'finding_high': 16744448,  # Orange
            'scan_completed': 65280,   # Green
            'fix_applied': 65280      # Green
        }
        return colors.get(event, 9895408)  # Gray


# Global singleton instance
_notifier = None


def get_notifier() -> WebhookNotifier:
    """Get or create global webhook notifier instance.

    Returns:
        WebhookNotifier instance
    """
    global _notifier
    if _notifier is None:
        _notifier = WebhookNotifier()
    return _notifier


def notify(event: str, data: dict) -> None:
    """Send a notification event.

    Args:
        event: Event type
        data: Event data
    """
    get_notifier().notify(event, data)

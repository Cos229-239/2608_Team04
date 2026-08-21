from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass


SUPPORTED_EVENTS = frozenset(
    {
        "authorization_required",
        "workflow_blocked",
        "blocking_finding",
        "provider_failure",
        "repair_completed",
        "verification_failed",
        "run_approved",
        "run_completed",
        "run_rejected",
        "run_cancelled",
    }
)


@dataclass(frozen=True, slots=True)
class NotificationResult:
    delivered: bool
    channel: str
    detail: str


def deliver_local_notification(event: str, title: str, detail: str) -> NotificationResult:
    """Deliver a content-minimized local notification when the OS supports it."""
    if event not in SUPPORTED_EVENTS:
        raise ValueError("unsupported notification event")
    safe_title = _plain(title)[:120]
    safe_detail = _plain(detail)[:300]
    if platform.system() != "Windows":
        return NotificationResult(False, "in-app", "OS notification unavailable")
    script = (
        "$ErrorActionPreference='Stop';"
        "$template=[Windows.UI.Notifications.ToastTemplateType]::ToastText02;"
        "$xml=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($template);"
        "$nodes=$xml.GetElementsByTagName('text');"
        "$nodes.Item(0).AppendChild($xml.CreateTextNode($args[0]))|Out-Null;"
        "$nodes.Item(1).AppendChild($xml.CreateTextNode($args[1]))|Out-Null;"
        "$toast=[Windows.UI.Notifications.ToastNotification]::new($xml);"
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Keeper').Show($toast)"
    )
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
                safe_title,
                safe_detail,
            ],
            capture_output=True,
            text=True,
            shell=False,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return NotificationResult(False, "in-app", "OS notification failed")
    return NotificationResult(
        result.returncode == 0,
        "windows-toast" if result.returncode == 0 else "in-app",
        "delivered" if result.returncode == 0 else "OS notification failed",
    )


def _plain(value: str) -> str:
    return "".join(character for character in value if character.isprintable()).replace(
        "\n", " "
    )

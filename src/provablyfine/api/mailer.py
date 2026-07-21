from __future__ import annotations

import email.message
import os
import subprocess

import requests

from . import config as config_module


def send(cfg: config_module.EmailConfig, to: str, subject: str, body: str) -> None:
    if isinstance(cfg, config_module.SendmailEmailConfig):
        _send_sendmail(cfg, to, subject, body)
    else:
        _send_resend(cfg, to, subject, body)


def _send_sendmail(cfg: config_module.SendmailEmailConfig, to: str, subject: str, body: str) -> None:
    msg = email.message.EmailMessage()
    msg["From"] = cfg.from_address
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    result = subprocess.run([cfg.sendmail_path, "-t"], input=msg.as_bytes(), capture_output=True)  # noqa: S603
    if result.returncode != 0:
        raise RuntimeError(f"sendmail exited {result.returncode}: {result.stderr!r}")


def _send_resend(cfg: config_module.ResendEmailConfig, to: str, subject: str, body: str) -> None:
    filename = cfg.api_key_filename.format(PF_SECRET_DIRECTORY=os.getenv("PF_SECRET_DIRECTORY", ""))
    with open(filename) as f:
        api_key = f.read().strip()
    response = requests.post(
        "https://api.resend.com/emails",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"from": cfg.from_address, "to": [to], "subject": subject, "text": body},
        timeout=10,
    )
    if not response.ok:
        raise RuntimeError(f"Resend API error {response.status_code}: {response.text}")

"""
SOC Assist — Email SMTP Notifications (#32)
Sends alert emails for Critical/Breach incident classifications.
Config stored in smtp_config.json (never commit with real credentials).
"""
import json
import smtplib
import ssl
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

SMTP_CONFIG_FILE = Path("smtp_config.json")

_CLS_META = {
    "critico": ("🔴", "CRÍTICO",       "#dc2626", "#7f1d1d"),
    "brecha":  ("🚨", "BRECHA",        "#b91c1c", "#450a0a"),
}


def load_smtp_config() -> dict:
    if SMTP_CONFIG_FILE.exists():
        try:
            return json.loads(SMTP_CONFIG_FILE.read_text("utf-8"))
        except Exception:
            pass
    return {}


def save_smtp_config(cfg: dict) -> None:
    SMTP_CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), "utf-8")


def _build_message(cfg: dict, incident_id: int, classification: str,
                   final_score: float, analyst_name: str,
                   base_url: str, recipients: list[str]) -> MIMEMultipart:
    emoji, label, color, bg = _CLS_META.get(
        classification, ("⚠️", classification.upper(), "#f59e0b", "#451a03")
    )
    now_str = datetime.utcnow().strftime("%d/%m/%Y %H:%M UTC")
    incident_url = f"{base_url.rstrip('/')}/incidentes/{incident_id}"
    subject = f"[SOC Assist] {emoji} Incidente #{incident_id} — {label}"

    body_text = f"""
SOC Assist — Alerta de Seguridad
=================================

Se ha clasificado un nuevo incidente con nivel {label}.

  ID del Incidente : #{incident_id}
  Clasificación    : {label}
  Score Final      : {int(final_score)}
  Analista         : {analyst_name or 'N/A'}
  Fecha / Hora     : {now_str}
  URL              : {incident_url}

Accedé al sistema para revisar el incidente, asignarlo y tomar acción.

--
SOC Assist — Plataforma de Alerta Temprana en Ciberseguridad
Este correo fue generado automáticamente. No respondas este mensaje.
""".strip()

    body_html = f"""<!DOCTYPE html>
<html><body style="margin:0;padding:20px;font-family:Arial,sans-serif;background:#0f172a;color:#e2e8f0;">
<div style="max-width:600px;margin:0 auto;border-radius:8px;overflow:hidden;border:1px solid #334155;">
  <div style="background:{bg};padding:18px 24px;">
    <h2 style="margin:0;color:#fff;font-size:1.25rem;">{emoji} SOC Assist — {label}</h2>
  </div>
  <div style="padding:24px;background:#1e293b;">
    <table style="width:100%;border-collapse:collapse;font-size:0.9rem;">
      <tr><td style="padding:6px 0;color:#94a3b8;width:160px;">ID del Incidente</td>
          <td style="padding:6px 0;font-weight:bold;font-size:1.05rem;">#{incident_id}</td></tr>
      <tr><td style="padding:6px 0;color:#94a3b8;">Clasificación</td>
          <td style="padding:6px 0;font-weight:bold;color:{color};">{label}</td></tr>
      <tr><td style="padding:6px 0;color:#94a3b8;">Score Final</td>
          <td style="padding:6px 0;font-weight:bold;">{int(final_score)}</td></tr>
      <tr><td style="padding:6px 0;color:#94a3b8;">Analista</td>
          <td style="padding:6px 0;">{analyst_name or 'N/A'}</td></tr>
      <tr><td style="padding:6px 0;color:#94a3b8;">Fecha / Hora</td>
          <td style="padding:6px 0;">{now_str}</td></tr>
    </table>
    <div style="margin-top:24px;text-align:center;">
      <a href="{incident_url}"
         style="background:{color};color:#fff;padding:12px 28px;text-decoration:none;
                border-radius:6px;font-weight:bold;display:inline-block;">
        Ver Incidente #{incident_id}
      </a>
    </div>
  </div>
  <div style="padding:12px 24px;background:#0f172a;color:#64748b;font-size:11px;text-align:center;">
    SOC Assist — Plataforma de Alerta Temprana en Ciberseguridad<br>
    Este correo fue generado automáticamente. No respondas este mensaje.
  </div>
</div>
</body></html>""".strip()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = cfg.get("smtp_from") or cfg.get("smtp_user") or "soc@localhost"
    msg["To"]      = ", ".join(recipients)
    msg.attach(MIMEText(body_text, "plain", "utf-8"))
    msg.attach(MIMEText(body_html, "html", "utf-8"))
    return msg


def _send(cfg: dict, msg: MIMEMultipart, recipients: list[str]) -> None:
    host     = cfg.get("smtp_host", "")
    port     = int(cfg.get("smtp_port", 587))
    use_tls  = cfg.get("smtp_tls", True)
    username = cfg.get("smtp_user", "")
    password = cfg.get("smtp_password", "")

    if use_tls and port == 465:
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=15) as srv:
            if username:
                srv.login(username, password)
            srv.sendmail(msg["From"], recipients, msg.as_string())
    else:
        with smtplib.SMTP(host, port, timeout=15) as srv:
            if use_tls:
                srv.starttls()
            if username:
                srv.login(username, password)
            srv.sendmail(msg["From"], recipients, msg.as_string())


def send_incident_alert(
    incident_id: int,
    classification: str,
    final_score: float,
    analyst_name: str,
    base_url: str = "http://localhost:8000",
) -> bool:
    """
    Send an alert email when a Critical or Breach incident is created.
    Returns True if sent, False if skipped/failed (non-blocking — caller uses fire-and-forget).
    """
    cfg = load_smtp_config()
    if not cfg.get("enabled"):
        return False
    if classification not in ("critico", "brecha"):
        return False

    raw = cfg.get("notify_emails", "")
    recipients = [e.strip() for e in raw.replace(";", ",").split(",") if e.strip()]
    if not recipients:
        return False

    try:
        msg = _build_message(cfg, incident_id, classification, final_score, analyst_name,
                             base_url, recipients)
        _send(cfg, msg, recipients)
        return True
    except Exception as exc:
        print(f"[Mailer] Error enviando alerta del incidente #{incident_id}: {exc}")
        return False


def test_smtp_connection(cfg: dict) -> tuple[bool, str]:
    """
    Test SMTP connectivity with the given config dict.
    Returns (success: bool, message: str).
    """
    host = cfg.get("smtp_host", "").strip()
    if not host:
        return False, "Host SMTP no configurado."
    try:
        port     = int(cfg.get("smtp_port", 587))
        use_tls  = cfg.get("smtp_tls", True)
        username = cfg.get("smtp_user", "").strip()
        password = cfg.get("smtp_password", "").strip()

        if use_tls and port == 465:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=ctx, timeout=8) as srv:
                if username:
                    srv.login(username, password)
        else:
            with smtplib.SMTP(host, port, timeout=8) as srv:
                if use_tls:
                    srv.starttls()
                if username:
                    srv.login(username, password)
        return True, "Conexión y autenticación exitosa."
    except smtplib.SMTPAuthenticationError:
        return False, "Error de autenticación SMTP — verificá usuario/contraseña."
    except smtplib.SMTPConnectError:
        return False, f"No se pudo conectar a {host}:{cfg.get('smtp_port', 587)}."
    except Exception as exc:
        return False, str(exc)

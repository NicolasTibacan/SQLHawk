import json
import os
import tempfile
from typing import Any

import gradio as gr
import requests


DEFAULT_API_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
DEFAULT_TIMEOUT = float(os.getenv("API_TIMEOUT", "10"))
DEFAULT_PORT = int(os.getenv("FRONTEND_PORT", "7860"))


CSS = """
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Fira+Mono:wght@400;600&display=swap');

:root {
  --bg-1: #f7f3ee;
  --bg-2: #e8f2ff;
  --ink-1: #1c1c1c;
  --ink-2: #4b5563;
  --accent: #0f766e;
  --accent-2: #f97316;
  --card: rgba(255, 255, 255, 0.85);
  --card-border: rgba(15, 118, 110, 0.15);
  --shadow: 0 20px 50px rgba(15, 23, 42, 0.12);
}

body, .gradio-container {
  background: radial-gradient(circle at 10% 20%, #ffffff 0%, var(--bg-1) 35%, var(--bg-2) 100%);
  color: var(--ink-1);
  font-family: 'Space Grotesk', system-ui, sans-serif;
}

#hero {
  background: linear-gradient(135deg, #fff 0%, rgba(248, 250, 252, 0.9) 50%, rgba(255, 247, 237, 0.9) 100%);
  border: 1px solid rgba(249, 115, 22, 0.15);
  border-radius: 20px;
  padding: 20px 24px;
  box-shadow: var(--shadow);
  position: relative;
  overflow: hidden;
  animation: floatIn 0.6s ease-out;
}

#hero:before {
  content: "";
  position: absolute;
  inset: -40px -80px auto auto;
  width: 220px;
  height: 220px;
  background: radial-gradient(circle, rgba(15, 118, 110, 0.18), transparent 70%);
  transform: rotate(15deg);
}

.hero-title {
  font-size: 32px;
  font-weight: 700;
  letter-spacing: 0.5px;
}

.hero-sub {
  color: var(--ink-2);
  font-size: 16px;
  margin-top: 6px;
}

#sidebar {
  background: var(--card);
  border: 1px solid var(--card-border);
  border-radius: 18px;
  padding: 16px;
  box-shadow: var(--shadow);
}

#nav label {
  font-weight: 600;
}

#nav .wrap {
  gap: 8px;
}

.gr-button {
  border-radius: 12px !important;
  background: var(--accent) !important;
  color: #fff !important;
  border: none !important;
  transition: transform 0.15s ease, box-shadow 0.15s ease;
}

.gr-button:hover {
  transform: translateY(-2px);
  box-shadow: 0 14px 30px rgba(15, 118, 110, 0.25);
}

.panel {
  background: var(--card);
  border: 1px solid var(--card-border);
  border-radius: 18px;
  padding: 16px;
  box-shadow: var(--shadow);
  animation: riseIn 0.5s ease-out;
    margin-bottom: 12px;
}

.panel h3 {
  margin-bottom: 8px;
}

.badge {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
  border-radius: 999px;
  background: rgba(15, 118, 110, 0.12);
  color: var(--accent);
  font-weight: 600;
  font-size: 13px;
}

.metric-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px;
}

.metric-card {
  background: #fff;
  border: 1px solid rgba(15, 118, 110, 0.12);
  border-radius: 14px;
  padding: 12px;
}

.metric-label {
  color: var(--ink-2);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.metric-value {
  font-size: 22px;
  font-weight: 700;
  margin-top: 6px;
}

.dataframe {
  border-radius: 12px;
  overflow: hidden;
}

.code {
  font-family: 'Fira Mono', ui-monospace, monospace;
  font-size: 12px;
  color: var(--ink-2);
}

@keyframes floatIn {
  from { transform: translateY(8px); opacity: 0; }
  to { transform: translateY(0); opacity: 1; }
}

@keyframes riseIn {
  from { transform: translateY(12px); opacity: 0; }
  to { transform: translateY(0); opacity: 1; }
}
"""


def _normalize_api_url(value: str) -> str:
    url = (value or "").strip()
    if not url:
        return DEFAULT_API_URL
    return url.rstrip("/")


def _request_json(method: str, url: str, token: str | None = None, **kwargs) -> tuple[Any, str | None]:
    headers = kwargs.pop("headers", {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            timeout=DEFAULT_TIMEOUT,
            **kwargs,
        )
    except requests.RequestException as exc:
        return None, f"Network error: {exc}"

    if response.status_code >= 400:
        try:
            detail = response.json().get("detail", response.text)
        except ValueError:
            detail = response.text
        return None, f"{response.status_code} {detail}"

    if response.headers.get("content-type", "").startswith("application/json"):
        return response.json(), None
    return response.text, None


def ping_api(api_url: str) -> str:
    base_url = _normalize_api_url(api_url)
    payload, error = _request_json("GET", f"{base_url}/health")
    if error:
        return f"API error: {error}"
    return f"API ok: {json.dumps(payload)}"


def login_action(api_url: str, email: str, password: str) -> tuple[str, dict, str, str, str, str]:
    base_url = _normalize_api_url(api_url)
    if not email or not password:
        return "", {}, "Provide email and password.", "Not signed in", "", ""

    token_payload, error = _request_json(
        "POST",
        f"{base_url}/auth/login",
        data={"username": email, "password": password},
    )
    if error:
        return "", {}, f"Login failed: {error}", "Not signed in", "", ""

    token = token_payload.get("access_token", "")
    if not token:
        return "", {}, "Login failed: token missing", "Not signed in", "", ""

    user_payload, error = _request_json("GET", f"{base_url}/auth/me", token=token)
    if error:
        return token, {}, f"Login ok, but profile failed: {error}", "Signed in", "", ""

    display = f"Signed in as {user_payload.get('email', '')}"
    return (
        token,
        user_payload,
        "Login ok.",
        display,
        user_payload.get("email") or "",
        user_payload.get("full_name") or "",
    )


def register_action(api_url: str, email: str, password: str, full_name: str) -> str:
    base_url = _normalize_api_url(api_url)
    if not email or not password:
        return "Provide email and password."

    payload = {"email": email, "password": password, "full_name": full_name or None}
    _, error = _request_json("POST", f"{base_url}/auth/register", json=payload)
    if error:
        return f"Register failed: {error}"
    return "Register ok. Now login."


def _scan_choices(scans: list[dict]) -> list[tuple[str, int]]:
    choices = []
    for scan in scans:
        label = f"#{scan['id']} {scan['target_name']} ({scan['risk_level']})"
        choices.append((label, scan["id"]))
    return choices


def _scan_rows(scans: list[dict]) -> list[list[Any]]:
    rows = []
    for scan in scans:
        rows.append(
            [
                scan.get("id"),
                scan.get("target_name"),
                scan.get("target_type"),
                scan.get("risk_score"),
                scan.get("risk_level"),
                scan.get("started_at"),
            ]
        )
    return rows


def _metric_cards(scans: list[dict]) -> str:
    total = len(scans)
    if not scans:
        return """
        <div class="metric-grid">
          <div class="metric-card">
            <div class="metric-label">Total scans</div>
            <div class="metric-value">0</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Avg risk</div>
            <div class="metric-value">0.0</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Latest target</div>
            <div class="metric-value">-</div>
          </div>
        </div>
        """

    avg = sum(scan.get("risk_score", 0.0) for scan in scans) / total
    latest = scans[0]
    return f"""
    <div class="metric-grid">
      <div class="metric-card">
        <div class="metric-label">Total scans</div>
        <div class="metric-value">{total}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Avg risk</div>
        <div class="metric-value">{avg:.2f}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Latest target</div>
        <div class="metric-value">{latest.get('target_name', '-')}</div>
      </div>
    </div>
    """


def refresh_scans(
    api_url: str, token: str
) -> tuple[list[dict], str, list[list[Any]], str, dict, dict, dict]:
    if not token:
        empty = []
        return (
            empty,
            _metric_cards(empty),
            [],
            "Login required.",
            gr.update(choices=[], value=None),
            gr.update(choices=[], value=None),
            gr.update(choices=[], value=None),
        )

    base_url = _normalize_api_url(api_url)
    scans, error = _request_json("GET", f"{base_url}/scans", token=token)
    if error:
        empty = []
        return (
            empty,
            _metric_cards(empty),
            [],
            f"Failed to load scans: {error}",
            gr.update(choices=[], value=None),
            gr.update(choices=[], value=None),
            gr.update(choices=[], value=None),
        )

    choices = _scan_choices(scans)
    return (
        scans,
        _metric_cards(scans),
        _scan_rows(scans),
        f"Loaded {len(scans)} scans.",
        gr.update(choices=choices, value=choices[0][1] if choices else None),
        gr.update(choices=choices, value=choices[0][1] if choices else None),
        gr.update(choices=choices, value=choices[0][1] if choices else None),
    )


def _scan_summary(scan: dict) -> str:
    return f"""
    <div class="metric-grid">
      <div class="metric-card">
        <div class="metric-label">Target</div>
        <div class="metric-value">{scan.get('target_name', '-')}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Risk</div>
        <div class="metric-value">{scan.get('risk_score', 0.0)} ({scan.get('risk_level', '-')})</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Strength</div>
        <div class="metric-value">{scan.get('strength_score', 0.0)}</div>
      </div>
    </div>
    """


def load_findings(
    api_url: str, token: str, scan_id: int | None, severity: str
) -> tuple[list[list[Any]], str, str]:
    if not token:
        return [], "Login required.", ""
    if not scan_id:
        return [], "Select a scan.", ""

    base_url = _normalize_api_url(api_url)
    scan, error = _request_json("GET", f"{base_url}/scans/{scan_id}", token=token)
    if error:
        return [], f"Failed to load scan: {error}", ""

    findings = scan.get("findings", [])
    if severity and severity != "all":
        findings = [f for f in findings if f.get("severity") == severity]

    rows = []
    for finding in findings:
        rows.append(
            [
                finding.get("severity"),
                finding.get("title"),
                finding.get("description"),
                finding.get("recommendation"),
                finding.get("evidence") or "-",
            ]
        )

    return rows, f"Loaded {len(findings)} findings.", _scan_summary(scan)


def load_recommendations(
    api_url: str, token: str, scan_id: int | None
) -> tuple[list[list[Any]], str]:
    if not token:
        return [], "Login required."
    if not scan_id:
        return [], "Select a scan."

    base_url = _normalize_api_url(api_url)
    scan, error = _request_json("GET", f"{base_url}/scans/{scan_id}", token=token)
    if error:
        return [], f"Failed to load scan: {error}"

    rows = []
    for item in scan.get("recommendations", []):
        rows.append(
            [
                item.get("severity"),
                item.get("title"),
                item.get("recommendation"),
            ]
        )

    return rows, f"Loaded {len(rows)} recommendations."


def download_report_pdf(
    api_url: str, token: str, scan_id: int | None
) -> tuple[str | None, str]:
    if not token:
        return None, "Login required."
    if not scan_id:
        return None, "Select a scan."

    base_url = _normalize_api_url(api_url)
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(
            f"{base_url}/reports/{scan_id}?format=pdf",
            headers=headers,
            timeout=DEFAULT_TIMEOUT,
        )
    except requests.RequestException as exc:
        return None, f"Download failed: {exc}"

    if response.status_code >= 400:
        return None, f"Download failed: {response.status_code}"

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    tmp.write(response.content)
    tmp.flush()
    tmp.close()
    return tmp.name, "PDF ready."


def download_report_json(
    api_url: str, token: str, scan_id: int | None
) -> tuple[str | None, str]:
    if not token:
        return None, "Login required."
    if not scan_id:
        return None, "Select a scan."

    base_url = _normalize_api_url(api_url)
    payload, error = _request_json("GET", f"{base_url}/reports/{scan_id}", token=token)
    if error:
        return None, f"Download failed: {error}"

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    tmp.write(json.dumps(payload, indent=2).encode("utf-8"))
    tmp.flush()
    tmp.close()
    return tmp.name, "JSON ready."


def load_report_html(api_url: str, token: str, scan_id: int | None) -> str:
    if not token:
        return "Login required."
    if not scan_id:
        return "Select a scan."

    base_url = _normalize_api_url(api_url)
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(
            f"{base_url}/reports/{scan_id}?format=html",
            headers=headers,
            timeout=DEFAULT_TIMEOUT,
        )
    except requests.RequestException as exc:
        return f"Failed to load report: {exc}"

    if response.status_code >= 400:
        return f"Failed to load report: {response.status_code}"

    return response.text


def create_scan(
    api_url: str,
    token: str,
    target_name: str,
    db_type: str,
    host: str,
    port: float | None,
    username: str,
    password: str,
    database: str,
    ssl: bool,
) -> tuple[str, dict]:
    if not token:
        return "Login required.", {}

    base_url = _normalize_api_url(api_url)
    payload = {
        "target_name": target_name,
        "target": {
            "db_type": db_type,
            "host": host,
            "username": username,
            "password": password,
            "database": database,
            "ssl": bool(ssl),
        },
    }

    if port and port > 0:
        payload["target"]["port"] = int(port)

    result, error = _request_json("POST", f"{base_url}/scans", token=token, json=payload)
    if error:
        return f"Scan failed: {error}", {}
    return "Scan completed.", result


def update_profile(
    api_url: str, token: str, full_name: str, password: str
) -> str:
    if not token:
        return "Login required."

    payload: dict[str, Any] = {}
    if full_name:
        payload["full_name"] = full_name
    if password:
        payload["password"] = password

    if not payload:
        return "No changes to update."

    base_url = _normalize_api_url(api_url)
    _, error = _request_json("PUT", f"{base_url}/users/me", token=token, json=payload)
    if error:
        return f"Update failed: {error}"
    return "Profile updated."


def set_screen(screen: str) -> tuple[dict, dict, dict, dict, dict, dict]:
    return (
        gr.update(visible=screen == "Login"),
        gr.update(visible=screen == "Dashboard"),
        gr.update(visible=screen == "Vulnerabilidades"),
        gr.update(visible=screen == "Recomendaciones"),
        gr.update(visible=screen == "Nuevo scan"),
        gr.update(visible=screen == "Perfil"),
    )


with gr.Blocks(css=CSS, title="SQLHawk Frontend") as demo:
    token_state = gr.State("")
    user_state = gr.State({})
    scans_state = gr.State([])

    with gr.Row():
        with gr.Column(scale=1, elem_id="sidebar"):
            gr.Markdown("## Control")
            api_url_input = gr.Textbox(label="API URL", value=DEFAULT_API_URL)
            api_ping_btn = gr.Button("Probar API")
            api_status = gr.Markdown("Listo.")

            nav = gr.Radio(
                label="Navegacion",
                choices=[
                    "Login",
                    "Dashboard",
                    "Vulnerabilidades",
                    "Recomendaciones",
                    "Nuevo scan",
                    "Perfil",
                ],
                value="Login",
                elem_id="nav",
            )
            login_badge = gr.Markdown("Not signed in")

        with gr.Column(scale=3):
            gr.HTML(
                """
                <div id="hero">
                  <div class="hero-title">SQLHawk</div>
                  <div class="hero-sub">Visibilidad de seguridad para tus bases de datos.</div>
                </div>
                """,
                elem_id="hero",
            )

            with gr.Group(visible=True) as login_group:
                with gr.Group(elem_classes=["panel"]):
                    gr.Markdown("### Login")
                    with gr.Row():
                        login_email = gr.Textbox(label="Email")
                        login_password = gr.Textbox(label="Password", type="password")
                    login_btn = gr.Button("Entrar")
                    login_status = gr.Markdown()

                with gr.Group(elem_classes=["panel"]):
                    gr.Markdown("### Registro")
                    with gr.Row():
                        register_email = gr.Textbox(label="Email")
                        register_password = gr.Textbox(label="Password", type="password")
                    register_name = gr.Textbox(label="Full name (optional)")
                    register_btn = gr.Button("Crear cuenta")
                    register_status = gr.Markdown()

            with gr.Group(visible=False) as dashboard_group:
                with gr.Group(elem_classes=["panel"]):
                    gr.Markdown("### Dashboard")
                    dashboard_metrics = gr.HTML()
                    refresh_btn = gr.Button("Refrescar scans")
                    dashboard_status = gr.Markdown()
                    scan_table = gr.Dataframe(
                        headers=["ID", "Target", "Type", "Risk", "Level", "Started"],
                        datatype=["number", "str", "str", "number", "str", "str"],
                        interactive=False,
                        elem_classes=["dataframe"],
                    )

            with gr.Group(visible=False) as vuln_group:
                with gr.Group(elem_classes=["panel"]):
                    gr.Markdown("### Vulnerabilidades")
                    with gr.Row():
                        vuln_scan = gr.Dropdown(label="Scan", choices=[])
                        vuln_severity = gr.Dropdown(
                            label="Severity",
                            choices=["all", "low", "medium", "high", "critical"],
                            value="all",
                        )
                    vuln_load = gr.Button("Cargar findings")
                    vuln_status = gr.Markdown()
                    vuln_summary = gr.HTML()
                    vuln_table = gr.Dataframe(
                        headers=[
                            "Severity",
                            "Title",
                            "Description",
                            "Recommendation",
                            "Evidence",
                        ],
                        datatype=["str", "str", "str", "str", "str"],
                        interactive=False,
                        elem_classes=["dataframe"],
                    )

            with gr.Group(visible=False) as reco_group:
                with gr.Group(elem_classes=["panel"]):
                    gr.Markdown("### Recomendaciones")
                    reco_scan = gr.Dropdown(label="Scan", choices=[])
                    reco_load = gr.Button("Cargar recomendaciones")
                    reco_status = gr.Markdown()
                    reco_table = gr.Dataframe(
                        headers=["Severity", "Title", "Recommendation"],
                        datatype=["str", "str", "str"],
                        interactive=False,
                        elem_classes=["dataframe"],
                    )
                    gr.HTML("<div style='margin-top: 10px;'><span class='badge'>Descargas</span></div>")
                    report_scan = gr.Dropdown(label="Scan para reporte", choices=[])
                    with gr.Row():
                        report_pdf_btn = gr.Button("Descargar PDF")
                        report_json_btn = gr.Button("Descargar JSON")
                        report_html_btn = gr.Button("Ver HTML")
                    report_status = gr.Markdown()
                    report_file = gr.File(label="Archivo", interactive=False)
                    report_html = gr.HTML()

            with gr.Group(visible=False) as scan_group:
                with gr.Group(elem_classes=["panel"]):
                    gr.Markdown("### Nuevo scan")
                    target_name = gr.Textbox(label="Target name")
                    with gr.Row():
                        db_type = gr.Dropdown(
                            label="DB type",
                            choices=["postgres", "mysql", "workbench"],
                            value="postgres",
                        )
                        host = gr.Textbox(label="Host", value="127.0.0.1")
                        port = gr.Number(label="Port", value=5432)
                    with gr.Row():
                        username = gr.Textbox(label="Username")
                        password = gr.Textbox(label="Password", type="password")
                    database = gr.Textbox(label="Database")
                    ssl = gr.Checkbox(label="Use SSL", value=False)
                    scan_btn = gr.Button("Ejecutar scan")
                    scan_status = gr.Markdown()
                    scan_result = gr.JSON()

            with gr.Group(visible=False) as profile_group:
                with gr.Group(elem_classes=["panel"]):
                    gr.Markdown("### Perfil")
                    profile_email = gr.Textbox(label="Email", interactive=False)
                    profile_name = gr.Textbox(label="Full name")
                    profile_password = gr.Textbox(label="New password", type="password")
                    profile_btn = gr.Button("Actualizar perfil")
                    profile_status = gr.Markdown()

    api_ping_btn.click(ping_api, inputs=[api_url_input], outputs=[api_status])

    login_btn.click(
        login_action,
        inputs=[api_url_input, login_email, login_password],
        outputs=[
            token_state,
            user_state,
            login_status,
            login_badge,
            profile_email,
            profile_name,
        ],
    ).then(
        refresh_scans,
        inputs=[api_url_input, token_state],
        outputs=[
            scans_state,
            dashboard_metrics,
            scan_table,
            dashboard_status,
            vuln_scan,
            reco_scan,
            report_scan,
        ],
    )

    register_btn.click(
        register_action,
        inputs=[api_url_input, register_email, register_password, register_name],
        outputs=[register_status],
    )

    refresh_btn.click(
        refresh_scans,
        inputs=[api_url_input, token_state],
        outputs=[
            scans_state,
            dashboard_metrics,
            scan_table,
            dashboard_status,
            vuln_scan,
            reco_scan,
            report_scan,
        ],
    )

    vuln_load.click(
        load_findings,
        inputs=[api_url_input, token_state, vuln_scan, vuln_severity],
        outputs=[vuln_table, vuln_status, vuln_summary],
    )

    reco_load.click(
        load_recommendations,
        inputs=[api_url_input, token_state, reco_scan],
        outputs=[reco_table, reco_status],
    )

    report_pdf_btn.click(
        download_report_pdf,
        inputs=[api_url_input, token_state, report_scan],
        outputs=[report_file, report_status],
    )

    report_json_btn.click(
        download_report_json,
        inputs=[api_url_input, token_state, report_scan],
        outputs=[report_file, report_status],
    )

    report_html_btn.click(
        load_report_html,
        inputs=[api_url_input, token_state, report_scan],
        outputs=[report_html],
    )

    scan_btn.click(
        create_scan,
        inputs=[
            api_url_input,
            token_state,
            target_name,
            db_type,
            host,
            port,
            username,
            password,
            database,
            ssl,
        ],
        outputs=[scan_status, scan_result],
    ).then(
        refresh_scans,
        inputs=[api_url_input, token_state],
        outputs=[
            scans_state,
            dashboard_metrics,
            scan_table,
            dashboard_status,
            vuln_scan,
            reco_scan,
            report_scan,
        ],
    )

    profile_btn.click(
        update_profile,
        inputs=[api_url_input, token_state, profile_name, profile_password],
        outputs=[profile_status],
    )

    nav.change(
        set_screen,
        inputs=[nav],
        outputs=[
            login_group,
            dashboard_group,
            vuln_group,
            reco_group,
            scan_group,
            profile_group,
        ],
    )


def main() -> None:
    demo.launch(server_name="0.0.0.0", server_port=DEFAULT_PORT, show_api=False)


if __name__ == "__main__":
    main()

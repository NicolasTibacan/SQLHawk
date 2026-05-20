from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import SQLAlchemyError

from .risk import score_findings
from ..schemas.scan import TargetConnection


def run_scan(target: TargetConnection) -> dict:
    db_type = _normalize_db_type(target.db_type)
    url = _build_target_url(target, db_type)
    findings: list[dict] = []
    engine = None

    try:
        connect_args = _build_connect_args(target, db_type)
        engine = create_engine(url, pool_pre_ping=True, connect_args=connect_args)
        with engine.connect() as connection:
            _check_transport_security(connection, target, db_type, findings)
            if db_type == "postgres":
                _postgres_checks(connection, findings)
            elif db_type == "mysql":
                _mysql_checks(connection, findings)
    except SQLAlchemyError:
        findings.append(
            {
                "title": "Connection failed",
                "description": "The target database could not be reached or authenticated.",
                "severity": "critical",
                "evidence": None,
                "recommendation": "Verify host, port, and credentials. Ensure the DB is reachable.",
            }
        )
    finally:
        if engine is not None:
            try:
                engine.dispose()
            except Exception:
                pass

    _optional_port_check(target, db_type, findings)

    risk_score, risk_level, strength_score = score_findings(findings)
    recommendations = _collect_recommendations(findings)

    return {
        "target_type": db_type,
        "findings": findings,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "strength_score": strength_score,
        "recommendations": recommendations,
    }


def _normalize_db_type(db_type: str) -> str:
    normalized = db_type.strip().lower()
    if normalized in {"postgres", "postgresql"}:
        return "postgres"
    if normalized in {"mysql", "mariadb", "workbench", "mysql-workbench", "mysql_workbench"}:
        return "mysql"
    raise ValueError("Unsupported db_type")


def _build_target_url(target: TargetConnection, db_type: str) -> URL:
    if db_type == "postgres":
        driver = "postgresql+psycopg2"
        port = target.port or 5432
        query = {"sslmode": "require"} if target.ssl else None
    else:
        driver = "mysql+pymysql"
        port = target.port or 3306
        query = None

    return URL.create(
        drivername=driver,
        username=target.username,
        password=target.password,
        host=target.host,
        port=port,
        database=target.database,
        query=query,
    )


def _build_connect_args(target: TargetConnection, db_type: str) -> dict:
    if db_type == "mysql" and target.ssl:
        return {"ssl": {}}
    return {}


def _postgres_checks(connection, findings: list[dict]) -> None:
    access_limited = False

    def safe_fetch(query: str, mark_limited: bool = True):
        nonlocal access_limited
        try:
            return connection.execute(text(query)).fetchall()
        except Exception:
            if mark_limited:
                access_limited = True
            return []

    superusers = safe_fetch("SELECT rolname FROM pg_roles WHERE rolsuper IS TRUE")
    if superusers:
        names = ", ".join(row[0] for row in superusers)
        findings.append(
            {
                "title": "Superuser roles detected",
                "description": "There are roles with superuser privileges.",
                "severity": "high",
                "evidence": names,
                "recommendation": "Limit superuser roles and use least privilege.",
            }
        )

    createdb_roles = safe_fetch("SELECT rolname FROM pg_roles WHERE rolcreatedb IS TRUE")
    if createdb_roles:
        names = ", ".join(row[0] for row in createdb_roles)
        findings.append(
            {
                "title": "Roles with CREATEDB privilege",
                "description": "Some roles can create databases.",
                "severity": "medium",
                "evidence": names,
                "recommendation": "Restrict database creation to admin roles only.",
            }
        )

    createrole_roles = safe_fetch(
        "SELECT rolname FROM pg_roles WHERE rolcreaterole IS TRUE"
    )
    if createrole_roles:
        names = ", ".join(row[0] for row in createrole_roles)
        findings.append(
            {
                "title": "Roles with CREATEROLE privilege",
                "description": "Some roles can create or alter roles.",
                "severity": "medium",
                "evidence": names,
                "recommendation": "Restrict role management to admin roles only.",
            }
        )

    encryption = safe_fetch("SHOW password_encryption")
    if encryption:
        value = str(encryption[0][0])
        if value.lower() == "md5":
            findings.append(
                {
                    "title": "Weak password encryption",
                    "description": "password_encryption is set to md5.",
                    "severity": "medium",
                    "evidence": value,
                    "recommendation": "Use scram-sha-256 for password encryption.",
                }
            )

    ssl_state = safe_fetch("SHOW ssl")
    if ssl_state:
        value = str(ssl_state[0][0])
        if value.lower() in {"off", "false", "0"}:
            findings.append(
                {
                    "title": "SSL is disabled",
                    "description": "Database connections are not forced to use SSL.",
                    "severity": "medium",
                    "evidence": value,
                    "recommendation": "Enable SSL and enforce encrypted connections.",
                }
            )

    if access_limited:
        findings.append(
            {
                "title": "Limited metadata access",
                "description": "Some security checks were skipped due to limited privileges.",
                "severity": "low",
                "evidence": None,
                "recommendation": "Use a read-only account with access to system catalogs.",
            }
        )


def _mysql_checks(connection, findings: list[dict]) -> None:
    access_limited = False

    def safe_fetch(query: str, mark_limited: bool = True):
        nonlocal access_limited
        try:
            return connection.execute(text(query)).fetchall()
        except Exception:
            if mark_limited:
                access_limited = True
            return []

    anonymous_users = safe_fetch("SELECT user, host FROM mysql.user WHERE user = ''")
    if anonymous_users:
        names = ", ".join(f"{row[0]}@{row[1]}" for row in anonymous_users)
        findings.append(
            {
                "title": "Anonymous users detected",
                "description": "There are anonymous accounts in mysql.user.",
                "severity": "high",
                "evidence": names,
                "recommendation": "Remove anonymous accounts or restrict them.",
            }
        )

    remote_root = safe_fetch(
        "SELECT user, host FROM mysql.user WHERE user = 'root' "
        "AND host NOT IN ('localhost', '127.0.0.1', '::1')"
    )
    if remote_root:
        names = ", ".join(f"{row[0]}@{row[1]}" for row in remote_root)
        findings.append(
            {
                "title": "Remote root accounts",
                "description": "Root can log in from remote hosts.",
                "severity": "critical",
                "evidence": names,
                "recommendation": "Limit root to localhost and use admin roles instead.",
            }
        )

    super_priv = safe_fetch("SELECT user, host FROM mysql.user WHERE Super_priv = 'Y'")
    if super_priv:
        names = ", ".join(f"{row[0]}@{row[1]}" for row in super_priv)
        findings.append(
            {
                "title": "Users with SUPER privilege",
                "description": "Accounts with SUPER privileges were found.",
                "severity": "high",
                "evidence": names,
                "recommendation": "Reduce SUPER privilege usage to admin-only accounts.",
            }
        )

    empty_passwords = safe_fetch(
        "SELECT user, host FROM mysql.user WHERE authentication_string = '' "
        "OR authentication_string IS NULL",
        mark_limited=False,
    )
    if not empty_passwords:
        empty_passwords = safe_fetch(
            "SELECT user, host FROM mysql.user WHERE password = '' OR password IS NULL",
            mark_limited=False,
        )
    if empty_passwords:
        names = ", ".join(f"{row[0]}@{row[1]}" for row in empty_passwords)
        findings.append(
            {
                "title": "Accounts without passwords",
                "description": "Some MySQL accounts have empty passwords.",
                "severity": "critical",
                "evidence": names,
                "recommendation": "Set strong passwords and disable unused accounts.",
            }
        )

    local_infile = safe_fetch("SHOW VARIABLES LIKE 'local_infile'")
    if local_infile and str(local_infile[0][1]).lower() in {"on", "1"}:
        findings.append(
            {
                "title": "local_infile enabled",
                "description": "The local_infile option is enabled.",
                "severity": "medium",
                "evidence": str(local_infile[0][1]),
                "recommendation": "Disable local_infile unless required.",
            }
        )

    secure_transport = safe_fetch("SHOW VARIABLES LIKE 'require_secure_transport'")
    if secure_transport and str(secure_transport[0][1]).lower() in {"off", "0"}:
        findings.append(
            {
                "title": "SSL not enforced",
                "description": "Secure transport is not required.",
                "severity": "medium",
                "evidence": str(secure_transport[0][1]),
                "recommendation": "Require SSL and enforce encrypted connections.",
            }
        )

    password_policy = safe_fetch("SHOW VARIABLES LIKE 'validate_password.policy'", mark_limited=False)
    if password_policy:
        value = str(password_policy[0][1]).lower()
        if value in {"low", "0"}:
            findings.append(
                {
                    "title": "Weak password policy",
                    "description": "validate_password policy is low.",
                    "severity": "medium",
                    "evidence": value,
                    "recommendation": "Set validate_password.policy to MEDIUM or STRONG.",
                }
            )
    else:
        findings.append(
            {
                "title": "Password policy not enforced",
                "description": "validate_password plugin is not enabled.",
                "severity": "low",
                "evidence": None,
                "recommendation": "Enable validate_password to enforce strong passwords.",
            }
        )

    secure_file_priv = safe_fetch("SHOW VARIABLES LIKE 'secure_file_priv'", mark_limited=False)
    if secure_file_priv and str(secure_file_priv[0][1]).strip() == "":
        findings.append(
            {
                "title": "Unrestricted file import/export",
                "description": "secure_file_priv is empty, allowing file access from any path.",
                "severity": "medium",
                "evidence": "(empty)",
                "recommendation": "Set secure_file_priv to a restricted directory.",
            }
        )

    password_lifetime = safe_fetch(
        "SHOW VARIABLES LIKE 'default_password_lifetime'",
        mark_limited=False,
    )
    if password_lifetime and str(password_lifetime[0][1]) in {"0", "-1"}:
        findings.append(
            {
                "title": "Passwords never expire",
                "description": "default_password_lifetime disables password rotation.",
                "severity": "low",
                "evidence": str(password_lifetime[0][1]),
                "recommendation": "Set a password rotation policy.",
            }
        )

    if access_limited:
        findings.append(
            {
                "title": "Limited metadata access",
                "description": "Some security checks were skipped due to limited privileges.",
                "severity": "low",
                "evidence": None,
                "recommendation": "Use a read-only account with access to system tables.",
            }
        )


def _check_transport_security(connection, target: TargetConnection, db_type: str, findings: list[dict]) -> None:
    ssl_active = None
    try:
        if db_type == "postgres":
            rows = connection.execute(
                text("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
            ).fetchall()
            if rows:
                ssl_active = bool(rows[0][0])
        elif db_type == "mysql":
            rows = connection.execute(text("SHOW STATUS LIKE 'Ssl_cipher'")).fetchall()
            if rows:
                ssl_active = bool(rows[0][1])
    except Exception:
        ssl_active = None

    if ssl_active is False:
        findings.append(
            {
                "title": "Connection not encrypted",
                "description": "The database connection is not using TLS.",
                "severity": "medium",
                "evidence": None,
                "recommendation": "Enable TLS and require encrypted connections.",
            }
        )
    elif ssl_active is None and not target.ssl and not _is_local_host(target.host):
        findings.append(
            {
                "title": "TLS not requested",
                "description": "The scan connection was made without TLS enabled.",
                "severity": "low",
                "evidence": None,
                "recommendation": "Enable TLS when scanning remote databases.",
            }
        )


def _is_local_host(host: str) -> bool:
    normalized = host.strip().lower()
    return normalized in {"localhost", "127.0.0.1", "::1"}


def _optional_port_check(
    target: TargetConnection, db_type: str, findings: list[dict]
) -> None:
    try:
        import nmap  # type: ignore
    except Exception:
        return

    port = target.port or (5432 if db_type == "postgres" else 3306)
    try:
        scanner = nmap.PortScanner()
        scanner.scan(
            hosts=target.host,
            ports=str(port),
            arguments="-sT -Pn --host-timeout 5s",
        )
        state = (
            scanner[target.host]["tcp"][port]["state"]
            if target.host in scanner.all_hosts()
            else None
        )
        if state == "open":
            findings.append(
                {
                    "title": "DB port exposed",
                    "description": "The database port is reachable on the network.",
                    "severity": "low",
                    "evidence": f"tcp/{port} open",
                    "recommendation": "Restrict access with firewall rules or private networks.",
                }
            )
    except Exception:
        findings.append(
            {
                "title": "Port scan skipped",
                "description": "Optional port scan could not be completed.",
                "severity": "low",
                "evidence": None,
                "recommendation": "Ensure nmap is installed and the host is reachable.",
            }
        )


def _collect_recommendations(findings: list[dict]) -> list[dict]:
    recommendations = []
    for finding in findings:
        recommendations.append(
            {
                "title": finding.get("title"),
                "recommendation": finding.get("recommendation"),
                "severity": finding.get("severity"),
            }
        )
    return recommendations

# SQLHawk

SQLHawk es una plataforma de seguridad que analiza metadatos de bases de datos para detectar patrones de riesgo comunes y generar recomendaciones. Incluye un backend en FastAPI y un frontend en Gradio con pantallas para login, vulnerabilidades y descargas de reportes.

## Objetivo
Ofrecer un flujo simple para:
- autenticar usuarios,
- ejecutar scans de solo metadatos,
- visualizar hallazgos y recomendaciones,
- descargar reportes en varios formatos.

## Alcance
- Compatible con PostgreSQL y MySQL.
- Analisis no invasivo: no altera la base objetivo.
- Resultados almacenados por usuario.

## Arquitectura (alto nivel)
- Frontend (Gradio): UI multi pantalla, consume el API.
- Backend (FastAPI): auth, scans, reportes.
- DB del API: SQLite por defecto (o Postgres via API_DATABASE_URL).
- Reportes: HTML y PDF generados bajo demanda.

## Flujo general
1) El usuario se autentica en el frontend.
2) El frontend consume el API para listar scans o crear uno nuevo.
3) El backend se conecta a la base objetivo y ejecuta checks de metadatos.
4) Se guardan resultados, y los reportes se generan bajo demanda.

## Requisitos
- Python 3.10+
- Backend ejecutandose en http://localhost:8000 (por defecto)
- Acceso de red a las bases objetivo
- (Opcional) nmap instalado si se desea check de puertos

## Instalacion y ejecucion local
### 1) Backend
```
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

Crea backend/.env con estas variables minimas:
```
API_DATABASE_URL=sqlite:///./data/sqlhawk.db
JWT_SECRET_KEY=change-me
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRES_MINUTES=60
REPORTS_DIR=./data/reports
```

Luego inicia el servidor:
```
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 2) Frontend (Gradio)
```
python -m venv .venv
source .venv/bin/activate
pip install -r frontend/requirements.txt
export API_BASE_URL="http://localhost:8000"
python frontend/app.py
```

Abrir la URL de Gradio (default: http://localhost:7860).

## Pantallas del frontend
- Login: registro y acceso.
- Dashboard: resumen de scans recientes y metricas.
- Vulnerabilidades: tabla de hallazgos por severidad.
- Recomendaciones: recomendaciones y descargas de reportes.
- Nuevo scan: formulario para crear un scan.
- Perfil: actualizar nombre o password.

## API principal (resumen)
- POST /auth/register: crear cuenta.
- POST /auth/login: obtener token.
- GET /auth/me: obtener perfil.
- PUT /users/me: actualizar perfil.
- POST /scans: crear scan.
- GET /scans: listar scans.
- GET /scans/{id}: detalle de scan.
- GET /reports/{id}?format=html|json|pdf: generar reporte.

## Autenticacion
- El backend usa JWT. El frontend guarda el token en memoria y lo envia en cada request.
- Para llamadas directas al API, usar header:
```
Authorization: Bearer <token>
```

## Ejemplo de scan (request)
```
POST /scans
{
	"target_name": "db-produccion",
	"target": {
		"db_type": "postgres",
		"host": "127.0.0.1",
		"port": 5432,
		"username": "readonly",
		"password": "secret",
		"database": "app_db",
		"ssl": false
	}
}
```

## Que se evalua en los scans
Los checks son solo de metadatos. Ejemplos:
- PostgreSQL: roles superuser, CREATEDB, CREATEROLE, password_encryption, ssl.
- MySQL: usuarios anonimos, root remoto, SUPER, local_infile, require_secure_transport.

## Scoring
- Cada finding tiene severidad: low, medium, high, critical.
- risk_score se calcula sumando severidades y se limita a 10.
- strength_score se calcula como:

$$
strength\_score = 100 - risk\_score \times 10
$$

## Reportes y descargas
- JSON: datos estructurados para integraciones.
- HTML: reporte legible en navegador.
- PDF: reporte descargable para auditorias.

## Estructura del repositorio
```
backend/          API en FastAPI
frontend/         UI en Gradio
data/reports/     PDFs generados
README.md         Documentacion principal
```

## Configuracion
Backend (backend/.env):
- API_DATABASE_URL: URL de la base del API (default sqlite:///./data/sqlhawk.db)
- JWT_SECRET_KEY: secreto JWT
- JWT_ALGORITHM: algoritmo JWT (default HS256)
- ACCESS_TOKEN_EXPIRES_MINUTES: expiracion del token
- REPORTS_DIR: carpeta de reportes (default ./data/reports)

Frontend:
- API_BASE_URL: base del API (default http://localhost:8000)
- API_TIMEOUT: timeout en segundos (default 10)
- FRONTEND_PORT: puerto del frontend (default 7860)

## Seguridad recomendada
- Usar cuentas de solo lectura para la base objetivo.
- Evitar exponer el API publico sin auth.
- Rotar JWT_SECRET_KEY en entornos productivos.
- Proteger la carpeta de reportes si contiene datos sensibles.

## Troubleshooting
- Error 401: token invalido o expirado. Volver a loguear.
- Error de conexion: validar API_BASE_URL y que el backend este arriba.
- Scan falla: revisar host/puerto/credenciales de la DB objetivo.
- PDF vacio: revisar permisos de escritura en REPORTS_DIR.

## Notas y limitaciones
- El scanner solo lee metadatos y no modifica la base objetivo.
- Algunas validaciones pueden fallar si el usuario de DB tiene permisos limitados.
- El check de puertos depende de nmap (opcional).
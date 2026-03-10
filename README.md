# SOC Assist — Plataforma de Alerta Temprana en Ciberseguridad

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green?logo=fastapi)](https://fastapi.tiangolo.com)
[![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-purple?logo=bootstrap)](https://getbootstrap.com)
[![Version](https://img.shields.io/badge/Version-1.13-orange)](ROADMAP.md)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

**SOC Assist** es una plataforma web completa de evaluación y clasificación de eventos de ciberseguridad. Permite que analistas con distintos niveles de experiencia detecten señales de alerta, calculen un puntaje de riesgo estructurado, enriquezcan con inteligencia de amenazas en tiempo real y sepan exactamente qué hacer a continuación.

Incluye dos canales de evaluación complementarios:

- **Formulario Wizard** — 66 preguntas distribuidas en 12 bloques temáticos, con enriquecimiento TI automático inline
- **Chatbot Analista** — 4 modos de conversación (SOC · Ciudadano · Experto+ · Unificado) con routing inteligente que reduce las preguntas a 15–24 según la amenaza inferida

---

## Contenido

- [Características](#características)
- [Quickstart — Desarrollo local](#quickstart--desarrollo-local)
- [Quickstart — Docker (recomendado)](#quickstart--docker-recomendado)
- [Acceso desde otra máquina / red](#acceso-desde-otra-máquina--red)
- [Continuar desarrollo en otra PC](#continuar-desarrollo-en-otra-pc)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Variables de entorno](#variables-de-entorno)
- [Motor de Scoring](#motor-de-scoring)
- [Chatbot Multimodal](#chatbot-multimodal)
- [Threat Intelligence](#threat-intelligence)
- [API REST](#api-rest)
- [Seguridad y Autenticación](#seguridad-y-autenticación)
- [Multi-Tenant y Organizaciones](#multi-tenant-y-organizaciones)
- [CMDB y Activos](#cmdb-y-activos)
- [Panel de Administración](#panel-de-administración)
- [Integraciones Externas](#integraciones-externas)
- [Rutas HTTP Completas](#rutas-http-completas)
- [Modelo de Datos](#modelo-de-datos)
- [Arquitectura del Código](#arquitectura-del-código)

---

## Características

### Evaluación y Clasificación

| Característica | Detalle |
|----------------|---------|
| **Motor de scoring ponderado** | 66 preguntas, 9 módulos, pesos configurables, hard rules, multiplicadores |
| **5 niveles de clasificación** | Informativo · Sospechoso · Incidente · Crítico · Brecha |
| **Anti-anchoring** | El score numérico nunca se muestra al analista durante la evaluación |
| **12 bloques temáticos** | Bloque 0 (IoCs) → Bloques 1–11 (módulos especializados) |
| **Threat Intelligence inline** | VT/AbuseIPDB/IBM X-Force enriquece los indicadores en tiempo real |
| **Ajuste TI** | El analista puede aceptar/rechazar el ajuste de score sugerido por TI |
| **MITRE ATT&CK** | Técnicas mapeadas automáticamente según el perfil del incidente |
| **Playbooks** | Guías de respuesta configurables por nivel de clasificación |

### Chatbot Analista (4 modos)

| Modo | Audiencia | Preguntas |
|------|-----------|-----------|
| **SOC** | Analistas avanzados | 8 gateway + 8–16 dirigidas según amenaza inferida |
| **Experto+** | Especialistas DFIR | Variante SOC con preguntas forenses adicionales |
| **Ciudadano** | Público general / PYME | 68 preguntas simplificadas N/P1–P4 |
| **Unificado** | Todos | Modo combinado con escalada automática |

- Inferencia de categoría de amenaza (ransomware / phishing / APT / DDoS / insider / credential_theft)
- Auto-respuesta de preguntas desde resultados TI (q_003, q_006, q_007, q_009, q_062)
- Modo Simulacro (test_mode) para entrenamiento
- Historial de sesiones con replay
- REST API completa para integración SOAR/SIEM

### Gestión de Incidentes

- Dashboard con KPIs en tiempo real: MTTR, closure rate, distribución temporal
- Línea de tiempo por incidente con eventos auditados
- Búsqueda full-text y filtros avanzados (fecha, clasificación, analista, tag, organización)
- Comentarios con menciones
- Asignación de casos y seguimiento de responsable
- SLA Tracking: `resolved_at` automático, age buckets, métricas por nivel
- Tags libres (add/remove) con filtro `/incidentes?tag=xxx`
- Exportación CSV + impresión PDF
- Similitud coseno entre incidentes para clustering
- Adjuntos de evidencia (jpg/png/pdf/txt/log/csv/json/xml/zip/pcap — máx 10 MB)

### Administración y Seguridad

- Gestión completa de usuarios (crear/editar/roles/desactivar)
- Roles: `analyst` · `admin` · `super_admin`
- Autenticación 2FA TOTP (Google Authenticator / Authy)
- Tokens API con prefijo `soc_` y hash bcrypt (se muestran una sola vez)
- Códigos de recuperación de un solo uso
- Audit log completo paginado
- Backup ZIP bajo demanda (DB + config JSON)
- Rate limiting in-memory: 20 req/60s en `/evaluar`
- Panel multi-tenant con jerarquía de organizaciones

---

## Quickstart — Desarrollo local

```bash
# 1. Clonar
git clone https://github.com/jvarela90/SOC-Assist.git
cd SOC-Assist/soc_assist

# 2. Entorno virtual
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 3. Dependencias
pip install -r requirements.txt

# 4. Levantar
python run.py
# → http://127.0.0.1:8000
# Credenciales: admin / admin123
```

> La base de datos SQLite se crea automáticamente en `soc_assist.db`. No se requiere configuración previa.

---

## Quickstart — Docker (recomendado)

```bash
# Desarrollo (HTTP)
docker-compose up -d

# Producción con Nginx + TLS
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

- Acceder en `http://localhost:8000` (desarrollo) o `https://localhost` (producción)
- Volumen persistente: `./data` → `/app/data` dentro del contenedor
- Las variables de entorno se configuran en `.env` (ver sección siguiente)

---

## Acceso desde otra máquina / red

```bash
# En run.py está configurado host="0.0.0.0"
# Simplemente abre el firewall en el puerto 8000
# URL: http://<IP-del-servidor>:8000

# Para HTTPS en producción: editar nginx/nginx.conf con tu dominio/certificado
```

---

## Continuar desarrollo en otra PC

```bash
git clone https://github.com/jvarela90/SOC-Assist.git
cd SOC-Assist/soc_assist
python -m venv venv && venv/Scripts/activate
pip install -r requirements.txt
python run.py
```

El archivo `soc_assist.db` no se incluye en git (`.gitignore`). El servidor lo crea en el primer arranque con el usuario `admin/admin123`.

---

## Estructura del proyecto

```
soc_assist/
├── run.py                    # Entry point (uvicorn con reload)
├── requirements.txt          # 10 dependencias
├── Dockerfile
├── docker-compose.yml
├── nginx/
│   └── nginx.conf            # Reverse proxy + TLS
│
├── config_engine.json        # Pesos, umbrales, multiplicadores, hard rules
├── questions.json            # 66 preguntas (q_001–q_066), 12 bloques
├── playbooks.json            # Playbooks por nivel de clasificación
├── ti_config.json            # API keys TI + webhooks (NO en git)
├── smtp_config.json          # Configuración SMTP (NO en git)
│
└── app/
    ├── main.py               # FastAPI app + todos los routers + /health
    │
    ├── core/
    │   ├── constants.py      # Constantes globales (TI_TIMEOUT, PAGINATION_SIZE, etc.)
    │   ├── engine.py         # Motor de scoring ponderado
    │   ├── auth.py           # bcrypt + require_auth/require_admin + api_auth (Bearer/Basic/session)
    │   └── rate_limit.py     # Rate limiter in-memory (dependency FastAPI)
    │
    ├── models/
    │   └── database.py       # 14 modelos SQLAlchemy + init_db() + migración inline
    │
    ├── routes/
    │   ├── admin/            # Paquete — panel de administración
    │   │   ├── __init__.py   # Re-exporta router, importa sub-módulos
    │   │   ├── _base.py      # router + templates + helpers compartidos
    │   │   ├── config.py     # Pesos, umbrales, calibración
    │   │   ├── integrations.py # SMTP, webhooks, TI keys, TheHive
    │   │   ├── users.py      # CRUD usuarios + recovery codes
    │   │   └── security.py   # Audit log, API tokens, backup ZIP
    │   ├── form.py           # Wizard de evaluación + evaluar_submit
    │   ├── dashboard.py      # Dashboard KPIs + historial + detalle
    │   ├── chatbot.py        # Chatbot web (AJAX endpoints)
    │   ├── chatbot_api.py    # REST API chatbot (/api/v1/chat/sessions)
    │   ├── api.py            # REST API incidentes (/api/v1/incidents)
    │   ├── ti.py             # TI lookup inline (/api/ti/lookup, /api/mac/lookup)
    │   ├── orgs.py           # CRUD organizaciones multi-tenant
    │   ├── assets.py         # CMDB activos + CSV import/export
    │   └── attachments.py    # Adjuntos de evidencia upload/serve/delete
    │
    ├── services/
    │   ├── chatbot_engine.py # Routing chatbot SOC: inference table, category routes
    │   ├── citizen_engine.py # Routing chatbot ciudadano: 68 preguntas N/P1-P4
    │   ├── chatbot_utils.py  # Helpers compartidos: jloads, load_session, run_ti_lookups
    │   ├── threat_intel.py   # VirusTotal / AbuseIPDB / IBM X-Force
    │   ├── mailer.py         # SMTP fire-and-forget
    │   ├── notifications.py  # Webhooks Teams/Slack fire-and-forget
    │   ├── scheduler.py      # check_asset_reviews() notificaciones in-app
    │   ├── similarity.py     # Similitud coseno entre incidentes
    │   ├── mitre.py          # Mapeo MITRE ATT&CK
    │   └── thehive.py        # Integración TheHive SOAR
    │
    ├── templates/            # 21 plantillas Jinja2 (Bootstrap 5.3 dark)
    │   ├── base.html
    │   ├── dashboard.html
    │   ├── form.html         # Wizard evaluación
    │   ├── detail.html       # Detalle de incidente
    │   ├── chatbot.html      # UI chatbot multimodal
    │   ├── admin.html        # Panel admin principal
    │   ├── users.html        # Gestión de usuarios
    │   ├── audit_log.html
    │   ├── api_tokens.html
    │   ├── assets.html       # CMDB activos
    │   ├── orgs.html         # Árbol organizacional
    │   └── ...               # thehive_config, chat_history, etc.
    │
    └── uploads/              # Adjuntos de evidencia (gitignored)
        └── {incident_id}/
            └── {uuid}{ext}
```

---

## Variables de entorno

| Variable | Default | Descripción |
|----------|---------|-------------|
| `DATABASE_URL` | SQLite local | URL SQLAlchemy (ej: `postgresql://user:pass@host/db`) |
| `SECRET_KEY` | `dev-secret-key` | Clave de firma para cookies de sesión |
| `ADMIN_PASSWORD` | `admin123` | Contraseña del usuario admin inicial |
| `UPLOAD_DIR` | `app/uploads` | Directorio para adjuntos de evidencia |
| `LOG_LEVEL` | `info` | Nivel de logging uvicorn |

Crear archivo `.env` en la raíz del proyecto (al mismo nivel que `run.py`):

```env
DATABASE_URL=postgresql://soc:secret@localhost/soc_assist
SECRET_KEY=cambia-esto-en-produccion
ADMIN_PASSWORD=contraseña-segura
```

---

## Motor de Scoring

### Arquitectura

```
Preguntas (66)
    ↓ respuesta × peso_pregunta
Suma por módulo
    ↓ × peso_módulo (config_engine.json)
Score base [0–100]
    ↓ hard rules (bypass umbrales)
    ↓ × multiplicador_TI (×1.5 malicioso / ×1.2 sospechoso)
    ↓ × multiplicador_asset (×0.8–×1.5 según criticidad CMDB)
Score final
    ↓ umbrales configurables
Clasificación (5 niveles)
```

### Módulos (9)

| ID | Módulo | Peso default |
|----|--------|-------------|
| `detection` | Detección y fuente | 15% |
| `lateral` | Movimiento lateral | 12% |
| `persistence` | Persistencia | 10% |
| `impact` | Impacto operativo | 20% |
| `data` | Compromiso de datos | 15% |
| `network` | Red y C2 | 12% |
| `identity` | Identidad y credenciales | 8% |
| `response` | Respuesta y contención | 5% |
| `context` | Contexto y vectores | 3% |

### Hard Rules

Condiciones que elevan el score automáticamente al umbral de `incidente` o `critico` independientemente del puntaje acumulado (configurables en `config_engine.json`).

### Calibración

- **Manual**: ajustar pesos desde el panel `/admin`
- **Automática**: recalibración basada en incidentes históricos con `calibration_target`
- Historial de pesos guardado en `WeightHistory` con trazabilidad completa

---

## Chatbot Multimodal

### Flujo SOC

```
1. Iniciar sesión → 8 preguntas gateway (q_002/q_008/q_027/q_029/q_038/q_046/q_048/q_057)
2. [Opcional] Enviar IoCs → TI lookup → auto-responde hasta 7 preguntas del Bloque 2
3. Inferencia de categoría → routing a 8–16 preguntas dirigidas
4. Resultado: clasificación + threat_classification + playbook
5. [Opcional] Crear incidente → redirect a /incidentes/{id}
```

### Categorías inferidas

| Categoría | Preguntas adicionales | Disparadores principales |
|-----------|----------------------|--------------------------|
| `ransomware` | 11 | q_048=yes, q_008=yes |
| `phishing` | 9 | q_057=yes |
| `apt_intrusion` | 16 | q_046=yes, q_002=siem_high |
| `ddos` | 5 | q_038=burst |
| `insider` | 10 | q_029=disabled_active |
| `credential_theft` | 8 | q_029=inactive |
| `unknown` | todas (66) | sin datos suficientes |

### Modo Simulacro

Activar `test_mode=true` al iniciar sesión — crea un `ChatSession` con `test_mode=True`, el incidente resultante se marca como simulacro y NO activa webhooks ni emails.

### Flujo Ciudadano

68 preguntas simplificadas con escala N (No sé) / P1–P4 (niveles de impacto). Sin terminología técnica. Resultado presenta recomendaciones en lenguaje accesible.

---

## Threat Intelligence

### Fuentes

| Fuente | Indicadores | API |
|--------|-------------|-----|
| VirusTotal v3 | IP, dominio, URL, hash | `virustotal.com/api/v3/` |
| AbuseIPDB v2 | IP | `api.abuseipdb.com/api/v2/check` |
| IBM X-Force | IP, dominio, hash | `api.xforce.ibmcloud.com/` |
| MAC OUI | MAC address | Lookup local + IEEE |

### Comportamiento

- Lookups en paralelo con `asyncio.gather` y timeout de 8 segundos (`TI_TIMEOUT`)
- Score TI se calcula con multiplicador: ×1.5 si malicioso, ×1.2 si sospechoso
- Banner de ajuste en el formulario: analista acepta/rechaza el ajuste propuesto
- En el chatbot: responde automáticamente q_003/q_006/q_007/q_009/q_062 con los resultados TI

### Configuración

Desde `/admin` → pestaña Integraciones → campo de API keys. Las claves se guardan en `ti_config.json` (excluido de git).

---

## API REST

### Autenticación

La API acepta tres métodos (en orden de prioridad):

1. **Cookie de sesión** — navegador autenticado
2. **Bearer token** — `Authorization: Bearer soc_xxxx`
3. **HTTP Basic** — `-u usuario:contraseña`

### Endpoints de Incidentes (`/api/v1/incidents`)

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/api/v1/incidents` | Lista paginada con filtros (page, classification, analyst) |
| `POST` | `/api/v1/incidents` | Crear incidente con scoring automático |
| `GET` | `/api/v1/incidents/{id}` | Detalle completo (incluyendo TI + contexto de red) |
| `POST` | `/api/v1/incidents/{id}/resolve` | Marcar como resuelto (setea resolved_at) |
| `POST` | `/api/v1/incidents/{id}/assign` | Asignar a analista |
| `GET` | `/api/v1/incidents/{id}/timeline` | Línea de tiempo del incidente |
| `GET` | `/api/v1/incidents/{id}/similar` | Incidentes similares (similitud coseno) |
| `POST` | `/api/v1/incidents/{id}/tags/add` | Añadir tag |
| `POST` | `/api/v1/incidents/{id}/tags/remove` | Eliminar tag |

### Endpoints de Chatbot (`/api/v1/chat`)

| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/api/v1/chat/sessions` | Iniciar sesión de chat |
| `GET` | `/api/v1/chat/sessions/{uuid}` | Estado completo de la sesión |
| `POST` | `/api/v1/chat/sessions/{uuid}/iocs` | Enviar IoCs para enriquecimiento TI |
| `POST` | `/api/v1/chat/sessions/{uuid}/answer` | Responder pregunta actual |
| `POST` | `/api/v1/chat/sessions/{uuid}/skip` | Omitir pregunta |
| `POST` | `/api/v1/chat/sessions/{uuid}/back` | Volver a pregunta anterior |
| `POST` | `/api/v1/chat/sessions/{uuid}/complete` | Finalizar y obtener resultado |
| `GET` | `/api/v1/chat/sessions/{uuid}/result` | Resultado completo |

### Ejemplo de uso (curl)

```bash
# 1. Crear sesión con IoCs
curl -X POST http://server:8000/api/v1/chat/sessions \
  -u admin:admin123 \
  -H "Content-Type: application/json" \
  -d '{"mode": "soc", "iocs": {"ip_src": "185.220.101.45", "ip_dst": "10.0.1.15"}}'

# 2. Responder pregunta gateway
curl -X POST http://server:8000/api/v1/chat/sessions/{uuid}/answer \
  -u admin:admin123 \
  -H "Content-Type: application/json" \
  -d '{"question_id": "q_002", "answer_value": "edr_av"}'

# 3. Finalizar y crear incidente
curl -X POST http://server:8000/api/v1/chat/sessions/{uuid}/complete \
  -u admin:admin123 \
  -H "Content-Type: application/json" \
  -d '{"create_incident": true}'

# 4. Listar incidentes recientes
curl -u admin:admin123 "http://server:8000/api/v1/incidents?page=1&classification=critico"
```

### Documentación interactiva

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

---

## Seguridad y Autenticación

### Flujo de autenticación

```
POST /login (username + password)
    ↓ bcrypt verify
    ↓ Si 2FA habilitado → redirect a /login/totp
    ↓ request.session["user"] = {id, username, role, org_id}
Sesión firmada con SECRET_KEY (cookie HTTP-only)
```

### 2FA TOTP

1. Admin activa TOTP en `/profile` o desde `/admin/usuarios`
2. Se genera `totp_secret` y se muestra el QR con `pyotp`
3. En cada login posterior: verificación del código de 6 dígitos

### Tokens API

```bash
# Desde /admin/api-tokens: crear token → se muestra UNA VEZ
# Formato: soc_ + 30 bytes urlsafe (ej: soc_abc123...)
# Almacenado como hash bcrypt con prefijo visible (primeros 8 chars)
# Uso: Authorization: Bearer soc_abc123...
```

### Códigos de recuperación

- Generados por admin desde `/admin/usuarios`
- Formato: `XXXXXX-XXXXXX-XXXXXX-XXXXXX` (A–Z + dígitos)
- Hash bcrypt almacenado en `User.recovery_code_hash`
- Un solo uso: se invalida automáticamente al usarse

### Rate Limiting

- Endpoint: `POST /evaluar` (submit del formulario)
- Límite: 20 requests por 60 segundos por IP
- Configurable en `app/core/constants.py`
- Respuesta: `HTTP 429` con header `Retry-After`

---

## Multi-Tenant y Organizaciones

### Jerarquía

```
central
  └── regional
        └── provincial
              └── local
```

- Tipos: `central` · `regional` · `provincial` · `local` · `flat` · `shift`
- Navegación BFS para obtener todos los descendientes
- `super_admin` ve todos los datos de todas las organizaciones
- `admin` ve su organización y sus descendientes
- `analyst` ve solo su organización

### Visibilidad de datos

```python
# get_visible_org_ids(user_dict, db) → list[int] | None
# None = super_admin (sin filtro)
# list = IDs de la org del usuario + todos sus descendientes
```

---

## CMDB y Activos

### Modelo de criticidad

| Criticidad | Multiplicador | Descripción |
|------------|--------------|-------------|
| 5 | ×1.5 | Misión crítica |
| 4 | ×1.3 | Producción importante |
| 3 | ×1.1 | Impacto moderado |
| 2 | ×0.9 | Uso rutinario |
| 1 | ×0.8 | Mínimo impacto |

### Funcionalidades

- CRUD completo de activos con contactos y ubicaciones
- Importación/exportación CSV con template descargable
- Revisión periódica con notificaciones in-app (`scheduler.py`)
- Búsqueda por identificador: IP exacta, hostname, CIDR (`lookup_asset_by_identifier`)
- Al evaluar un incidente: si la IP src/dst matchea un activo del CMDB, se aplica el multiplicador automáticamente

---

## Panel de Administración

### Acceso

- URL: `/admin`
- Requiere: `role = admin` o `role = super_admin`

### Secciones

| Sección | Ruta | Contenido |
|---------|------|-----------|
| **Principal** | `/admin` | Pesos de módulos, umbrales, multiplicadores, calibración manual/auto |
| **Usuarios** | `/admin/usuarios` | Lista, crear, editar rol/contraseña/notas, recovery codes |
| **TI Keys** | `/admin` (pestaña) | API keys VT/AbuseIPDB/X-Force (enmascaradas al mostrar) |
| **Webhooks** | `/admin` (pestaña) | Teams URL + Slack URL + habilitado/deshabilitado |
| **SMTP** | `/admin` (pestaña) | Host, puerto, TLS, usuario, contraseña, destinatarios |
| **TheHive** | `/admin/thehive` | URL, API key, organización, verify SSL |
| **Audit Log** | `/admin/audit-log` | Todas las acciones administrativas paginadas |
| **API Tokens** | `/admin/api-tokens` | Crear/revocar tokens API |
| **Backup** | `/admin/backup` | Descarga ZIP (DB + todos los JSON de configuración) |
| **Organizaciones** | `/admin/orgs` | Árbol jerárquico, crear/editar |

---

## Integraciones Externas

### Webhooks (Teams / Slack)

Notificaciones automáticas al clasificar un incidente como `critico` o `brecha` (umbral configurable en `ti_config.json`).

```json
// Payload Teams (Adaptive Card)
{
  "type": "message",
  "attachments": [{ "contentType": "application/vnd.microsoft.card.adaptive", ... }]
}
```

### Email SMTP

Fire-and-forget al crear incidentes clasificados. Configurable desde `/admin` → SMTP. Test de conexión disponible sin salir del panel.

### TheHive SOAR

Exportar incidentes a TheHive. Configuración desde `/admin/thehive`: URL base, API key, organización, verify SSL.

### MITRE ATT&CK

Mapeo automático de técnicas/tácticas basado en las respuestas del formulario. Se muestra en el detalle del incidente en formato tabla con enlaces a attack.mitre.org.

---

## Rutas HTTP Completas

### Públicas

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/` | Redirect a `/evaluar` |
| `GET` | `/health` | `{"status":"ok","version":"1.10.0"}` |
| `GET/POST` | `/login` | Formulario de login |
| `POST` | `/login/totp` | Verificación 2FA |
| `GET` | `/logout` | Cerrar sesión |

### Evaluación (require_auth)

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/evaluar` | Formulario wizard |
| `POST` | `/evaluar` | Enviar evaluación (rate limited) |
| `POST` | `/evaluar/apply-ti-adjustment` | Aplicar ajuste TI |

### Dashboard e Incidentes (require_auth)

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/dashboard` | KPIs y gráficos |
| `GET` | `/incidentes` | Lista con filtros y búsqueda |
| `GET` | `/incidentes/{id}` | Detalle completo |
| `POST` | `/incidentes/{id}/resolve` | Resolver/des-resolver |
| `POST` | `/incidentes/{id}/assign` | Asignar analista |
| `POST` | `/incidentes/{id}/comment` | Añadir comentario |
| `POST` | `/incidentes/{id}/tags/add` | Añadir tag |
| `POST` | `/incidentes/{id}/tags/remove` | Eliminar tag |

### Chatbot (require_auth)

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/chatbot` | UI chatbot |
| `GET` | `/chatbot/sessions` | Historial de sesiones |
| `POST` | `/chatbot/session/start` | Iniciar sesión |
| `POST` | `/chatbot/session/iocs` | Enviar IoCs |
| `POST` | `/chatbot/session/answer` | Responder pregunta |
| `POST` | `/chatbot/session/skip` | Omitir pregunta |
| `POST` | `/chatbot/session/back` | Volver a anterior |
| `POST` | `/chatbot/session/complete` | Finalizar |
| `POST` | `/chatbot/session/save` | Crear incidente |

### Adjuntos (require_auth)

| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/incidentes/{id}/adjuntar` | Subir adjunto |
| `GET` | `/adjuntos/{id}` | Servir adjunto |
| `DELETE` | `/adjuntos/{id}` | Eliminar adjunto |

### TI Inline (require_auth)

| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/api/ti/lookup` | Lookup TI de un indicador |
| `POST` | `/api/mac/lookup` | Lookup OUI de una MAC |

### Activos CMDB (require_auth)

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/activos` | Lista de activos |
| `POST` | `/activos/add` | Crear activo |
| `POST` | `/activos/{id}/edit` | Editar activo |
| `POST` | `/activos/{id}/delete` | Eliminar activo |
| `GET` | `/activos/export` | Exportar CSV |
| `POST` | `/activos/import` | Importar CSV |
| `GET` | `/activos/template` | Descargar template CSV |

### Organizaciones (require_admin)

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/admin/orgs` | Árbol de organizaciones |
| `POST` | `/admin/orgs/add` | Crear organización |
| `POST` | `/admin/orgs/{id}/edit` | Editar organización |
| `POST` | `/admin/orgs/{id}/delete` | Eliminar organización |

---

## Modelo de Datos

### Modelos principales (14)

#### User
```
id, username, password_hash, role (analyst|admin|super_admin)
is_active, organization_id, last_login, last_analysis_at
password_changed_at, notes, recovery_code_hash, recovery_set_at
totp_secret, totp_enabled
```

#### Incident
```
id, analyst_name, user_id, organization_id, asset_id
base_score, final_score, classification, category_label
network_context (JSON), ti_enrichment (JSON), ti_adjusted (bool)
asset_criticality_applied (bool), tags (JSON list)
resolved_at, assigned_to, timestamp
```

#### IncidentAnswer
```
id, incident_id, question_id, answer_value
question_text, question_module, score_contribution
```

#### ChatSession
```
id, session_uuid, user_id, organization_id, mode
status (active|completed|abandoned), phase (gateway|targeted|complete)
iocs (JSON), ti_results (JSON), ti_answers (JSON)
inferred_category, category_confidence, category_probs (JSON)
question_queue (JSON), answered_questions (JSON), answers (JSON)
messages (JSON), test_mode (bool)
final_score, final_classification, threat_classification (JSON)
incident_id, created_at, updated_at
```

#### Organization
```
id, name, slug, org_type, parent_id (self-ref FK)
is_active, settings (JSON), created_at
```

#### Asset
```
id, name, identifier, asset_type, criticality (1–5)
organization_id, description, tags (JSON)
last_reviewed_at, review_interval_days, created_at
contacts (relationship → AssetContact)
locations (relationship → AssetLocation)
```

#### APIToken
```
id, name, token_hash, token_prefix (8 chars)
user_id, organization_id, is_active, last_used_at, created_at
```

#### AuditLog
```
id, admin_user, action, target, details, ip, timestamp
```

#### WeightHistory / CalibrationLog
```
Historial de cambios de pesos del motor con trazabilidad completa
```

#### IncidentAttachment
```
id, incident_id, uploaded_by, filename, stored_name
file_size, mime_type, description, created_at
```

### Migraciones

El sistema usa migraciones inline en `_run_migrations()` dentro de `init_db()`:

```python
# Patrón: try/except por columna, ignorar si ya existe (SQLite compatible)
try:
    db.execute(text("ALTER TABLE incidents ADD COLUMN resolved_at DATETIME"))
except Exception:
    pass
```

Esto permite actualizar el esquema sin herramientas externas y es compatible con la transición SQLite → PostgreSQL.

---

## Arquitectura del Código

### Principios aplicados

- **Separación por afinidad** — cada módulo tiene una sola responsabilidad clara
- **DRY** — `api_auth`, `jloads`, `load_session`, `run_ti_lookups` centralizados
- **Anti-anchoring** — scores en atributos `data-*` HTML, nunca en texto visible
- **Fire-and-forget** — webhooks y emails en `asyncio.create_task()` para no bloquear la respuesta
- **Constantes centralizadas** — `app/core/constants.py` como única fuente de verdad para números mágicos

### Flujo de evaluación completo

```
Analista llena formulario (12 bloques)
    ↓
Bloque 0: IP src/dst/dir + URL + MAC
    ↓ POST /api/ti/lookup (AJAX, inline)
TI results aparecen en pantalla mientras el analista continúa
    ↓
POST /evaluar (evaluar_submit)
    ├── _extract_network_context(all_data)
    ├── _enrich_with_ti(ctx)          ← lookups TI server-side si no se hicieron inline
    ├── _apply_asset_enrichment(...)  ← busca IP en CMDB, aplica multiplicador
    ├── engine_instance.evaluate(answers)
    ├── _persist_incident(...)        ← crea Incident + IncidentAnswer en DB
    └── _fire_notifications(...)      ← webhook Teams/Slack + email SMTP
    ↓
redirect → /incidentes/{id} (detalle con MITRE + playbook + TI)
```

### Dependency injection en rutas

```python
# Rutas web (Jinja2)
@router.get("/")
async def page(request: Request, user=Depends(require_auth), db=Depends(get_db)):
    ...

# REST API
@router.get("/api/v1/incidents")
async def list_incidents(user=Depends(api_auth), db=Depends(get_db)):
    ...
```

### Paquete admin

```python
# app/routes/admin/__init__.py
from ._base import router          # router = APIRouter(prefix="/admin")
from . import config               # registra rutas GET/POST /admin
from . import integrations         # registra rutas POST /admin/ti-keys, /smtp, /webhooks, /thehive
from . import users                # registra rutas GET/POST /admin/usuarios, /users/{id}/*
from . import security             # registra rutas GET /admin/audit-log, /backup, /api-tokens

# app/main.py (sin cambios)
from app.routes import admin
app.include_router(admin.router)
```

---

## Stack tecnológico

| Componente | Tecnología |
|------------|-----------|
| Backend | FastAPI 0.115 + Uvicorn |
| ORM | SQLAlchemy 2.0 |
| Base de datos | SQLite (dev) / PostgreSQL (prod) |
| Autenticación | bcrypt 4.x + SessionMiddleware + TOTP (pyotp) |
| Templates | Jinja2 3.1 |
| Frontend | Bootstrap 5.3 (dark) + Vanilla JS |
| Threat Intel | httpx async (VT / AbuseIPDB / X-Force) |
| Contenedor | Docker + Nginx |

### Dependencias (requirements.txt)

```
fastapi>=0.115
uvicorn[standard]
sqlalchemy>=2.0
jinja2
python-multipart
bcrypt>=4.0
starlette          # SessionMiddleware
httpx              # TI async lookups
pyotp              # 2FA TOTP
python-dotenv
```

---

## Número de líneas por componente

| Componente | ~Líneas Python |
|------------|---------------|
| Routes (todos los routers) | ~3,200 |
| Models (database.py) | ~350 |
| Services | ~1,100 |
| Core (engine, auth, constants, rate_limit) | ~800 |
| Templates (Jinja2) | ~4,300 |
| **Total** | **~9,750** |

**68 endpoints HTTP** distribuidos en **11 módulos de rutas**.
**14 modelos SQLAlchemy** con **migraciones inline** compatibles SQLite/PostgreSQL.
**21 plantillas Jinja2** Bootstrap 5.3 dark.

---

## Licencia

MIT — ver [LICENSE](LICENSE)

---

*SOC Assist v1.13 — Plataforma de Alerta Temprana en Ciberseguridad*
*Documentación generada para el estado final del proyecto (2026-03-10)*

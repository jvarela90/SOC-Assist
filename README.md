# SOC Assist — Plataforma de Alerta Temprana en Ciberseguridad

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green?logo=fastapi)](https://fastapi.tiangolo.com)
[![Version](https://img.shields.io/badge/Version-1.11-orange)](ROADMAP.md)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

**SOC Assist** es una plataforma web de evaluación y clasificación de eventos de ciberseguridad. Permite que analistas con distintos niveles de experiencia puedan detectar señales de alerta, calcular un puntaje de riesgo estructurado, enriquecer con inteligencia de amenazas y saber exactamente qué hacer a continuación.

Incluye un **chatbot multimodal** (SOC · Ciudadano · Experto+ · Unificado) como canal alternativo al formulario wizard, con routing inteligente que reduce las 66 preguntas a 15-24 según la amenaza inferida.

---

## Contenido

- [Características v1.11](#caracteristicas)
- [Quickstart — Desarrollo local](#quickstart--desarrollo-local)
- [Quickstart — Docker (recomendado)](#quickstart--docker-recomendado)
- [Acceso desde otra máquina / red](#acceso-desde-otra-maquina--red)
- [Continuar desarrollo en otra PC](#continuar-desarrollo-en-otra-pc)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Variables de entorno](#variables-de-entorno)
- [Rutas principales](#rutas-principales)
- [Motor de Scoring](#motor-de-scoring)
- [API REST](#api-rest)

---

## Características

| # | Feature | Estado |
|---|---------|--------|
| — | Motor de scoring ponderado (66 preguntas, 12 bloques, 5 niveles) | ✅ |
| — | Dashboard ejecutivo + heatmap temporal + métricas SLA (MTTR, tasa de cierre) | ✅ |
| — | Threat Intelligence: VirusTotal, AbuseIPDB, IBM X-Force | ✅ |
| — | Bloque 0 — Contexto de Red: IPs, dirección, URL, MAC + lookup inline | ✅ |
| — | Ajuste TI híbrido — analista confirma ajuste de score | ✅ |
| — | Webhooks Teams / Slack + Email SMTP para incidentes Crítico/Brecha | ✅ |
| — | Mapeo MITRE ATT&CK + Playbooks de respuesta | ✅ |
| — | Autenticación con roles (Analista / Admin / Super Admin) | ✅ |
| — | Gestión de usuarios: crear, activar, cambiar rol, notas, trazabilidad | ✅ |
| — | Multi-tenant: organizaciones jerárquicas (central > regional > local) | ✅ |
| — | CMDB de activos: IP, hostname, criticidad (×0.8–×1.5), CSV import/export | ✅ |
| — | Adjuntos de evidencia por incidente (imágenes, PDF, PCAP, logs — máx 10 MB) | ✅ |
| — | SLA tracking: `resolved_at`, MTTR por clasificación | ✅ |
| — | Etiquetas libres (tags) en incidentes con filtro en historial | ✅ |
| — | **Chatbot multimodal** (SOC · Ciudadano · Experto+ · Unificado) | ✅ |
| — | Chatbot SOC: routing inteligente — 15-24 preguntas vs. 66 del wizard | ✅ |
| — | Chatbot Ciudadano: lenguaje no técnico, clasificación P1/P2/P3/P4 | ✅ |
| — | Anti-anchoring en chatbot: opciones en orden aleatorio (Fisher-Yates) | ✅ |
| — | REST API chatbot `/api/v1/chat/sessions` para integración SOAR/SIEM | ✅ |
| — | Códigos de recuperación de cuenta (single-use, bcrypt) | ✅ |
| — | Audit log de todas las acciones de administrador | ✅ |
| — | REST API documentada (OpenAPI/Swagger en `/docs`) | ✅ |
| — | Soporte Docker + docker-compose | ✅ |
| — | Soporte PostgreSQL vía `DATABASE_URL` | ✅ |

---

## Quickstart — Desarrollo local

### Requisitos

- Python **3.10 o superior**
- Git

### Pasos

```bash
# 1. Clonar el repositorio
git clone https://github.com/jvarela90/SOC-Assist.git
cd SOC-Assist

# 2. Crear entorno virtual
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Levantar la aplicación (modo desarrollo con auto-reload)
python run.py
```

Abrir en el navegador: **http://127.0.0.1:8000**

**Credenciales por defecto** (primer arranque):
| Usuario | Contraseña | Rol |
|---------|-----------|-----|
| `admin` | `admin123` | Admin |

> Cambiar la contraseña del admin en el primer ingreso desde `/admin/usuarios`.

---

## Quickstart — Docker (recomendado)

### Requisitos

- Docker Desktop (Windows/macOS) o Docker Engine (Linux)
- docker-compose v2+

### Levantar con un solo comando

```bash
git clone https://github.com/jvarela90/SOC-Assist.git
cd SOC-Assist

# Opción A: con variables de entorno por defecto (dev/test)
docker-compose up -d

# Opción B: con secret key personalizada (producción)
SOC_SECRET_KEY="mi-clave-segura-aleatoria-32chars" docker-compose up -d
```

```bash
# Ver logs en tiempo real
docker-compose logs -f soc-assist

# Detener
docker-compose down

# Detener y borrar volumen de datos (¡elimina la BD!)
docker-compose down -v
```

Abrir en el navegador: **http://localhost:8000**

### Construir imagen manualmente

```bash
docker build -t soc-assist:1.8 .
docker run -d \
  -p 8000:8000 \
  -v soc_data:/data \
  -e SOC_SECRET_KEY="cambiar-esto" \
  --name soc-assist \
  soc-assist:1.8
```

---

## Acceso desde otra maquina / red

### Modo desarrollo (sin Docker)

Por defecto `run.py` escucha solo en `127.0.0.1`. Para que sea accesible desde otras máquinas de la red local, editar `run.py`:

```python
# Cambiar host de "127.0.0.1" a "0.0.0.0"
uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
```

O lanzar directamente con uvicorn:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Desde otra máquina en la misma red, acceder con:

```
http://<IP-de-tu-PC>:8000
```

Para conocer la IP local:
```bash
# Windows
ipconfig

# Linux / macOS
ip a   # o ifconfig
```

### Modo Docker

Docker ya expone en `0.0.0.0:8000` por defecto. No requiere ningún cambio.

```
http://<IP-de-tu-servidor>:8000
```

### Firewall (Windows)

Si otra PC no puede conectar, crear regla de firewall:

```powershell
# Ejecutar como Administrador
New-NetFirewallRule -DisplayName "SOC Assist Dev" `
  -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow
```

### Pruebas desde otra red (túnel rápido)

Para exponer temporalmente sin abrir puertos del router, usar **ngrok**:

```bash
# Instalar: https://ngrok.com/download
ngrok http 8000
```

Ngrok devuelve una URL pública tipo `https://xxxx.ngrok-free.app` que cualquiera puede usar mientras el túnel esté activo.

---

## Continuar desarrollo en otra PC

### Paso 1 — Clonar y configurar el entorno

```bash
git clone https://github.com/jvarela90/SOC-Assist.git
cd SOC-Assist

python -m venv venv

# Windows
venv\Scripts\activate
# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt
```

### Paso 2 — Restaurar la base de datos (opcional)

La BD (`soc_assist.db`) está en `.gitignore` y **no se sube a GitHub** (contiene datos de producción/test).

**Opción A — BD limpia (recomendado en nueva PC):**
El primer `python run.py` crea automáticamente una BD nueva con el usuario `admin/admin123`.

**Opción B — Copiar BD existente:**
Copiar el archivo `soc_assist.db` desde la PC original (puede estar en la raíz del proyecto o en `/data/` si usas Docker) a la raíz del proyecto en la nueva PC.

```bash
# Desde la PC origen (ejemplo con scp a IP de destino)
scp soc_assist.db usuario@192.168.1.XX:/ruta/SOC-Assist/

# O simplemente copiar el archivo por USB / red compartida
```

### Paso 3 — Restaurar `ti_config.json` (API keys TI)

El archivo `ti_config.json` está en `.gitignore` porque puede contener API keys reales.
Copiarlo manualmente desde la PC original o configurar las keys desde el panel Admin:

```
http://localhost:8000/admin  →  sección "Threat Intelligence"
```

El archivo tiene esta estructura (las keys vacías deshabilitan esa fuente):

```json
{
  "virustotal_api_key": "",
  "abuseipdb_api_key": "",
  "xforce_api_key": "",
  "xforce_api_password": ""
}
```

### Paso 4 — Levantar y verificar

```bash
python run.py
# → http://127.0.0.1:8000/health debe devolver {"status":"ok","version":"1.8.0"}
```

### Flujo de trabajo con Git

```bash
# Antes de empezar a trabajar: traer cambios remotos
git pull origin main

# Mientras desarrollas: guardar cambios
git add archivo1.py app/templates/pagina.html
git commit -m "feat: descripción del cambio"

# Subir al repositorio
git push origin main
```

> **Nunca hacer `git add .` sin revisar** — puede incluir `soc_assist.db` o `ti_config.json` con datos sensibles. Usar `git status` primero y agregar archivos explícitamente.

---

## Estructura del proyecto

```
SOC-Assist/
├── run.py                    # Punto de entrada (uvicorn dev server)
├── requirements.txt          # Dependencias Python
├── Dockerfile                # Imagen Docker Python 3.13-slim
├── docker-compose.yml        # Despliegue con volumen persistente
├── config_engine.json        # Scoring: pesos, umbrales, multiplicadores, reglas
├── ti_config.json            # API keys TI — NO commitear con claves reales
├── smtp_config.json          # Configuración SMTP — NO commitear con credenciales
├── playbooks.json            # Playbooks de respuesta por nivel
├── questions.json            # 66 preguntas + bloques temáticos
├── ROADMAP.md                # Estado de desarrollo por fase
└── app/
    ├── main.py               # FastAPI app + routers + /health
    ├── core/
    │   ├── engine.py         # Motor de scoring ponderado
    │   ├── calibration.py    # Auto-calibración basada en TP/FP
    │   ├── auth.py           # bcrypt + dependencias require_auth/require_admin
    │   └── rate_limit.py     # Rate limiting in-memory (20 req/min/IP)
    ├── models/
    │   └── database.py       # SQLAlchemy + SQLite/PostgreSQL + migraciones inline
    ├── routes/
    │   ├── auth.py           # Login / logout / recuperación de cuenta
    │   ├── form.py           # Wizard + TI enrichment + comentarios + asignación
    │   ├── dashboard.py      # Dashboard + historial + SLA + tags + CSV
    │   ├── admin.py          # Panel admin + usuarios + SMTP + audit log + backup
    │   ├── api.py            # REST API v1 (/api/v1/...)
    │   ├── ti.py             # API TI + MAC OUI lookup
    │   ├── orgs.py           # CRUD organizaciones (/admin/orgs)
    │   ├── assets.py         # CMDB activos + CSV import/export (/activos)
    │   ├── attachments.py    # Adjuntos de evidencia (/incidentes/{id}/adjuntar)
    │   ├── chatbot.py        # Chatbot web: session start/answer/back/skip/complete/save
    │   └── chatbot_api.py    # REST API chatbot (/api/v1/chat/sessions/...)
    ├── services/
    │   ├── mitre.py          # Mapeo MITRE ATT&CK
    │   ├── threat_intel.py   # VirusTotal / AbuseIPDB / IBM X-Force
    │   ├── mac_oui.py        # Fabricante por prefijo MAC
    │   ├── similarity.py     # Similitud coseno entre incidentes
    │   ├── notifications.py  # Webhooks Teams / Slack
    │   ├── mailer.py         # SMTP: alertas por email
    │   ├── scheduler.py      # Revisión periódica de activos → notificaciones in-app
    │   ├── chatbot_engine.py # Gateway questions, routing SOC, inferencia de categoría
    │   └── citizen_engine.py # 68 preguntas ciudadano, clasificación P1-P4, BRIDGE_MAP
    ├── uploads/              # Evidencia adjunta (app/uploads/{incident_id}/{uuid}.ext)
    ├── templates/            # Jinja2 + Bootstrap 5.3 (dark theme)
    └── static/               # CSS + JS
```

---

## Variables de entorno

| Variable | Default | Descripción |
|----------|---------|-------------|
| `SOC_SECRET_KEY` | `soc-assist-change-this-...` | Clave de firma para cookies de sesión. **Cambiar en producción.** |
| `DATABASE_URL` | `sqlite:///./soc_assist.db` | URL de base de datos. Para PostgreSQL: `postgresql://user:pass@host:5432/soc_assist` |
| `SOC_HOST` | `0.0.0.0` | IP de escucha (solo Docker/uvicorn directo) |
| `SOC_PORT` | `8000` | Puerto de escucha |

### Ejemplo `.env` para docker-compose

```env
SOC_SECRET_KEY=genera-una-clave-aleatoria-larga-aqui
DATABASE_URL=sqlite:///./soc_assist.db
```

```bash
# Generar clave segura
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Rutas principales

| URL | Descripción | Rol mínimo |
|-----|-------------|-----------|
| `/` | Inicio | — |
| `/login` | Autenticación | — |
| `/recuperar` | Recuperación de cuenta con código admin | — |
| `/evaluar` | Formulario wizard de evaluación (Bloque 0 + 11 bloques) | Analista |
| `/chatbot` | Chat Analista — 4 modos: SOC, Ciudadano, Experto+, Unificado | Analista |
| `/dashboard` | Dashboard ejecutivo con gráficos + heatmap + SLA | Analista |
| `/incidentes` | Historial completo con filtros avanzados y tags | Analista |
| `/incidentes/{id}` | Detalle: timeline, TI, MITRE, playbook, similitud, adjuntos | Analista |
| `/activos` | CMDB: inventario de activos, criticidad, CSV import/export | Analista |
| `/admin` | Panel de configuración: pesos, umbrales, calibración, TI keys, SMTP | Admin |
| `/admin/usuarios` | Gestión de usuarios: crear, roles, trazabilidad, recuperación | Admin |
| `/admin/orgs` | Gestión de organizaciones jerárquicas | Admin |
| `/admin/audit-log` | Registro de todas las acciones administrativas | Admin |
| `/api/v1/chat/sessions` | REST API chatbot (SOAR/SIEM) | Admin |
| `/docs` | Swagger UI — REST API interactiva | Admin |
| `/redoc` | ReDoc — REST API documentada | Admin |
| `/health` | Health check (`{"status":"ok","version":"1.11.0"}`) | — |

---

## Motor de Scoring

### Formula

```
Score_base  = Σ (raw_score × question_weight × module_weight)
Score_final = Score_base × Π(multiplicadores_activos)
```

### Niveles de clasificación

| Nivel | Score | Accion recomendada |
|-------|-------|--------------------|
| 🟢 Informativo | 0–40 | Monitorear y documentar |
| 🟡 Sospechoso | 41–110 | Investigar y recolectar evidencia |
| 🟠 Incidente | 111–280 | Escalar al equipo de seguridad |
| 🔴 Critico | 281–600 | Escalar a gerencia e iniciar IR |
| 🚨 Brecha | 601+ | Activar plan de respuesta completo |

### Multiplicadores de riesgo

| Condicion | Factor |
|-----------|--------|
| Persistencia + Movimiento Lateral | ×1.5 |
| Exfiltracion en activo Crown Jewel | ×1.8 |
| Sin EDR en activo critico | ×1.3 |
| Movimiento Lateral + Elevacion de Privilegios | ×1.4 |

---

## API REST

La API está disponible en `/api/v1/` y documentada en `/docs` (Swagger) y `/redoc`.

**Autenticación:** HTTP Basic Auth con credenciales de usuario Admin.

```bash
# Ejemplo: listar incidentes via API
curl -u admin:tu_password http://localhost:8000/api/v1/incidents

# Ejemplo: obtener detalle de incidente
curl -u admin:tu_password http://localhost:8000/api/v1/incidents/42

# Lookup TI (sin auth requerida internamente, usa sesion)
curl -X POST http://localhost:8000/api/ti/lookup \
  -H "Content-Type: application/json" \
  -d '{"indicator": "8.8.8.8", "type": "ip"}'
```

---

## Stack tecnologico

| Capa | Tecnologia |
|------|-----------|
| Backend | Python 3.10+ · FastAPI 0.115 · SQLAlchemy 2.0 |
| Base de datos | SQLite (default) · PostgreSQL (produccion) |
| Frontend | Jinja2 · Bootstrap 5.3 · Chart.js · Bootstrap Icons |
| Auth | bcrypt 4.x · itsdangerous (sesiones firmadas) |
| TI | VirusTotal API v3 · AbuseIPDB API v2 · IBM X-Force Exchange |
| Deploy | Uvicorn · Docker · docker-compose · Nginx (proxy) |

---

## Licencia

MIT License — Libre para uso interno, educativo y adaptacion.

---

*Desarrollado como herramienta SOC de alerta temprana — v1.11*

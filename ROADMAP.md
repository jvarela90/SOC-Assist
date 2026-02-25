# SOC Assist — Guía de Desarrollo y Roadmap

> **Estado actual:** v1.8 — Motor ponderado + TI + Webhooks + Auth + Playbooks + Heatmap + CSV + Filtros + MITRE ATT&CK + Comentarios + Asignación + Audit Log + Docker + REST API + Similitud + Timeline + Rate Limit + Backup + PostgreSQL + Nginx + Contexto de Red + TI Enrichment Híbrido + Gestión de Usuarios
> **Repositorio:** https://github.com/jvarela90/SOC-Assist
> **Última actualización:** 2026-02

---

## Estado de Desarrollo por Fase

| Fase | Nombre | Estado |
|------|--------|--------|
| 1 | Core — Motor + Formulario | ✅ Completado |
| 2 | UX — Bloques temáticos + sesgo neutral | ✅ Completado |
| 3 | Integraciones externas | ✅ Completado |
| 4 | Analítica avanzada + Colaboración | ✅ Completado |
| 5 | Producción + Seguridad | ✅ Completado |
| 6 | Contexto de Red + TI Enrichment Híbrido | ✅ Completado |
| 7 | Gestión de Usuarios + Trazabilidad | ✅ Completado |

---

## Fase 1 — Core (Completado ✅)

| # | Feature | Estado |
|---|---------|--------|
| 1 | Motor de scoring ponderado (score = raw × q_weight × mod_weight × multipliers) | ✅ |
| 2 | 63 preguntas organizadas en 9 módulos de análisis | ✅ |
| 3 | 5 niveles de clasificación: Informativo / Sospechoso / Incidente / Crítico / Brecha | ✅ |
| 4 | Reglas de corte (Hard Rules) — floor mínimo, no techo | ✅ |
| 5 | Multiplicadores de riesgo (condiciones combinadas) | ✅ |
| 6 | Dashboard ejecutivo con KPIs y gráficos (Chart.js) | ✅ |
| 7 | Historial completo de evaluaciones con resolución TP/FP | ✅ |
| 8 | Auto-calibración de pesos basada en feedback histórico | ✅ |
| 9 | Panel de administración: pesos, umbrales, calibración manual | ✅ |
| 10 | Explicabilidad del resultado (módulos, factores, multipliers) | ✅ |
| 11 | Base de datos SQLite (local, sin configuración) | ✅ |
| 12 | Tema oscuro cybersec (Bootstrap 5.3 + CSS custom) | ✅ |

---

## Fase 2 — UX Neutralidad y Bloques (Completado ✅)

| # | Feature | Estado |
|---|---------|--------|
| 13 | Preguntas agrupadas en 11 bloques temáticos (no por módulo) | ✅ |
| 14 | Navegación por bloques con checklist lateral | ✅ |
| 15 | Eliminación total de puntajes visibles en opciones (anti-anchoring) | ✅ |
| 16 | Opciones con estilo 100% neutral — sin semáforo de colores | ✅ |
| 17 | Grid 2 columnas × 3 filas por bloque (máx. 6 preguntas) | ✅ |
| 18 | Preguntas IP origen / IP destino / MAC / hostname en mismo bloque | ✅ |
| 19 | Indicador de nivel en tiempo real (sin número, solo label + barra) | ✅ |
| 20 | Tooltips de ayuda contextual (desktop) + texto inline (mobile) | ✅ |
| 21 | Resumen final antes de envío: preguntas respondidas / sin responder | ✅ |
| 22 | Animación fadeIn al cambiar bloques | ✅ |

---

## Fase 3 — Integraciones Externas (Completado ✅)

### 3.1 — Threat Intelligence (implementado en esta versión)

| # | Feature | Estado |
|---|---------|--------|
| 23 | Configuración de API Keys desde panel admin (VirusTotal, AbuseIPDB, IBM X-Force) | ✅ |
| 24 | Validación: bloquear IPs privadas / loopback antes de consultar fuentes OSINT | ✅ |
| 25 | Lookup de IP en VirusTotal (detections, categories, last analysis) | ✅ |
| 26 | Lookup de IP en AbuseIPDB (abuse score, total reports, country) | ✅ |
| 27 | Lookup de dominio / URL en IBM X-Force Exchange | ✅ |
| 28 | Base de datos OUI local para identificar fabricante/dispositivo por MAC | ✅ |
| 29 | Widget de consulta TI en formulario (campo IP origen/destino) | ✅ |

### 3.2 — Notificaciones (Parcialmente completado)

| # | Feature | Estado |
|---|---------|--------|
| 30 | Webhook a Microsoft Teams al clasificar como Crítico o Brecha | ✅ |
| 31 | Webhook a Slack con resumen del incidente | ✅ |
| 32 | Notificación por email (SMTP configurable) | ⬜ |
| 33 | Configuración de webhooks desde panel admin | ✅ |

### 3.3 — Autenticación básica (Completado ✅)

| # | Feature | Estado |
|---|---------|--------|
| 34 | Login con usuario + contraseña (sesión local, bcrypt) | ✅ |
| 35 | Roles: Analista (solo evaluar/ver) / Admin (todo) | ✅ |
| 36 | Protección de /admin con rol Admin | ✅ |

---

## Fase 4 — Analítica Avanzada + Colaboración (🔄 En Progreso)

| # | Feature | Estado |
|---|---------|--------|
| 37 | Mapeo MITRE ATT&CK — etiquetar respuestas con técnica (T1059, T1003…) | ✅ |
| 38 | Playbooks de respuesta — lista de pasos por tipo de incidente | ✅ |
| 39 | Heatmap temporal (hora del día × día de semana) de incidentes | ✅ |
| 40 | REST API documentada (OpenAPI) para integración con SIEMs externos | ✅ |
| 41 | Exportación de reportes a PDF (print CSS + botón imprimir) | ✅ |
| 42 | Exportación a CSV/Excel del historial | ✅ |
| 43 | Comparación de incidentes similares (coseno sobre vectores de módulo) | ✅ |
| 44 | Score de similitud — "Este incidente se parece a ID-42 en un 78%" | ✅ |
| 45 | Comentarios colaborativos por incidente (varios analistas) | ✅ |
| 46 | Asignación de incidentes a analista específico | ✅ |
| 47 | Timeline gráfico del incidente (creación → comentarios → resolución) | ✅ |
| 48 | Adjuntar evidencia (screenshots, logs, pcap) al incidente | ⬜ |
| 49 | Búsqueda full-text en historial de incidentes | ✅ |
| 50 | Filtros avanzados en historial: por fecha, nivel, módulo, analista | ✅ |

---

## Fase 5 — Producción y Seguridad (Completado ✅)

| # | Feature | Estado |
|---|---------|--------|
| 51 | Soporte PostgreSQL vía DATABASE_URL env var | ✅ |
| 52 | Docker + docker-compose para despliegue en un comando | ✅ |
| 53 | HTTPS / TLS con Nginx reverse proxy (nginx/nginx.conf) | ✅ |
| 54 | Audit log de todas las acciones de administrador | ✅ |
| 55 | Backup de BD + config descargable como ZIP desde /admin | ✅ |
| 56 | Rate limiting en /evaluar (20 req/min por IP, in-memory) | ✅ |
| 57 | Modo multi-tenant (varias organizaciones en una instancia) | ⬜ |

---

## Fase 6 — Contexto de Red + TI Enrichment Híbrido (Completado ✅)

| # | Feature | Estado |
|---|---------|--------|
| 58 | Bloque 0 "Contexto del Evento" antes del wizard (IP src/dir/dst, URL, MAC) | ✅ |
| 59 | Lookups TI inline en Bloque 0 (botón Analizar por campo) con badge LIMPIO/SOSPECHOSO/MALICIOSO | ✅ |
| 60 | 3 preguntas nuevas: q_064 (comunicación exitosa), q_065 (usuario identificado), q_066 (función crítica) | ✅ |
| 61 | TI enrichment server-side en POST /evaluar (asyncio.gather, timeout 8s) | ✅ |
| 62 | Banner TI en resultado: score ajustado sugerido + botón "Aplicar ajuste TI" (flujo híbrido) | ✅ |
| 63 | POST /incident/{id}/apply-ti-adjustment — analista confirma ajuste, audit log registra acción | ✅ |
| 64 | Tarjeta "Contexto de Red" en incident_detail con flujo IP→→IP, veredicto TI, badge ajuste aplicado | ✅ |

---

## Arquitectura de Referencia

```
SOC-Assist/
├── run.py                    # Punto de entrada (uvicorn)
├── requirements.txt          # Dependencias Python
├── Dockerfile                # Imagen Docker Python 3.13-slim
├── docker-compose.yml        # Despliegue con volumen persistente
├── config_engine.json        # Scoring: pesos, umbrales, multiplicadores, reglas
├── ti_config.json            # Threat Intelligence: API keys (NO commitear con claves reales)
├── playbooks.json            # Playbooks de respuesta por nivel de clasificación
├── questions.json            # 63 preguntas + bloques temáticos
├── ROADMAP.md                # Este archivo
└── app/
    ├── main.py               # FastAPI app + routers + /health endpoint
    ├── core/
    │   ├── engine.py         # Motor de scoring ponderado
    │   ├── calibration.py    # Auto-calibración basada en TP/FP
    │   └── auth.py           # Hashing bcrypt + dependencias require_auth / require_admin
    ├── models/
    │   └── database.py       # SQLAlchemy + SQLite (Incident, IncidentAnswer,
    │                         #   IncidentComment, AuditLog, User, WeightHistory…)
    ├── routes/
    │   ├── auth.py           # Login / logout (sesión con cookies firmadas)
    │   ├── form.py           # Formulario wizard + comentarios + asignación
    │   ├── dashboard.py      # Dashboard + historial + exportación CSV
    │   ├── admin.py          # Panel admin (pesos, umbrales, calibración, TI keys,
    │                         #   usuarios, webhooks) con audit log completo
    │   └── ti.py             # API de Threat Intelligence y MAC OUI lookup
    ├── services/
    │   ├── mitre.py          # Mapeo MITRE ATT&CK (módulos + hard rules → técnicas)
    │   ├── threat_intel.py   # VirusTotal / AbuseIPDB / IBM X-Force + validación IP privada
    │   ├── mac_oui.py        # Lookup fabricante por prefijo MAC (OUI database local)
    │   └── notifications.py  # Webhooks Teams / Slack — dispatch fire-and-forget
    ├── templates/            # Jinja2 + Bootstrap 5 (tema oscuro)
    └── static/               # CSS + JS
```

---

## Notas de Diseño

### Sesgo Neutral (Anti-Anchoring)
Las opciones de las preguntas **nunca muestran puntajes** al analista. Los pesos están en atributos
`data-score` del HTML y son procesados solo por JavaScript para el indicador de nivel. El analista
responde por criterio propio, no por el color o número de cada opción.

### Reglas de Corte (Hard Rules)
Las hard rules actúan como **floor mínimo**, nunca como techo. Si el score calculado es más alto
que el nivel impuesto por la hard rule, se mantiene el score alto. Ejemplo: ransomware detectado
fuerza "brecha" como mínimo, pero si el score ya era brecha, sigue siendo brecha.

### Threat Intelligence — IPs Privadas
Las IPs en rangos privados (RFC 1918), loopback, link-local y espacio compartido **nunca se envían**
a fuentes de inteligencia externas. La validación ocurre en el backend, no solo en el cliente.

### Almacenamiento de API Keys
Las API keys se guardan en `ti_config.json` (archivo local, fuera del motor de scoring).
**No commitear `ti_config.json` con claves reales** — está en `.gitignore` como precaución.
En producción, usar variables de entorno o un vault de secretos.

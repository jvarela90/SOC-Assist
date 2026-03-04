# SOC Assist — Guía de Desarrollo y Roadmap

> **Estado actual:** v1.11 — Chatbot Multimodal (SOC · Ciudadano · Experto+ · Unificado)
> **Repositorio:** https://github.com/jvarela90/SOC-Assist
> **Última actualización:** 2026-03

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
| 8 | Multi-Tenant + CMDB de Activos | ✅ Completado |
| 9 | Adjuntos de Evidencia + Notificaciones SMTP | ✅ Completado |
| 10 | SLA Tracking + Etiquetas de Incidentes | ✅ Completado |
| 11 | Chatbot Multimodal (SOC · Ciudadano · Experto+ · Unificado) | ✅ Completado |

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

### 3.1 — Threat Intelligence

| # | Feature | Estado |
|---|---------|--------|
| 23 | Configuración de API Keys desde panel admin (VirusTotal, AbuseIPDB, IBM X-Force) | ✅ |
| 24 | Validación: bloquear IPs privadas / loopback antes de consultar fuentes OSINT | ✅ |
| 25 | Lookup de IP en VirusTotal (detections, categories, last analysis) | ✅ |
| 26 | Lookup de IP en AbuseIPDB (abuse score, total reports, country) | ✅ |
| 27 | Lookup de dominio / URL en IBM X-Force Exchange | ✅ |
| 28 | Base de datos OUI local para identificar fabricante/dispositivo por MAC | ✅ |
| 29 | Widget de consulta TI en formulario (campo IP origen/destino) | ✅ |

### 3.2 — Notificaciones

| # | Feature | Estado |
|---|---------|--------|
| 30 | Webhook a Microsoft Teams al clasificar como Crítico o Brecha | ✅ |
| 31 | Webhook a Slack con resumen del incidente | ✅ |
| 32 | Notificación por email (SMTP configurable) | ✅ |
| 33 | Configuración de webhooks desde panel admin | ✅ |

### 3.3 — Autenticación básica

| # | Feature | Estado |
|---|---------|--------|
| 34 | Login con usuario + contraseña (sesión local, bcrypt) | ✅ |
| 35 | Roles: Analista (solo evaluar/ver) / Admin (todo) | ✅ |
| 36 | Protección de /admin con rol Admin | ✅ |

---

## Fase 4 — Analítica Avanzada + Colaboración (Completado ✅)

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
| 48 | Adjuntar evidencia (screenshots, logs, pcap) al incidente | ✅ |
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
| 57 | Modo multi-tenant (varias organizaciones en una instancia) | ✅ |

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

## Fase 7 — Gestión de Usuarios + Trazabilidad (Completado ✅)

| # | Feature | Estado |
|---|---------|--------|
| 65 | CRUD de usuarios desde /admin/usuarios (crear, editar rol, activar/desactivar) | ✅ |
| 66 | Roles: analyst / admin / super_admin con permisos jerárquicos | ✅ |
| 67 | Trazabilidad: último login, conteo de logins, fecha de último análisis | ✅ |
| 68 | Códigos de recuperación de contraseña de un solo uso (/recuperar) | ✅ |
| 69 | Historial de cambios de contraseña (password_changed_at) | ✅ |
| 70 | Notas internas por usuario (visibles solo para admin) | ✅ |

---

## Fase 8 — Multi-Tenant + CMDB de Activos (Completado ✅)

| # | Feature | Estado |
|---|---------|--------|
| 71 | Organizaciones jerárquicas: central > regional > provincial > local | ✅ |
| 72 | BFS para determinar orgs descendientes visibles por rol | ✅ |
| 73 | super_admin ve TODAS las orgs; admin ve su subárbol | ✅ |
| 74 | Inventario de activos (CMDB): IP, hostname, servidor, red, usuario crítico | ✅ |
| 75 | Criticidad del activo (1–5) como multiplicador de score de incidente (×0.8–×1.5) | ✅ |
| 76 | Contactos y ubicaciones por activo (responsable, admin, escalación) | ✅ |
| 77 | Revisión periódica de activos con notificaciones in-app (3/6 meses) | ✅ |
| 78 | Importación y exportación CSV de activos + plantilla descargable | ✅ |
| 79 | Lookup automático de activo por IP/hostname en evaluar_submit (CIDR matching) | ✅ |

---

## Fase 9 — Adjuntos de Evidencia + Notificaciones SMTP (Completado ✅)

| # | Feature | Estado |
|---|---------|--------|
| 80 | Upload de evidencia por incidente (imágenes, PDF, PCAP, logs, ZIP — máx 10 MB) | ✅ |
| 81 | Descarga autenticada de adjuntos (/adjuntos/{id}) | ✅ |
| 82 | Eliminación de adjuntos (solo admin, con audit log) | ✅ |
| 83 | Almacenamiento con nombre UUID (previene path traversal) | ✅ |
| 84 | Panel SMTP en /admin: host/port/TLS/credenciales/destinatarios + botón probar | ✅ |
| 85 | Envío de alerta por email en incidentes Crítico/Brecha (fire-and-forget) | ✅ |
| 86 | Email con diseño HTML responsive (dark theme) + versión texto plano | ✅ |

---

## Fase 10 — SLA Tracking + Etiquetas de Incidentes (Completado ✅)

| # | Feature | Estado |
|---|---------|--------|
| 87 | Campo resolved_at en Incident — timestamp de cierre efectivo | ✅ |
| 88 | MTTR (Mean Time To Resolve) calculado automáticamente por clasificación | ✅ |
| 89 | Métricas SLA en dashboard: MTTR promedio, tasa de cierre, incidentes abiertos por antigüedad | ✅ |
| 90 | Etiquetas libres (tags) en incidentes: agregar/eliminar desde el detalle | ✅ |
| 91 | Filtro por etiqueta en historial de incidentes (/incidentes?tag=xxx) | ✅ |
| 92 | Las etiquetas se muestran en historial y detalle con badges visuales | ✅ |

---

## Fase 11 — Chatbot Multimodal (Completado ✅)

| # | Feature | Estado |
|---|---------|--------|
| 93 | Canal chatbot alternativo al formulario wizard (nueva pestaña "Chat Analista") | ✅ |
| 94 | **Modo SOC** — 8 preguntas gateway + ruta dirigida por categoría (15–24 preguntas vs. 66) | ✅ |
| 95 | **Modo Ciudadano** — 68 preguntas en lenguaje no técnico, resultado P1/P2/P3/P4 | ✅ |
| 96 | **Modo Experto+** — igual que SOC pero transición anticipada a ruta dirigida (confidence ≥ 0.45) | ✅ |
| 97 | **Modo Unificado** — Ciudadano → BRIDGE → SOC en una sola sesión | ✅ |
| 98 | Inferencia de categoría de amenaza tras gateway (ransomware / phishing / apt / ddos / insider / credential_theft) | ✅ |
| 99 | TI auto-answers — responde q_003, q_006, q_062, q_046 automáticamente desde resultados de lookup | ✅ |
| 100 | Anti-anchoring en opciones — orden aleatorio (Fisher-Yates) en cada pregunta renderizada | ✅ |
| 101 | Navegación hacia atrás (deshacer última respuesta) y omitir pregunta | ✅ |
| 102 | Creación de Incident + IncidentAnswer desde el chatbot (mismo modelo que el formulario) | ✅ |
| 103 | REST API `/api/v1/chat/sessions` para consumo programático por SOAR/SIEM | ✅ |
| 104 | Modelo `ChatSession` en BD — estado persistente de sesión (modo, fase, cola, respuestas, TI) | ✅ |
| 105 | Escalado ciudadano → analista SOC ("Escalar a Analista SOC" en resultados P1/P2) | ✅ |
| 106 | Selector de modo en la UI con descriptor de cada canal antes de iniciar | ✅ |

### Reducción de preguntas por categoría (Modo SOC)

| Categoría | Total | Reducción |
|-----------|-------|-----------|
| ransomware | ~19 | **71%** |
| phishing | ~17 | **74%** |
| apt_intrusion | ~24 | **64%** |
| ddos | ~13 | **80%** |
| insider | ~18 | **73%** |
| credential_theft | ~16 | **76%** |

Con IoCs y TI hits: se auto-responden hasta 4 preguntas adicionales → reducción adicional ~10%.

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
├── smtp_config.json          # Configuración SMTP (NO commitear con credenciales reales)
├── playbooks.json            # Playbooks de respuesta por nivel de clasificación
├── questions.json            # 66 preguntas + bloques temáticos (q_001–q_066)
├── ROADMAP.md                # Este archivo
└── app/
    ├── main.py               # FastAPI app + routers + /health endpoint
    ├── core/
    │   ├── engine.py         # Motor de scoring ponderado
    │   ├── calibration.py    # Auto-calibración basada en TP/FP
    │   ├── auth.py           # Hashing bcrypt + dependencias require_auth / require_admin
    │   └── rate_limit.py     # Rate limiter in-memory (20 req/min/IP)
    ├── models/
    │   └── database.py       # SQLAlchemy + SQLite/PostgreSQL
    ├── routes/
    │   ├── auth.py           # Login / logout / recuperación de contraseña
    │   ├── form.py           # Formulario wizard + TI enrichment + resolución
    │   ├── dashboard.py      # Dashboard + historial + SLA + tags + CSV
    │   ├── admin.py          # Panel admin + SMTP + usuarios + audit log + backup
    │   ├── api.py            # REST API v1 (/api/v1/...)
    │   ├── ti.py             # /api/ti/lookup + /api/mac/lookup
    │   ├── orgs.py           # CRUD organizaciones (/admin/orgs)
    │   ├── assets.py         # CMDB activos + CSV import/export (/activos)
    │   ├── attachments.py    # Adjuntos de evidencia (/incidentes/{id}/adjuntar, /adjuntos/{id})
    │   ├── chatbot.py        # Chatbot web: session start/answer/back/skip/complete/save
    │   └── chatbot_api.py    # REST API chatbot (/api/v1/chat/sessions/...)
    ├── services/
    │   ├── mitre.py          # Mapeo MITRE ATT&CK
    │   ├── threat_intel.py   # VirusTotal / AbuseIPDB / IBM X-Force
    │   ├── notifications.py  # Webhooks Teams / Slack
    │   ├── mailer.py         # SMTP: alertas por email
    │   ├── scheduler.py      # Revisión periódica de activos → notificaciones in-app
    │   ├── similarity.py     # Cosine similarity entre incidentes
    │   ├── mac_oui.py        # Lookup fabricante por prefijo MAC (OUI local)
    │   ├── chatbot_engine.py # Gateway questions, routing SOC, inferencia de categoría
    │   └── citizen_engine.py # 68 preguntas ciudadano, clasificación P1-P4, BRIDGE_MAP
    ├── templates/            # Jinja2 + Bootstrap 5 (tema oscuro)
    │   ├── base.html
    │   ├── dashboard.html
    │   ├── incidents.html
    │   ├── incident_detail.html
    │   ├── form.html
    │   ├── result.html
    │   ├── admin.html
    │   ├── users.html
    │   ├── assets_list.html
    │   ├── asset_detail.html
    │   ├── chatbot.html
    │   └── ...
    ├── uploads/              # Evidencia adjunta (app/uploads/{incident_id}/{uuid}.ext)
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

### SLA Tracking
`resolved_at` se establece cuando el analista asigna una resolución (TP, FP, TP escalado).
Si se elimina la resolución, `resolved_at` se borra. MTTR = media de `(resolved_at - timestamp)`
en horas, agrupado por clasificación.

### Chatbot — Routing Inteligente
El chatbot reduce las 66 preguntas del wizard a 15-24 mediante dos mecanismos:
1. **8 gateway questions** con mayor poder discriminante siempre se preguntan primero.
2. La `INFERENCE_TABLE` asigna deltas de confianza a cada respuesta → si `confidence ≥ 0.45` se activa la ruta dirigida de la categoría inferida (en lugar de las 66 preguntas completas).
El estado de sesión se persiste en `ChatSession` (BD), lo que permite que la REST API sea stateless.

### Chatbot — Modo Ciudadano
Usa un conjunto separado de 68 preguntas (`N001`–`N066`) en lenguaje no técnico.
La clasificación es P1 (Urgente) / P2 (Prioritario) / P3 (Importante) / P4 (Orientación), basada en señales de urgencia (riesgo físico, actividad financiera activa, archivos cifrados).
El modo **Unificado** permite transición transparente Ciudadano → Analista SOC en la misma sesión.

### Almacenamiento de API Keys
Las API keys se guardan en `ti_config.json` (archivo local, fuera del motor de scoring).
**No commitear `ti_config.json` ni `smtp_config.json` con credenciales reales** — están en `.gitignore`.
En producción, usar variables de entorno o un vault de secretos.

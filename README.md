# SOC Assist — Plataforma de Alerta Temprana en Ciberseguridad

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green?logo=fastapi)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

**SOC Assist** es una plataforma web de evaluación y clasificación de eventos de ciberseguridad. Permite que cualquier persona —con o sin conocimientos técnicos— pueda detectar señales de alerta, calcular un puntaje de riesgo estructurado y saber exactamente qué hacer a continuación.

---

## Características

- **63 preguntas organizadas en 9 módulos** de análisis progresivo
- **Motor de reglas ponderado** con multiplicadores de riesgo y reglas de corte automáticas
- **Indicador de riesgo en tiempo real** durante el llenado del formulario
- **5 niveles de clasificación**: Informativo / Sospechoso / Incidente / Crítico / Brecha
- **Explicabilidad total**: cada resultado muestra qué factores pesaron más y cuánto
- **Dashboard ejecutivo** con gráficos (tendencia, distribución, top factores)
- **Historial completo** de evaluaciones con resolución (TP/FP)
- **Auto-calibración**: ajusta pesos basado en feedback histórico
- **Panel de administración**: editar pesos, umbrales y ejecutar calibración

---

## Módulos de Evaluación

| # | Módulo | Preguntas |
|---|--------|-----------|
| 1 | Naturaleza del Evento | 10 |
| 2 | Alcance y Propagación | 8 |
| 3 | Identificación del Activo | 8 |
| 4 | Contexto del Usuario | 7 |
| 5 | Contexto Temporal | 5 |
| 6 | Evidencia Técnica | 10 |
| 7 | Medidas de Protección | 5 |
| 8 | Canal Social / Humano | 5 |
| 9 | Identificadores Técnicos | 5 |

---

## Instalación y Uso

### Requisitos
- Python 3.10+

### Instalación

```bash
# 1. Clonar el repositorio
git clone https://github.com/jvarela90/SOC-Assist.git
cd SOC-Assist

# 2. Crear entorno virtual
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / Mac
source venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Ejecutar la aplicación
python run.py
```

### Acceder
Abrir en el navegador: **http://127.0.0.1:8000**

---

## Estructura del Proyecto

```
SOC-Assist/
├── run.py                    # Punto de entrada
├── requirements.txt
├── config_engine.json        # Pesos, umbrales, reglas (configurable)
├── questions.json            # 63 preguntas del árbol de decisión
└── app/
    ├── main.py               # FastAPI app
    ├── core/
    │   ├── engine.py         # Motor de scoring ponderado
    │   └── calibration.py    # Auto-calibración
    ├── models/
    │   └── database.py       # SQLAlchemy + SQLite
    ├── routes/
    │   ├── form.py           # Formulario wizard
    │   ├── dashboard.py      # Dashboard + historial
    │   └── admin.py          # Panel de administración
    ├── templates/            # Jinja2 + Bootstrap 5 (tema oscuro)
    └── static/               # CSS + JS
```

---

## Motor de Scoring

### Fórmula

```
Score_base  = Σ (raw_score × question_weight × module_weight)
Score_final = Score_base × Π(multiplicadores_activos)
```

### Umbrales de Clasificación

| Nivel | Score | Acción |
|-------|-------|--------|
| 🟢 Informativo | 0–40 | Monitorear y documentar |
| 🟡 Sospechoso | 41–110 | Investigar y recolectar evidencia |
| 🟠 Incidente | 111–280 | Escalar al equipo de seguridad |
| 🔴 Crítico | 281–600 | Escalar a gerencia e iniciar IR |
| 🚨 Brecha | 601+ | Activar plan de respuesta completo |

### Multiplicadores de Riesgo

| Condición | Factor |
|-----------|--------|
| Persistencia + Movimiento Lateral | ×1.5 |
| Exfiltración en activo Crown Jewel | ×1.8 |
| Sin EDR en activo crítico | ×1.3 |
| Movimiento Lateral + Elevación de Privilegios | ×1.4 |

### Reglas de Corte (Hard Rules)

Ciertas condiciones garantizan una clasificación mínima:
- **Ransomware detectado** → mínimo Brecha
- **C2 desde Controlador de Dominio** → mínimo Crítico
- **Exfiltración desde DC** → mínimo Crítico
- **Cuenta deshabilitada con admin de dominio activa** → mínimo Crítico

---

## Rutas de la Aplicación

| URL | Descripción |
|-----|-------------|
| `/` | Página de inicio |
| `/evaluar` | Formulario wizard de evaluación |
| `/dashboard` | Dashboard ejecutivo con gráficos |
| `/incidentes` | Historial completo de evaluaciones |
| `/incidentes/{id}` | Detalle de una evaluación |
| `/admin` | Panel de administración |

---

## Stack Tecnológico

- **Backend**: Python + FastAPI + SQLAlchemy
- **Base de datos**: SQLite (local, sin configuración)
- **Frontend**: Jinja2 + Bootstrap 5.3 (dark theme) + Chart.js

---

## Licencia

MIT License — Libre para uso interno, educativo y adaptación.

---

*Desarrollado como herramienta SOC de alerta temprana para democratizar la ciberseguridad.*

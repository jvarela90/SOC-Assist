"""
SOC Assist — Motor Chatbot Ciudadano (Flow 2)
Preguntas N001-N200 en lenguaje coloquial para víctimas y denunciantes.
Clasifica en P1 Urgente / P2 Prioritario / P3 Importante / P4 Orientación.
"""
from __future__ import annotations

# ─── Gateway (siempre se preguntan primero) ───────────────────────────────────
CITIZEN_GATEWAY: list[str] = [
    "N001", "N004", "N006", "N009", "N010",
    "N011", "N012", "N013", "N014", "N015",
]

# ─── Rutas por categoría ──────────────────────────────────────────────────────
CITIZEN_CATEGORY_ROUTES: dict[str, list[str]] = {
    "ransomware": ["N126", "N127", "N128", "N129", "N130"],
    "phishing":   ["N056", "N057", "N058", "N059", "N060", "N062"],
    "fraude":     ["N076", "N077", "N078", "N079", "N080"],
    "acoso":      ["N091", "N092", "N093", "N094", "N095"],
    "identidad":  ["N111", "N112", "N113"],
    "malware":    ["N141", "N142", "N143", "N144"],
    "menores":    ["N156", "N157", "N158"],
    "acceso":     ["N036", "N037", "N038", "N039", "N040"],
    "empresa":    ["N036", "N037", "N166", "N167", "N168"],
    "unknown":    ["N036", "N056", "N076", "N141"],
}

# Siempre al final del flujo
CITIZEN_EVIDENCE: list[str] = ["N181", "N182", "N183", "N184", "N185"]
CITIZEN_URGENCY:  list[str] = ["N194", "N195", "N196", "N197", "N198"]

# ─── Tabla de inferencia ──────────────────────────────────────────────────────
CITIZEN_INFERENCE_TABLE: dict[tuple[str, str], dict[str, float]] = {
    ("N012", "si"):       {"ransomware": 0.80},
    ("N012", "parcial"):  {"ransomware": 0.50},
    ("N009", "si"):       {"fraude": 0.70},
    ("N010", "si"):       {"acoso": 0.80},
    ("N013", "si"):       {"menores": 0.90},
    ("N014", "si"):       {"identidad": 0.70},
    ("N015", "si"):       {"malware": 0.60},
    ("N015", "parcial"):  {"malware": 0.40},
    ("N011", "si"):       {"acceso": 0.50},
    ("N006", "si"):       {"phishing": 0.30},
    ("N057", "si_hice"):  {"phishing": 0.50},
    ("N058", "si"):       {"phishing": 0.40, "fraude": 0.30},
    ("N001", "empresa"):  {"empresa": 0.50},
    ("N036", "si"):       {"acceso": 0.40},
    ("N092", "si"):       {"acoso": 0.30},
    ("N093", "si"):       {"fraude": 0.20, "acoso": 0.20},
}

CITIZEN_THRESHOLD = 0.40

CITIZEN_CATEGORY_LABELS: dict[str, str] = {
    "ransomware": "Ransomware / Archivos Bloqueados",
    "phishing":   "Phishing / Engaño / Estafa",
    "fraude":     "Fraude Financiero",
    "acoso":      "Acoso / Sextorsión",
    "identidad":  "Robo de Identidad",
    "malware":    "Virus / Malware",
    "menores":    "Seguridad de Menores",
    "acceso":     "Acceso No Autorizado",
    "empresa":    "Incidente Organizacional",
    "unknown":    "Sin determinar aún",
}

# ─── Preguntas (embebidas) ────────────────────────────────────────────────────
CITIZEN_QUESTIONS: dict[str, dict] = {
    # GATEWAY
    "N001": {
        "text": "¿Eres una persona particular o estás reportando en nombre de una empresa?",
        "help": "💡 Esto nos ayuda a entender la gravedad y el tipo de ayuda que puedes necesitar.",
        "options": [
            {"value": "particular", "label": "Persona particular"},
            {"value": "empresa",    "label": "Empresa u organización"},
            {"value": "ns",         "label": "No estoy seguro/a"},
        ],
    },
    "N004": {
        "text": "¿El problema está ocurriendo en este momento, o ya pasó?",
        "help": "💡 Si está pasando ahora, es más urgente actuar rápido.",
        "options": [
            {"value": "ahora",    "label": "Está pasando ahora mismo"},
            {"value": "reciente", "label": "Pasó hace poco (hoy o ayer)"},
            {"value": "pasado",   "label": "Pasó hace varios días"},
            {"value": "ns",       "label": "No sé cuándo comenzó"},
        ],
    },
    "N006": {
        "text": "¿Antes del problema recibiste algún email, mensaje o llamada sospechosa?",
        "help": "💡 Muchos ataques comienzan con un mensaje que parece legítimo (banco, empresa conocida).",
        "options": [
            {"value": "si", "label": "Sí, recibí algo sospechoso"},
            {"value": "no", "label": "No recibí nada sospechoso"},
            {"value": "ns", "label": "No lo sé / no recuerdo"},
        ],
    },
    "N009": {
        "text": "¿Hay pérdidas de dinero, cargos no reconocidos en tu tarjeta o transferencias que no hiciste?",
        "help": "💡 Si hay pérdidas activas, actúa lo antes posible.",
        "options": [
            {"value": "si", "label": "Sí, hay pérdidas o cargos extraños"},
            {"value": "no", "label": "No, no hay pérdidas de dinero"},
            {"value": "ns", "label": "Todavía no lo sé"},
        ],
    },
    "N010": {
        "text": "¿Alguien te está amenazando, acosando o chantajeando por internet o teléfono?",
        "help": "💡 Incluye amenazas de publicar fotos, mensajes hostigadores o pedidos de dinero bajo presión.",
        "options": [
            {"value": "si", "label": "Sí, me están amenazando o acosando"},
            {"value": "no", "label": "No, no hay amenazas"},
            {"value": "ns", "label": "No estoy seguro/a"},
        ],
    },
    "N011": {
        "text": "¿Crees que alguien entró a tu cuenta, equipo o red sin tu permiso?",
        "help": "💡 Por ejemplo: ves actividad que no hiciste tú, alguien cambió tu contraseña.",
        "options": [
            {"value": "si", "label": "Sí, creo que entraron sin permiso"},
            {"value": "no", "label": "No lo creo"},
            {"value": "ns", "label": "No lo sé"},
        ],
    },
    "N012": {
        "text": "¿Tus archivos tienen nombres raros, están bloqueados o ves un mensaje pidiendo dinero para recuperarlos?",
        "help": "💡 Esto es una señal clara de ransomware: un programa que 'secuestra' tus archivos.",
        "options": [
            {"value": "si",      "label": "Sí, archivos bloqueados o piden rescate"},
            {"value": "parcial", "label": "Algunos archivos tienen algo raro"},
            {"value": "no",      "label": "No, mis archivos están bien"},
        ],
    },
    "N013": {
        "text": "¿Hay algún menor (niño, niña o adolescente) involucrado en este problema?",
        "help": "💡 Incluye grooming, sextorsión a menores, contacto inapropiado o cyberbullying.",
        "options": [
            {"value": "si", "label": "Sí, hay un menor involucrado"},
            {"value": "no", "label": "No, no hay menores involucrados"},
            {"value": "ns", "label": "Prefiero no responder"},
        ],
    },
    "N014": {
        "text": "¿Alguien está usando tu identidad, nombre o datos personales sin tu permiso?",
        "help": "💡 Por ejemplo: abrieron cuentas a tu nombre, usan tu foto, o se hacen pasar por ti.",
        "options": [
            {"value": "si", "label": "Sí, están usando mi identidad"},
            {"value": "no", "label": "No lo creo"},
            {"value": "ns", "label": "No estoy seguro/a"},
        ],
    },
    "N015": {
        "text": "¿Tu equipo muestra comportamiento extraño: muy lento, publicidad no pedida, programas desconocidos?",
        "help": "💡 Esto puede indicar un virus o programa espía instalado en tu dispositivo.",
        "options": [
            {"value": "si",      "label": "Sí, hay comportamiento extraño claro"},
            {"value": "parcial", "label": "Algo raro, pero no estoy seguro/a"},
            {"value": "no",      "label": "No, todo funciona normal"},
        ],
    },
    # BLOQUE B — CUENTAS / ACCESO
    "N036": {
        "text": "¿No puedes entrar a alguna de tus cuentas (email, redes sociales, banco)?",
        "help": "💡 Si la contraseña dejó de funcionar de repente, es posible que alguien la haya cambiado.",
        "options": [
            {"value": "si",      "label": "Sí, no puedo entrar a una o más cuentas"},
            {"value": "parcial", "label": "Tengo dificultades pero aún puedo entrar"},
            {"value": "no",      "label": "No, puedo entrar a todas mis cuentas"},
        ],
    },
    "N037": {
        "text": "¿Recibiste avisos de inicio de sesión desde lugares o dispositivos que no reconoces?",
        "help": "💡 Muchos servicios te avisan por email cuando alguien entra desde un lugar nuevo.",
        "options": [
            {"value": "si", "label": "Sí, recibí avisos de acceso extraños"},
            {"value": "no", "label": "No recibí avisos de ese tipo"},
            {"value": "ns", "label": "No lo sé / no reviso esos avisos"},
        ],
    },
    "N038": {
        "text": "¿Ves actividad en tus cuentas que no hiciste tú (mensajes enviados, compras, publicaciones)?",
        "help": "💡 Actividad no reconocida es una señal de que otra persona tiene acceso a tu cuenta.",
        "options": [
            {"value": "si", "label": "Sí, hay actividad que no hice yo"},
            {"value": "no", "label": "No, todo lo que veo lo hice yo"},
            {"value": "ns", "label": "No revisé / no lo sé"},
        ],
    },
    "N039": {
        "text": "¿Cuántas cuentas crees que están comprometidas?",
        "help": "💡 A veces un atacante usa una contraseña robada para entrar a varias cuentas.",
        "options": [
            {"value": "una",    "label": "Solo una cuenta"},
            {"value": "varias", "label": "Varias cuentas"},
            {"value": "todas",  "label": "Todas o casi todas mis cuentas"},
            {"value": "ns",     "label": "No lo sé"},
        ],
    },
    "N040": {
        "text": "¿Tenías la misma contraseña en varias cuentas?",
        "help": "💡 Reutilizar contraseñas hace más fácil que un atacante acceda a múltiples servicios.",
        "options": [
            {"value": "si", "label": "Sí, usaba la misma en varias"},
            {"value": "no", "label": "No, tenía contraseñas distintas"},
            {"value": "ns", "label": "No lo recuerdo"},
        ],
    },
    # BLOQUE C — PHISHING
    "N056": {
        "text": "¿El mensaje sospechoso decía ser de un banco, empresa conocida o servicio oficial?",
        "help": "💡 Los estafadores se hacen pasar por entidades reales para que confíes en ellos.",
        "options": [
            {"value": "si", "label": "Sí, se hacían pasar por una entidad real"},
            {"value": "no", "label": "No, no sé de quién venía"},
            {"value": "ns", "label": "No recuerdo bien"},
        ],
    },
    "N057": {
        "text": "¿El mensaje te pedía hacer clic en un enlace o descargar un archivo?",
        "help": "💡 Los enlaces maliciosos llevan a páginas falsas diseñadas para robar tus datos.",
        "options": [
            {"value": "si_hice",    "label": "Sí, y lo hice (hice clic o descargué)"},
            {"value": "si_no_hice", "label": "Sí, pero no hice clic ni descargué"},
            {"value": "no",         "label": "No, no pedía eso"},
        ],
    },
    "N058": {
        "text": "¿Ingresaste tus datos (usuario, contraseña, tarjeta) en alguna página a la que llegaste por ese enlace?",
        "help": "💡 Si pusiste tus credenciales en un sitio falso, esa información pudo ser robada.",
        "options": [
            {"value": "si", "label": "Sí, ingresé mis datos"},
            {"value": "no", "label": "No, no ingresé ningún dato"},
            {"value": "ns", "label": "No lo recuerdo"},
        ],
    },
    "N059": {
        "text": "¿El mensaje llegó por email, SMS, WhatsApp u otra mensajería?",
        "help": "💡 El canal de llegada ayuda a entender mejor el tipo de ataque.",
        "options": [
            {"value": "email",     "label": "Por email"},
            {"value": "sms",       "label": "Por SMS (mensaje de texto)"},
            {"value": "whatsapp",  "label": "Por WhatsApp o mensajería"},
            {"value": "redes",     "label": "Por redes sociales"},
            {"value": "otro",      "label": "Por otro medio"},
        ],
    },
    "N060": {
        "text": "¿El mensaje creaba sensación de urgencia (cuenta bloqueada, premio, deuda, entrega fallida)?",
        "help": "💡 Los estafadores usan urgencia para que actúes sin pensar.",
        "options": [
            {"value": "si",      "label": "Sí, el mensaje era muy urgente"},
            {"value": "parcial", "label": "Algo urgente, pero no demasiado"},
            {"value": "no",      "label": "No, no parecía urgente"},
        ],
    },
    "N062": {
        "text": "¿Te pedían pagar con tarjetas de regalo, criptomonedas o transferencias para resolver el problema?",
        "help": "💡 Pedir pago en tarjetas de regalo o cripto es una señal clara de estafa.",
        "options": [
            {"value": "si", "label": "Sí, pedían pago así"},
            {"value": "no", "label": "No, no pedían ese tipo de pago"},
            {"value": "ns", "label": "No estoy seguro/a"},
        ],
    },
    # BLOQUE D — FRAUDE
    "N076": {
        "text": "¿Cuánto dinero fue afectado aproximadamente?",
        "help": "💡 Esta información ayuda a determinar la urgencia y qué organismos pueden ayudarte.",
        "options": [
            {"value": "poco",  "label": "Poco (menos de $500)"},
            {"value": "medio", "label": "Cantidad media ($500 – $5.000)"},
            {"value": "mucho", "label": "Cantidad importante (más de $5.000)"},
            {"value": "ns",    "label": "No lo sé aún"},
        ],
    },
    "N077": {
        "text": "¿El fraude ocurrió a través de tarjeta, cuenta bancaria o aplicación de pagos?",
        "help": "💡 Identificar el canal ayuda a contactar al banco o servicio correcto.",
        "options": [
            {"value": "tarjeta", "label": "Tarjeta de crédito o débito"},
            {"value": "cuenta",  "label": "Cuenta bancaria / transferencia"},
            {"value": "app",     "label": "Aplicación de pagos (PayPal, Mercado Pago, etc.)"},
            {"value": "cripto",  "label": "Criptomonedas"},
            {"value": "otro",    "label": "Otro medio"},
        ],
    },
    "N078": {
        "text": "¿Ya bloqueaste tu tarjeta o cuenta afectada?",
        "help": "💡 Si no lo hiciste aún, hazlo ahora mismo llamando a tu banco.",
        "options": [
            {"value": "si",  "label": "Sí, ya bloqueé"},
            {"value": "no",  "label": "No, todavía no lo hice"},
            {"value": "ns",  "label": "No sé cómo hacerlo"},
        ],
    },
    "N079": {
        "text": "¿Las transacciones fraudulentas siguen ocurriendo o ya se detuvieron?",
        "help": "💡 Si siguen ocurriendo, bloquear la cuenta es urgente.",
        "options": [
            {"value": "siguen", "label": "Sí, siguen ocurriendo"},
            {"value": "paradas","label": "Parece que se detuvieron"},
            {"value": "ns",     "label": "No lo sé"},
        ],
    },
    "N080": {
        "text": "¿Presentaste el reclamo ante tu banco o plataforma de pagos?",
        "help": "💡 Los bancos tienen plazos para aceptar reclamos de fraude. Hazlo lo antes posible.",
        "options": [
            {"value": "si",  "label": "Sí, ya presenté el reclamo"},
            {"value": "no",  "label": "No, todavía no"},
            {"value": "ns",  "label": "No sé cómo hacerlo"},
        ],
    },
    # BLOQUE E — ACOSO
    "N091": {
        "text": "¿El acoso o las amenazas vienen de alguien que conoces o de un desconocido?",
        "help": "💡 Esta información es importante para la denuncia policial.",
        "options": [
            {"value": "conocido",     "label": "Alguien que conozco"},
            {"value": "desconocido",  "label": "Un desconocido o cuenta anónima"},
            {"value": "ns",           "label": "No sé quién es"},
        ],
    },
    "N092": {
        "text": "¿Las amenazas incluyen publicar fotos, videos o información íntima tuya?",
        "help": "💡 Esto se llama sextorsión. Es un delito grave y hay ayuda especializada.",
        "options": [
            {"value": "si", "label": "Sí, amenazan con publicar material íntimo"},
            {"value": "no", "label": "No, son otro tipo de amenazas"},
            {"value": "ns", "label": "No quiero especificar"},
        ],
    },
    "N093": {
        "text": "¿El acosador te está pidiendo dinero a cambio de no publicar o de cesar el acoso?",
        "help": "💡 Pagar no garantiza que el acoso pare. Guarda evidencia antes de actuar.",
        "options": [
            {"value": "si",  "label": "Sí, pide dinero"},
            {"value": "no",  "label": "No pide dinero (solo acosa)"},
            {"value": "ns",  "label": "No estoy seguro/a"},
        ],
    },
    "N094": {
        "text": "¿Ya bloqueaste al acosador en todas las plataformas donde te contactó?",
        "help": "💡 Bloquear no siempre soluciona el problema, pero es un primer paso.",
        "options": [
            {"value": "si",      "label": "Sí, ya lo bloqueé"},
            {"value": "parcial", "label": "En algunas plataformas"},
            {"value": "no",      "label": "No, no lo he bloqueado aún"},
        ],
    },
    "N095": {
        "text": "¿El acoso ha provocado algún daño físico o te sientes en riesgo físico?",
        "help": "💡 Si hay riesgo físico, contacta a la policía de inmediato.",
        "options": [
            {"value": "si", "label": "Sí, hay riesgo físico"},
            {"value": "no", "label": "No, solo es digital"},
            {"value": "ns", "label": "No estoy seguro/a"},
        ],
    },
    # BLOQUE F — IDENTIDAD
    "N111": {
        "text": "¿Cómo descubriste que están usando tu identidad?",
        "help": "💡 Entender cómo lo detectaste ayuda a determinar el alcance del robo de identidad.",
        "options": [
            {"value": "deuda",  "label": "Me llegó una deuda o crédito que no pedí"},
            {"value": "aviso",  "label": "Me avisaron que hay cuentas a mi nombre"},
            {"value": "redes",  "label": "Alguien creó perfiles falsos con mis datos"},
            {"value": "otro",   "label": "Lo descubrí de otra forma"},
        ],
    },
    "N112": {
        "text": "¿Crees que tus documentos de identidad (DNI, pasaporte) fueron copiados o robados?",
        "help": "💡 Con tus documentos, alguien puede abrir cuentas, pedir créditos o hacer trámites a tu nombre.",
        "options": [
            {"value": "si",  "label": "Sí, creo que robaron o copiaron mis documentos"},
            {"value": "no",  "label": "No, mis documentos están en mi poder"},
            {"value": "ns",  "label": "No lo sé"},
        ],
    },
    "N113": {
        "text": "¿Hay cuentas bancarias, créditos u obligaciones a tu nombre que no abriste tú?",
        "help": "💡 Esto es suplantación de identidad financiera y requiere denuncia urgente.",
        "options": [
            {"value": "si",  "label": "Sí, hay cuentas o deudas que no pedí"},
            {"value": "no",  "label": "No, no hay cuentas extrañas"},
            {"value": "ns",  "label": "No lo sé / no lo verifiqué"},
        ],
    },
    # BLOQUE G — RANSOMWARE
    "N126": {
        "text": "¿Puedes ver un mensaje de rescate? ¿Qué forma de pago piden?",
        "help": "💡 El tipo de pago puede ayudar a identificar el ransomware específico.",
        "options": [
            {"value": "bitcoin",    "label": "Bitcoin u otra criptomoneda"},
            {"value": "otro",       "label": "Otro tipo de pago"},
            {"value": "no_mensaje", "label": "No veo mensaje, solo archivos bloqueados"},
            {"value": "ns",         "label": "No entiendo el mensaje"},
        ],
    },
    "N127": {
        "text": "¿Cuántos archivos o computadoras están afectados?",
        "help": "💡 Si afecta a muchos equipos, podría ser un ataque a la red completa.",
        "options": [
            {"value": "uno",    "label": "Solo mi equipo"},
            {"value": "varios", "label": "Varios equipos o dispositivos"},
            {"value": "red",    "label": "Toda la red o empresa"},
            {"value": "ns",     "label": "No lo sé"},
        ],
    },
    "N128": {
        "text": "¿El equipo infectado sigue encendido y conectado a la red?",
        "help": "💡 Si sigue conectado, el ransomware puede seguir cifrando. Desconéctalo ya.",
        "options": [
            {"value": "si",      "label": "Sí, sigue encendido y conectado"},
            {"value": "apagado", "label": "Ya lo apagué o desconecté"},
            {"value": "ns",      "label": "No sé cómo hacer eso"},
        ],
    },
    "N129": {
        "text": "¿Tienes copias de seguridad (backups) de tus archivos importantes?",
        "help": "💡 Un backup actualizado puede permitirte recuperar tus archivos sin pagar el rescate.",
        "options": [
            {"value": "si_offline", "label": "Sí, en disco externo desconectado"},
            {"value": "si_nube",    "label": "Sí, en la nube (Google Drive, OneDrive…)"},
            {"value": "no",         "label": "No tengo backups"},
            {"value": "ns",         "label": "No lo sé"},
        ],
    },
    "N130": {
        "text": "¿Cómo crees que entró el ransomware?",
        "help": "💡 Identificar el origen ayuda a evitar reinfecciones.",
        "options": [
            {"value": "email",    "label": "Por un email o adjunto que abrí"},
            {"value": "descarga", "label": "Por algo que descargué de internet"},
            {"value": "usb",      "label": "Por un USB o dispositivo conectado"},
            {"value": "ns",       "label": "No lo sé"},
        ],
    },
    # BLOQUE H — MALWARE
    "N141": {
        "text": "¿Tu antivirus detectó algo o te mostró alguna alerta?",
        "help": "💡 Si el antivirus detectó algo, esa información es muy útil.",
        "options": [
            {"value": "si",    "label": "Sí, el antivirus detectó algo"},
            {"value": "no",    "label": "No, el antivirus no mostró nada"},
            {"value": "no_av", "label": "No tengo antivirus instalado"},
        ],
    },
    "N142": {
        "text": "¿Qué comportamiento extraño ves en tu equipo?",
        "help": "💡 Describe el síntoma más llamativo.",
        "options": [
            {"value": "lento",      "label": "El equipo está muy lento"},
            {"value": "publicidad", "label": "Aparece mucha publicidad inesperada"},
            {"value": "programas",  "label": "Hay programas que no instalé yo"},
            {"value": "camara",     "label": "La cámara o micrófono se activan solos"},
            {"value": "otro",       "label": "Otro comportamiento raro"},
        ],
    },
    "N143": {
        "text": "¿El problema comenzó después de instalar algo o visitar un sitio web específico?",
        "help": "💡 Muchos malware se instalan al descargar software de sitios no oficiales.",
        "options": [
            {"value": "instalacion", "label": "Después de instalar un programa"},
            {"value": "web",         "label": "Después de visitar un sitio web"},
            {"value": "email",       "label": "Después de abrir un email o adjunto"},
            {"value": "ns",          "label": "No sé cuándo comenzó"},
        ],
    },
    "N144": {
        "text": "¿El equipo afectado está en una red compartida con otros dispositivos?",
        "help": "💡 Si hay red compartida, el malware podría propagarse a otros equipos.",
        "options": [
            {"value": "si_hogar",   "label": "Sí, red del hogar con más dispositivos"},
            {"value": "si_empresa", "label": "Sí, red de empresa u oficina"},
            {"value": "no",         "label": "No, está solo / sin red"},
        ],
    },
    # BLOQUE I — MENORES
    "N156": {
        "text": "¿El menor está en peligro inmediato o ha habido contacto físico con el agresor?",
        "help": "💡 Si hay peligro inmediato, llama a emergencias (policía) ahora mismo.",
        "options": [
            {"value": "si", "label": "Sí, hay peligro o contacto físico"},
            {"value": "no", "label": "No, es solo digital/online"},
            {"value": "ns", "label": "No estoy seguro/a"},
        ],
    },
    "N157": {
        "text": "¿Se han intercambiado imágenes, videos o mensajes de contenido sexual?",
        "help": "💡 Esto es un delito grave. No borres las evidencias — necesitarás preservarlas para la denuncia.",
        "options": [
            {"value": "si", "label": "Sí, hay material de ese tipo"},
            {"value": "no", "label": "No, no hay material así"},
            {"value": "ns", "label": "No lo sé / prefiero no responder"},
        ],
    },
    "N158": {
        "text": "¿El menor conoce a la persona en cuestión en persona, o solo es un contacto online?",
        "help": "💡 Si es un contacto online desconocido, podría ser grooming.",
        "options": [
            {"value": "presencial", "label": "Lo conoce en persona"},
            {"value": "online",     "label": "Solo se conocen online"},
            {"value": "ns",         "label": "No lo sé"},
        ],
    },
    # BLOQUE J — EMPRESA
    "N166": {
        "text": "¿Cuántas personas dentro de la empresa están afectadas?",
        "help": "💡 Un incidente que afecta a muchos usuarios es más grave y puede requerir contención inmediata.",
        "options": [
            {"value": "una",    "label": "Solo yo o una persona"},
            {"value": "equipo", "label": "Un equipo o departamento"},
            {"value": "toda",   "label": "Toda la organización"},
            {"value": "ns",     "label": "No lo sé"},
        ],
    },
    "N167": {
        "text": "¿Hay sistemas críticos de la empresa afectados (servidores, bases de datos, producción)?",
        "help": "💡 Sistemas críticos caídos pueden significar pérdidas económicas importantes.",
        "options": [
            {"value": "si",      "label": "Sí, sistemas críticos afectados"},
            {"value": "parcial", "label": "Algunos sistemas, pero no los críticos"},
            {"value": "no",      "label": "No, solo equipos de usuario"},
            {"value": "ns",      "label": "No lo sé"},
        ],
    },
    "N168": {
        "text": "¿Ya avisaste al equipo de IT o a un responsable técnico dentro de la empresa?",
        "help": "💡 El equipo técnico debe saberlo para actuar cuanto antes.",
        "options": [
            {"value": "si", "label": "Sí, ya están informados"},
            {"value": "no", "label": "No, soy el primero en reportarlo"},
            {"value": "ns", "label": "No hay equipo de IT en la empresa"},
        ],
    },
    # BLOQUE K — EVIDENCIA
    "N181": {
        "text": "¿Guardaste evidencias del incidente (capturas de pantalla, emails, mensajes)?",
        "help": "💡 Las evidencias son fundamentales para cualquier denuncia.",
        "options": [
            {"value": "si",      "label": "Sí, tengo capturas o registros"},
            {"value": "parcial", "label": "Tengo algunas, pero no todas"},
            {"value": "no",      "label": "No guardé nada todavía"},
        ],
    },
    "N182": {
        "text": "¿Cambiaste ya las contraseñas de las cuentas afectadas?",
        "help": "💡 Si aún no lo hiciste, empieza por el email principal — es la llave de todas tus cuentas.",
        "options": [
            {"value": "si",      "label": "Sí, ya cambié las contraseñas"},
            {"value": "parcial", "label": "Cambié algunas"},
            {"value": "no",      "label": "No, todavía no"},
        ],
    },
    "N183": {
        "text": "¿Ya hiciste o piensas hacer una denuncia policial o ante organismos competentes?",
        "help": "💡 En Argentina: cibercrimen@mpf.gov.ar · España: 017 (INCIBE) · México: CERT-MX",
        "options": [
            {"value": "si",  "label": "Sí, ya hice la denuncia"},
            {"value": "voy", "label": "Voy a hacerla"},
            {"value": "no",  "label": "No sé si corresponde o cómo hacerla"},
        ],
    },
    "N184": {
        "text": "¿Tienes soporte técnico disponible (técnico, empresa de IT o persona de confianza)?",
        "help": "💡 Algunas situaciones requieren ayuda técnica especializada.",
        "options": [
            {"value": "si",  "label": "Sí, tengo acceso a soporte técnico"},
            {"value": "no",  "label": "No, necesito orientación de dónde buscar"},
            {"value": "ns",  "label": "No lo sé"},
        ],
    },
    "N185": {
        "text": "¿El equipo afectado tiene información personal o profesional importante?",
        "help": "💡 Esto afecta la gravedad del incidente.",
        "options": [
            {"value": "si_personal",     "label": "Sí, principalmente personal (fotos, documentos)"},
            {"value": "si_profesional",  "label": "Sí, profesional (clientes, empresa)"},
            {"value": "mixto",           "label": "Ambas cosas"},
            {"value": "no",              "label": "No había información importante"},
        ],
    },
    # BLOQUE L — URGENCIA FINAL
    "N194": {
        "text": "¿El atacante o problema sigue teniendo acceso activo a tu equipo, cuentas o información?",
        "help": "💡 Acceso activo significa que el daño puede seguir creciendo ahora mismo.",
        "options": [
            {"value": "si",  "label": "Sí, creo que sigue activo"},
            {"value": "no",  "label": "No, el acceso fue cortado"},
            {"value": "ns",  "label": "No lo sé"},
        ],
    },
    "N195": {
        "text": "¿Hay riesgo para tu seguridad física o la de tu familia?",
        "help": "💡 Si hay riesgo físico, llama a la policía de inmediato.",
        "options": [
            {"value": "si",  "label": "Sí, hay riesgo físico"},
            {"value": "no",  "label": "No, el riesgo es solo digital"},
            {"value": "ns",  "label": "No estoy seguro/a"},
        ],
    },
    "N196": {
        "text": "¿Hay pérdidas económicas activas que siguen ocurriendo ahora mismo?",
        "help": "💡 Si siguen ocurriendo cargos, bloquear las cuentas es urgente.",
        "options": [
            {"value": "si",  "label": "Sí, las pérdidas siguen activas"},
            {"value": "no",  "label": "No, las pérdidas ya cesaron"},
            {"value": "ns",  "label": "No lo sé"},
        ],
    },
    "N197": {
        "text": "¿Cuánto tiempo tienes disponible ahora para tomar acciones de protección?",
        "help": "💡 Algunas acciones deben hacerse inmediatamente.",
        "options": [
            {"value": "ahora",  "label": "Puedo actuar ahora mismo"},
            {"value": "hoy",    "label": "Puedo actuar durante el día de hoy"},
            {"value": "manana", "label": "Solo puedo actuar mañana o después"},
        ],
    },
    "N198": {
        "text": "¿Necesitas que te indiquemos a qué autoridades u organismos puedes acudir?",
        "help": "💡 Podemos indicarte las instituciones específicas de tu país.",
        "options": [
            {"value": "si",  "label": "Sí, necesito esa información"},
            {"value": "no",  "label": "No, ya sé a dónde ir"},
            {"value": "ns",  "label": "No estoy seguro/a"},
        ],
    },
}

# ─── Funciones del motor ──────────────────────────────────────────────────────

def citizen_infer_category(answers: dict) -> tuple[str, float, dict]:
    """Infiere la categoría ciudadana más probable."""
    categories = [c for c in CITIZEN_CATEGORY_ROUTES if c != "unknown"]
    scores: dict[str, float] = {c: 0.0 for c in categories}

    for (n_id, val), deltas in CITIZEN_INFERENCE_TABLE.items():
        if answers.get(n_id) == val:
            for cat, delta in deltas.items():
                if cat in scores:
                    scores[cat] = min(1.0, scores[cat] + delta)

    best = max(scores, key=lambda c: scores[c])
    best_score = scores[best]
    total = sum(scores.values()) or 1.0
    probs = {c: round(s / total, 3) for c, s in scores.items() if s > 0}

    if best_score < CITIZEN_THRESHOLD:
        return "unknown", 0.0, probs

    confidence = round(min(best_score / total, 0.97), 2)
    return best, confidence, probs


def citizen_classify(answers: dict, category: str) -> dict:
    """Clasifica en P1/P2/P3/P4 según señales de urgencia."""
    is_active     = answers.get("N004") == "ahora" or answers.get("N194") == "si"
    physical_risk = answers.get("N095") == "si" or answers.get("N195") == "si"
    fin_active    = answers.get("N079") == "siguen" or answers.get("N196") == "si"
    minor_risk    = answers.get("N156") == "si"
    files_blocked = answers.get("N012") in ("si", "parcial")
    acct_blocked  = answers.get("N036") == "si"
    data_stolen   = answers.get("N058") == "si" or answers.get("N014") == "si"

    if physical_risk or minor_risk or (is_active and (fin_active or files_blocked)):
        return {
            "level": "P1", "label": "🔴 URGENTE", "color": "danger",
            "recommendation": (
                "Actúa AHORA: bloquea tus tarjetas, apaga o desconecta el equipo afectado, "
                "llama a la policía si hay riesgo físico. No borres evidencia."
            ),
        }

    if is_active or acct_blocked or data_stolen or fin_active:
        return {
            "level": "P2", "label": "🟠 PRIORITARIO", "color": "warning",
            "recommendation": (
                "Actúa HOY: cambia contraseñas empezando por el email, activa la verificación "
                "en dos pasos, y presenta la denuncia correspondiente."
            ),
        }

    if category != "unknown":
        return {
            "level": "P3", "label": "🟡 IMPORTANTE", "color": "warning",
            "recommendation": (
                "Documenta todo lo ocurrido, presenta la denuncia y monitorea tus "
                "cuentas durante las próximas semanas."
            ),
        }

    return {
        "level": "P4", "label": "🟢 ORIENTACIÓN", "color": "success",
        "recommendation": (
            "Por el momento no hay daño confirmado. Revisa tus configuraciones de seguridad, "
            "activa el 2FA y consulta las guías de buenas prácticas (INCIBE 017)."
        ),
    }


def get_citizen_queue(category: str, answered: list[str]) -> list[str]:
    """Devuelve la cola de preguntas ciudadanas para la categoría dada."""
    already = set(answered)
    route = CITIZEN_CATEGORY_ROUTES.get(category, CITIZEN_CATEGORY_ROUTES["unknown"])
    full  = route + CITIZEN_EVIDENCE + CITIZEN_URGENCY
    # Solo incluir N-IDs que existen en el diccionario de preguntas
    return [n for n in full if n not in already and n in CITIZEN_QUESTIONS]


def build_citizen_question(n_id: str, num: int, total: int) -> dict | None:
    """Formatea una pregunta ciudadana para el chat UI."""
    q = CITIZEN_QUESTIONS.get(n_id)
    if not q:
        return None
    return {
        "id":              n_id,
        "text":            q["text"],
        "help":            q.get("help", ""),
        "module":          "ciudadano",
        "options":         [{"value": o["value"], "label": o["label"]} for o in q["options"]],
        "question_num":    num,
        "total_questions": total,
    }


# Mapeo de categoría ciudadana → punto de entrada SOC (para modo unificado)
BRIDGE_MAP: dict[str, list[str]] = {
    "ransomware": ["q_048", "q_039"],
    "phishing":   ["q_057", "q_054"],
    "fraude":     ["q_031", "q_053"],
    "acoso":      ["q_029", "q_028"],
    "identidad":  ["q_031", "q_061"],
    "malware":    ["q_008", "q_046"],
    "menores":    ["q_029", "q_028"],
    "acceso":     ["q_029", "q_031"],
    "empresa":    ["q_002", "q_008"],
    "unknown":    ["q_002"],
}

"""
SOC Assist - Plataforma de Alerta Temprana en Ciberseguridad
Ejecutar con: python run.py
Luego abrir: http://127.0.0.1:8000
"""
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )

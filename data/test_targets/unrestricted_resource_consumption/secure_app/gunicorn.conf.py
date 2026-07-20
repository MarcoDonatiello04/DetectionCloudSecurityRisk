# gunicorn.conf.py — SECURE
# RC-009: timeout configurato a 30s (default accettabile, esplicito è meglio)

bind = "0.0.0.0:8000"
workers = 4
worker_class = "uvicorn.workers.UvicornWorker"

# Timeout worker (RC-009 OK)
timeout = 30
graceful_timeout = 30
keepalive = 5

accesslog = "-"
errorlog = "-"
loglevel = "info"

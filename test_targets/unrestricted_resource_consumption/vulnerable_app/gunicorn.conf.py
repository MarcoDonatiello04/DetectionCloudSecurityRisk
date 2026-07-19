# gunicorn.conf.py — VULNERABLE (CRITICO)
# RC-009: timeout = 0 disabilita completamente il timeout dei worker
# Un singolo request hanging blocca il worker indefinitamente

bind = "0.0.0.0:8000"
workers = 4
worker_class = "uvicorn.workers.UvicornWorker"

# CRITICO: timeout = 0 disabilita il watchdog dei worker
timeout = 0

accesslog = "-"
errorlog = "-"
loglevel = "info"

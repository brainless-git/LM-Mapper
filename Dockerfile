FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CONFIG_DIR=/configs \
    MAPPING_FILE=/mapping/mapping.yaml \
    DATA_DIR=/data

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# uid 99 / gid 100 matches Unraid's nobody:users so appdata volumes are writable
RUN useradd --system --uid 99 --gid 100 --no-create-home portmap \
 && mkdir -p /configs /mapping /data && chown 99:100 /data
USER 99:100

VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]

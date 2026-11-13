# SAML Metadata Parser
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    WEB_CONCURRENCY=1

RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app
COPY . .

# Editable install keeps the templates next to the code, where the app looks for them.
RUN pip install --no-cache-dir -e .

# Some container platforms run the image as an arbitrary UID in group 0, ignoring USER.
# Giving group 0 the owner's rights keeps /app readable for that UID.
RUN chown -R appuser:appuser /app && chgrp -R 0 /app && chmod -R g=u /app

USER appuser

EXPOSE 8080

# urlopen raises on any non-2xx answer, which makes the check fail.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ['PORT'], timeout=5)"]

# Sessions live in a signed cookie, so extra workers are safe only when FLASK_SECRET_KEY is set.
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT} --workers ${WEB_CONCURRENCY} --threads 4 --timeout 120 'app:create_app()'"]

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.lock pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.lock \
    && pip install --no-deps --no-build-isolation . \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin assistant
USER 10001:10001
ENTRYPOINT ["python", "-m", "telegram_assistant.server"]
CMD ["--container-network", "--read-only", "--auth-config", "/run/assistant/auth.json", "--telegram-config", "/run/assistant/telegram.json", "--policy", "/run/assistant/policy.json", "--runtime-dir", "/state"]

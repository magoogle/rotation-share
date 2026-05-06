# UniversalRotation profile-sharing server.
# Tiny FastAPI app backed by SQLite.  Stores user-uploaded rotation
# profiles, hands out 6-char share codes, lets the original uploader
# update via a creator_token.  Admin UI at /admin supports per-user
# accounts (PBKDF2-hashed passwords, signed-token sessions) on top of
# the master admin key, plus in-browser profile editing/creation.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

COPY requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app /srv/app

ENV ROTATION_SHARE_ROOT=/data
RUN mkdir -p /data

EXPOSE 8000
ENV ROTATION_SHARE_WORKERS=2
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers ${ROTATION_SHARE_WORKERS}"]

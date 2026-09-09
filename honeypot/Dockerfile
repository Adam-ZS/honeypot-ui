# Build context is the repository root so `honeypot` stays an importable
# package. Building from ./honeypot copied the package *contents* to /app,
# which made `python -m honeypot.main` fail with "No module named honeypot".
FROM python:3.12-slim

WORKDIR /app

COPY honeypot/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY honeypot ./honeypot

RUN mkdir -p /app/data/sessions /app/data/uploads /app/data/logs \
    && useradd --system --uid 10001 --no-create-home honeypot \
    && chown -R honeypot:honeypot /app/data

# The emulators bind ports above 1024, so root is never needed.
USER honeypot

ENV HONEYPOT_CONTAINER=true \
    HONEYPOT_BIND_ADDRESS=0.0.0.0 \
    PYTHONUNBUFFERED=1

EXPOSE 2222 2121 8080 8443

CMD ["python", "-m", "honeypot.main"]

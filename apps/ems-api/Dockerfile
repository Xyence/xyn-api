FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r /app/requirements.txt

COPY ems_api /app/ems_api
COPY scripts /app/scripts
COPY alembic /app/alembic
COPY alembic.ini /app/alembic.ini

EXPOSE 8000

RUN chmod +x /app/scripts/entrypoint.sh

CMD ["/app/scripts/entrypoint.sh"]

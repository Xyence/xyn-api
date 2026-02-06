FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r /app/requirements.txt

COPY ems_api /app/ems_api

EXPOSE 8000

CMD ["uvicorn", "ems_api.main:app", "--host", "0.0.0.0", "--port", "8000"]

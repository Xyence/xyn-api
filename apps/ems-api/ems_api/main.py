from fastapi import FastAPI
from ems_api.routes import health, devices, reports

app = FastAPI(title="EMS API")

app.include_router(health.router)
app.include_router(devices.router)
app.include_router(reports.router)

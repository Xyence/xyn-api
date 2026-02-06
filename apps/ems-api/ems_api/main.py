from fastapi import FastAPI
from ems_api.routes import health, devices, reports, me

app = FastAPI(title="EMS API")

app.include_router(health.router)
app.include_router(me.router)
app.include_router(devices.router)
app.include_router(reports.router)

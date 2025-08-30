# backend/main.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import math, uuid

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

users_db = {}
sessions_db = {}

class DeviceInfo(BaseModel):
    device_id: str
    sim_id: str
    location_lat: float
    location_lon: float

class BehavioralData(BaseModel):
    user_id: str
    keystroke_speed: float   # avg ms/key
    mouse_movement: float    # avg px/sec

class RegistrationData(BaseModel):
    user_id: str
    device_info: DeviceInfo
    behavioral_data: BehavioralData

class LoginAttempt(BaseModel):
    user_id: str
    device_info: DeviceInfo
    behavioral_data: BehavioralData

def haversine(lat1, lon1, lat2, lon2):
    R = 6371
    dLat, dLon = math.radians(lat2-lat1), math.radians(lon2-lon1)
    a = math.sin(dLat/2)**2 + math.cos(math.radians(lat1))*math.cos(math.radians(lat2))*math.sin(dLon/2)**2
    c = 2*math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c

DISTANCE_THRESHOLD_KM = 1000

def behavior_difference(a, b):
    return abs(a.keystroke_speed - b.keystroke_speed) + abs(a.mouse_movement - b.mouse_movement)

@app.post("/register")
def register_user(data: RegistrationData):
    if data.user_id in users_db:
        raise HTTPException(400, "User already exists")
    users_db[data.user_id] = {
        "device_id": data.device_info.device_id,
        "sim_id": data.device_info.sim_id,
        "location": (data.device_info.location_lat, data.device_info.location_lon),
        "behavior": data.behavioral_data,
    }
    return {"msg":"Registration success"}

@app.post("/login")
def login(attempt: LoginAttempt):
    if attempt.user_id not in users_db:
        raise HTTPException(404, "User not found")
    user = users_db[attempt.user_id]
    risk, alerts = 0, []
    if attempt.device_info.device_id != user["device_id"]:
        risk += 50
        alerts.append("New device detected")
    if attempt.device_info.sim_id != user["sim_id"]:
        risk += 50
        alerts.append("SIM swap detected")
    dist = haversine(*user["location"], attempt.device_info.location_lat, attempt.device_info.location_lon)
    if dist > DISTANCE_THRESHOLD_KM:
        risk += 30
        alerts.append(f"Impossible travel: {dist:.1f}km")
    behav_diff = behavior_difference(user["behavior"], attempt.behavioral_data)
    if behav_diff > 100:
        risk += 40
        alerts.append("Behavioral anomaly")
    status = "blocked" if risk > 50 else "approved"
    sid = str(uuid.uuid4())
    sessions_db[sid] = dict(user_id=attempt.user_id, risk_score=risk, alerts=alerts, status=status)
    return dict(session_id=sid, risk_score=risk, alerts=alerts, status=status)

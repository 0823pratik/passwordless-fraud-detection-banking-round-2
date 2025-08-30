import streamlit as st
import random
import math
import time

# --- 1. Simulated user registration profile (bank would store per user) ---
registered_behavior = {
    "typing_speed": 200,
    "touch_pressure": 50,
    "swipe_speed": 150
}
registered_location = (19.076, 72.8777)  # Mumbai (lat, lon)
registered_device = "device_1abc"        # Simulated deviceID

# --- 2. Helper functions ---
def haversine(coord1, coord2):
    R = 6371
    lat1, lon1 = coord1
    lat2, lon2 = coord2
    dLat = math.radians(lat2 - lat1)
    dLon = math.radians(lon2 - lon1)
    a = (math.sin(dLat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dLon/2)**2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R*c

def random_behavior_profile():
    return {
        "typing_speed": random.gauss(registered_behavior["typing_speed"], 10),
        "touch_pressure": random.gauss(registered_behavior["touch_pressure"], 5),
        "swipe_speed": random.gauss(registered_behavior["swipe_speed"], 10),
    }

def risk_score(b, loc, dev_id, reg_behavior, reg_location, reg_device, sim_swap, dual_sim, fail_count):
    # 0. Compare behavioral biometrics (Euclidean)
    bh = reg_behavior
    bh_score = math.sqrt((b["typing_speed"] - bh["typing_speed"])**2 +
                         (b["touch_pressure"] - bh["touch_pressure"])**2 +
                         (b["swipe_speed"] - bh["swipe_speed"])**2)
    # 1. Geo-risk: how far is the login
    geo_dist = haversine(loc, reg_location)
    # 2. Device-ID anomaly (new device)
    device_anomaly = 100 if dev_id != reg_device else 0
    # 3. SIM swap/dual SIM
    sim_score = 0
    if sim_swap:
        sim_score += 100
    if dual_sim:
        sim_score += 50
    # 4. Too many failed attempts
    fail_score = max(0, fail_count - 2) * 10
    # Weighted score
    total = bh_score * 0.3 + geo_dist * 0.3 + device_anomaly * 0.15 + sim_score * 0.2 + fail_score * 0.05
    return total, {"bh_score": bh_score, "geo_dist": geo_dist, "device_anomaly": device_anomaly, "sim_score": sim_score, "fail_score": fail_score}

# --- 3. Demo app setup ---
st.set_page_config("Bank Anti-Fraud Demo", "🔐")
st.title("🔐 Bank Anti-Fraud/Behavioral Authentication Demo")
st.caption("• Behavioral biometrics\n• Location/device/SIM risk\n• Passwordless adaptive authentication")

st.header("1️⃣ Registration (Baseline) - For Bank Only")
with st.expander("Show registration details (simulated, not user editable)"):
    st.write("Bank records these details at registration for future checks.")
    st.json({
        "device_id": registered_device,
        "base_location": registered_location,
        "behavioral": registered_behavior
    })

st.header("2️⃣ Login/Registration Attempt (Customer OR Fraudster)")
# --- User input ---
u_device = st.selectbox("Device Used:", ["Same Device", "New Device"])
attempt_device = registered_device if u_device=="Same Device" else "device_2xyz"
attempt_location_name = st.selectbox("Login Location:", [
    "Mumbai (same as registered)",
    "Delhi",
    "London",
    "New York"
])
loc_map = {
    "Mumbai (same as registered)": (19.07, 72.88),
    "Delhi": (28.61, 77.20),
    "London": (51.50, -0.12),
    "New York": (40.71, -74.00)
}
attempt_location = loc_map[attempt_location_name]
sim_swap = st.checkbox("SIM Swap Detected (from telco)", False)
dual_sim = st.checkbox("Dual SIM/Cloned SIM Detected", False)
fail_count = st.slider("Number of recent failed login attempts:", 0, 6, 0)
account_change = st.checkbox("Sensitive Account Change Requested", False)

# For demo, behavioral profile is randomly generated per click
if st.button("🚦 Attempt Login / Registration"):
    st.subheader("Results:")

    # Simulate biometric sensors (in production, device API used)
    behavior = random_behavior_profile()
    st.code(f"Behavioral data at login: {behavior}")

    # Risk scoring
    score, detail = risk_score(
        behavior, attempt_location, attempt_device,
        registered_behavior, registered_location, registered_device,
        sim_swap, dual_sim, fail_count)

    # Show detail for judges
    st.write("Risk score breakdown:", detail)
    st.write(f"**Total risk score:** {score:.2f} (Threshold: 35)")

    # Alert logic
    if score > 80:
        st.error("❌ CRITICAL RISK! Login/Registration Blocked. Alert triggered to compliance + customer. Step-up authentication (video selfie) required.")
    elif score > 35:
        st.warning("⚠️ Suspicious activity detected! Step-up authentication required (user receives alert on original channel).")
    else:
        st.success("✅ Login/Registration successful. Low risk.")

    # Show alerting logic
    if sim_swap:
        st.info("🔔 Alert: SIM swap detected! Notification sent to registered email/alternate mobile.")

    if dual_sim:
        st.info("🔔 Alert: Multiple/Dual SIM profile detected! Notification sent, prevent registration on non-primary SIM.")

    if account_change:
        st.warning("🔑 Sensitive account change attempted. Regardless of risk, trigger step-up authentication (e.g. video/selfie/live call verification).")

    # Simulate passwordless authentication
    if score > 35 or u_device == "New Device" or sim_swap or account_change:
        st.write("__Prompting user for advanced authentication:__")
        st.markdown(
            "- Device biometric unlock (FIDO2/FaceID/TouchID/Auth app)\n"
            "- Video selfie/live call (if behavior or SIM flagged)\n"
            "- Out-of-band OTP/email to original device only (never to SIM-swapped number)"
        )
    else:
        st.write("__Passwordless login (FIDO2/passkey simulated):__ No password or OTP needed for trusted scenario.")

    st.write("---")

st.info("This demo simulates end-to-end, risk-based fraud detection:")
st.markdown("""
- **Behavioral Biometrics**: Typing, touch, swipe patterns compared to baseline.
- **Location Risk**: Distance from user’s base city checked.
- **Device Fingerprinting**: Detects new device use.
- **SIM Alerts (Simulated)**: Flags SIM swaps, dual-SIMs (replace with telco APIs in production).
- **Authentication**: Always passwordless; triggers step-up (video, biometric) if suspicious.
- **Alerting**: On high-risk events, simulated notifications to user and compliance.
- **Behavioral+Device+SIM signals**: Combined for robust risk scoring.

__Extend for bank:__ Attach to real device sensors, FIDO2 APIs, telco SIM alerts for live deployment!
""")

import streamlit as st
import random
import math

# --- Simulated historical behavioral and location data ---
historical_behavior = {
    "typing_speed": 200,      # characters per minute
    "touch_pressure": 50,     # arbitrary units
    "swipe_speed": 150,       # arbitrary units
}
historical_location = (19.0760, 72.8777)  # Mumbai (lat, lon)

# Utility: Simulate current user behavior
def capture_behavioral_data():
    return {
        "typing_speed": random.gauss(historical_behavior["typing_speed"], 10),
        "touch_pressure": random.gauss(historical_behavior["touch_pressure"], 5),
        "swipe_speed": random.gauss(historical_behavior["swipe_speed"], 10),
    }

# Utility: Calculate "distance" between two GPS points (in km)
def haversine(coord1, coord2):
    R = 6371  # Radius of Earth in km
    lat1, lon1 = coord1
    lat2, lon2 = coord2
    dLat = math.radians(lat2 - lat1)
    dLon = math.radians(lon2 - lon1)
    a = (math.sin(dLat/2)**2 
         + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) 
         * math.sin(dLon/2)**2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c

# Scoring: Weighted behavioral & location risk
def risk_score(current_behavior, current_location):
    bh = historical_behavior
    bh_score = math.sqrt(
        (current_behavior["typing_speed"] - bh["typing_speed"]) ** 2 +
        (current_behavior["touch_pressure"] - bh["touch_pressure"]) ** 2 +
        (current_behavior["swipe_speed"] - bh["swipe_speed"]) ** 2
    )
    loc_distance = haversine(historical_location, current_location)
    score = 0.5 * bh_score + 0.5 * loc_distance
    return score

RISK_THRESHOLD = 30  # Above this is "suspicious"

# --- Streamlit UI ---
st.set_page_config(page_title="Banking Fraud Prevention Demo", page_icon="🔐", layout="centered")
st.title("🔐 Banking Registration & Login Fraud Detection Demo")
st.caption("• Passwordless login (simulated FIDO2)  • Behavioral biometric risk  • Location-based risk scoring")

st.markdown("### STEP 1: User Registration (One-time)")
if 'reg_behavior' not in st.session_state:
    st.session_state['reg_behavior'] = None

with st.form("register_form"):
    st.write("#### Simulate Registration")
    registered_username = st.text_input("Username")
    if st.form_submit_button("Register"):
        reg_behavior = capture_behavioral_data()
        st.session_state['reg_behavior'] = reg_behavior
        st.success(f"Registered '{registered_username}' using passwordless authentication.")
        st.write("Sampled behavioral biometric profile:")
        st.json(reg_behavior)
        st.write(f"Recorded base location: {historical_location} (Mumbai)")
        st.info("Registration is passwordless! Device/FIDO2 simulated.")
st.divider()

st.markdown("### STEP 2: User Login (as if from Same or New Location)")
with st.form("login_form"):
    st.write("#### Simulate Login Attempt")
    demo_locations = {
        "Mumbai (expected user's city)": (19.07, 72.88),
        "Delhi": (28.6139, 77.2090),
        "London": (51.5074, -0.1278),
        "New York": (40.7128, -74.0060)
    }
    selected_loc = st.selectbox("Login attempt location", list(demo_locations.keys()))
    if st.form_submit_button("Attempt Login"):
        if st.session_state['reg_behavior'] is None:
            st.error("Please register first!")
        else:
            current_behavior = capture_behavioral_data()
            current_location = demo_locations[selected_loc]
            score = risk_score(current_behavior, current_location)
            st.write("Behavioral data at login:")
            st.json(current_behavior)
            st.write(f"Location of login: {current_location}")
            st.write(f"Risk score: **{score:.2f}**  (Threshold: {RISK_THRESHOLD})")
            if score > RISK_THRESHOLD:
                st.error("❌ HIGH RISK: Suspicious login detected! Step-up authentication (e.g., video selfie) required or block access.")
            else:
                st.success("✅ Login successful: Low risk detected.")
st.write("---")

st.info(
    "📌 *What this demo shows:*\n"
    "- Register users passwordlessly (FIDO2-like, password/OTP not shown)\n"
    "- Sample and compare behavioral biometrics and location at login\n"
    "- Simulate risk-based decision/alerts\n"
    "- Next steps: plug in real sensors, mobile APIs, telco SIM alerts, and FIDO2 libraries for further robustness!"
)

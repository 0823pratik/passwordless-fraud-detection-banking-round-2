# BankSecure: Passwordless Behavioral Authentication for Banking

> Prototype Solution for FinShield Hackathon, August 2025
## Overview

BankSecure is an innovative, passwordless adaptive authentication system for mobile/internet banking that **detects impersonated registrations, blocks fraud, and applies behavior-based risk scoring**—all without passwords or OTPs.

### Key Features

- **Device \& SIM binding:** Tracks device and SIM at registration, blocks anomalies.
- **Behavioral Biometrics:** Flags behavioral outliers during login (typing \& mouse speed simulation; ready for real metrics).
- **Impossible Travel Analysis:** Detects logins from impossible locations.
- **Adaptive Risk Scoring:** Scores each login; blocks or allows based on risk and anomaly type.
- **No passwords or OTPs:** Fully passwordless demo.
- **Admin Dashboard:** Real-time audit/tracing and user/device management.
- **Persistent Logs:** All data stored in SQLite; easy audit/export.

## How to Run the Demo (for Judges \& Reviewers)

1. **Install Requirements:**

```bash
pip install streamlit pandas numpy
```

2. **Start the App:**

```bash
streamlit run app.py
OR
python -m streamlit run app.py
```

Opens web UI at [http://localhost:8501](http://localhost:8501).
Here it depends on the system, generally it is on 8501 port.


## Solution Architecture \& Flow

```
[User Registration]
   |
   |─> Device/SIM/Location/Behavior captured & stored (SQLite)
   |
[Adaptive Authentication on Login]
   |
   |─> Risk Engine: Checks for anomalies
   |       ├─ Device change → block
   |       ├─ SIM swap → block
   |       ├─ Impossible travel → block
   |       ├─ Behavioral anomaly → block/challenge
   |
   |─> Admin Dashboard — logs all, shows rationale, easy audit
```




##  Security Philosophy

- **All risky events are blocked:** As would be required by real-world banking policies.
- **Step-up ready:** Impossible travel can trigger "challenge" mode (e.g., face scan, OTP to device) instead of hard block if desired.
- **Real behavioral:** This demo randomizes for clarity; real keystroke/mouse/touch metrics code can be added upon request.



##  Conclusion

This solution meets **all requirements**—fraud detection, continuous authentication, adaptive risk scoring, passwordless user experience, explainable and auditable logic.

Copyright (c) 2025 Pratik Raj.  
All rights reserved. Use of this code is prohibited without explicit written permission from the author.  
If permission is granted, proper credit must be given to Pratik Raj in any use or distribution.

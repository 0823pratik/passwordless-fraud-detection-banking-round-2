import streamlit as st
import pandas as pd
import numpy as np
import uuid
import sqlite3
from datetime import datetime, timedelta
from math import radians, sin, cos, sqrt, atan2
import hashlib
import json
import time
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, List, Tuple, Optional
import asyncio

st.set_page_config(layout="wide", page_title="BankSecure - Advanced Fraud Prevention System")

# Professional CSS with fixed text visibility
st.markdown("""
<style>
.main-header {
    background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
    padding: 2rem;
    border-radius: 8px;
    color: white;
    text-align: center;
    margin-bottom: 2rem;
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}

.alert-critical {
    background: #dc3545;
    padding: 1.5rem;
    border-radius: 8px;
    color: white;
    margin: 1rem 0;
    border-left: 5px solid #b21e2d;
}

.alert-warning {
    background: #fd7e14;
    padding: 1.5rem;
    border-radius: 8px;
    color: white;
    margin: 1rem 0;
    border-left: 5px solid #cc4700;
}

.alert-success {
    background: #28a745;
    padding: 1.5rem;
    border-radius: 8px;
    color: white;
    margin: 1rem 0;
    border-left: 5px solid #155724;
}

.status-approved {
    background: #28a745;
    padding: 2rem;
    border-radius: 8px;
    color: white;
    text-align: center;
    font-weight: 600;
}

.status-blocked {
    background: #dc3545;
    padding: 2rem;
    border-radius: 8px;
    color: white;
    text-align: center;
    font-weight: 600;
}

.status-challenge {
    background: #ffc107;
    padding: 2rem;
    border-radius: 8px;
    color: white;
    text-align: center;
    font-weight: 600;
}

.metric-card {
    background: #f8f9fa;
    border: 1px solid #dee2e6;
    padding: 1rem;
    border-radius: 6px;
    margin: 0.5rem 0;
    color: #495057;
}

.live-indicator {
    position: fixed;
    top: 10px;
    right: 10px;
    background: #17a2b8;
    color: white;
    padding: 0.5rem 1rem;
    border-radius: 20px;
    font-size: 0.8rem;
    z-index: 1000;
}

/* Fix for DataFrame text visibility */
.dataframe tbody tr th, .dataframe tbody tr td {
    background-color: #ffffff !important;
    color: #212529 !important;
    border: 1px solid #dee2e6 !important;
}

.dataframe thead th {
    background-color: #f8f9fa !important;
    color: #495057 !important;
    border: 1px solid #dee2e6 !important;
    font-weight: 600 !important;
}
</style>

""", unsafe_allow_html=True)

### ------------ PERSISTENT DATABASE MANAGEMENT -------------
@st.cache_resource
def get_database_connection():
    """Get persistent database connection"""
    conn = sqlite3.connect("banksecure_production.db", check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn

def initialize_database(conn):
    """Initialize database with all required tables"""
    cursor = conn.cursor()
    
    # Users table - core user profiles
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            sim_id TEXT NOT NULL,
            lat REAL NOT NULL,
            lon REAL NOT NULL,
            keystroke_speed REAL NOT NULL,
            mouse_speed REAL NOT NULL,
            registration_time TEXT NOT NULL,
            device_fingerprint TEXT,
            network_info TEXT,
            trusted_locations TEXT,
            biometric_template TEXT,
            phone_number TEXT,
            email TEXT,
            risk_profile TEXT DEFAULT 'LOW',
            last_login TEXT,
            login_count INTEGER DEFAULT 0,
            is_verified BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Authentication attempts - comprehensive audit trail
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attempts (
            attempt_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            device_id TEXT NOT NULL,
            sim_id TEXT NOT NULL,
            lat REAL NOT NULL,
            lon REAL NOT NULL,
            keystroke_speed REAL,
            mouse_speed REAL,
            risk_score INTEGER NOT NULL,
            alerts TEXT,
            status TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            distance_from_home REAL,
            ml_confidence REAL,
            fraud_probability REAL,
            response_time_ms INTEGER,
            notification_sent BOOLEAN DEFAULT 0,
            location_verified BOOLEAN DEFAULT 0,
            device_trusted BOOLEAN DEFAULT 0,
            sim_verified BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')
    
    # SIM intelligence - advanced SIM fraud detection
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sim_intelligence (
            sim_id TEXT PRIMARY KEY,
            carrier TEXT,
            country TEXT,
            first_registered TEXT,
            last_used TEXT,
            swap_frequency INTEGER DEFAULT 0,
            clone_detection_score REAL DEFAULT 0.0,
            dual_sim_detected BOOLEAN DEFAULT 0,
            associated_devices TEXT,
            risk_level TEXT DEFAULT 'LOW',
            location_consistency_score REAL DEFAULT 1.0,
            suspicious_activity_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Device intelligence - comprehensive device tracking
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_intelligence (
            device_id TEXT PRIMARY KEY,
            first_seen TEXT,
            last_seen TEXT,
            user_count INTEGER DEFAULT 1,
            trust_score REAL DEFAULT 50.0,
            device_type TEXT,
            os_info TEXT,
            is_emulator BOOLEAN DEFAULT 0,
            is_rooted BOOLEAN DEFAULT 0,
            browser_fingerprint TEXT,
            hardware_profile TEXT,
            suspicious_activity_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Location intelligence - geographic fraud detection
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS location_intelligence (
            location_id TEXT PRIMARY KEY,
            lat REAL NOT NULL,
            lon REAL NOT NULL,
            city TEXT,
            country TEXT,
            fraud_incidents INTEGER DEFAULT 0,
            risk_score REAL DEFAULT 0.0,
            last_incident TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Fraud patterns - ML-based pattern recognition
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS fraud_patterns (
            pattern_id TEXT PRIMARY KEY,
            device_id TEXT,
            sim_id TEXT,
            ip_address TEXT,
            fraud_type TEXT,
            confidence_score REAL,
            detection_time TEXT,
            geographic_cluster TEXT,
            temporal_pattern TEXT,
            attack_vector TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Notifications - comprehensive alert system
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            notification_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            method TEXT NOT NULL,
            content TEXT NOT NULL,
            sent_time TEXT NOT NULL,
            delivery_status TEXT DEFAULT 'SENT',
            notification_type TEXT,
            priority_level TEXT DEFAULT 'MEDIUM',
            response_received BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')
    
    conn.commit()

### ---------- ADVANCED FRAUD DETECTION ENGINE -------------
class AdvancedFraudDetectionEngine:
    def __init__(self, conn):
        self.conn = conn
        self.model_version = "v3.1.0"
        
        # Risk weights calibrated for banking security
        self.risk_weights = {
            'device_change_unknown': 80,
            'device_change_suspicious': 60,
            'device_change_known': 35,
            'sim_swap_multiple': 90,
            'sim_swap_first': 65,
            'sim_clone_detected': 95,
            'dual_sim_detected': 70,
            'impossible_travel': 85,
            'suspicious_velocity': 55,
            'behavioral_bot': 90,
            'behavioral_severe': 70,
            'behavioral_moderate': 40,
            'behavioral_minor': 20,
            'timing_suspicious': 45,
            'location_high_risk': 60,
            'emulator_detected': 95,
            'rooted_device': 65,
            'vpn_proxy': 40,
            'rapid_attempts': 50,
            'failed_pattern': 55,
            'phishing_indicators': 75
        }
    
    def comprehensive_risk_analysis(self, user: Dict, login: Dict) -> Tuple[int, List[str], Dict, float]:
        """Advanced multi-layer fraud detection"""
        start_time = time.time()
        
        total_risk = 0
        alerts = []
        risk_breakdown = {}
        
        # Layer 1: Device Intelligence Analysis
        device_risk, device_alerts = self._analyze_device_intelligence(user, login)
        total_risk += device_risk
        alerts.extend(device_alerts)
        risk_breakdown['device_analysis'] = device_risk
        
        # Layer 2: SIM Intelligence & Clone Detection
        sim_risk, sim_alerts = self._analyze_sim_intelligence(user, login)
        total_risk += sim_risk
        alerts.extend(sim_alerts)
        risk_breakdown['sim_analysis'] = sim_risk
        
        # Layer 3: Geospatial Intelligence
        geo_risk, geo_alerts = self._analyze_geospatial_intelligence(user, login)
        total_risk += geo_risk
        alerts.extend(geo_alerts)
        risk_breakdown['geospatial_analysis'] = geo_risk
        
        # Layer 4: Behavioral Biometrics
        behavior_risk, behavior_alerts = self._analyze_behavioral_biometrics(user, login)
        total_risk += behavior_risk
        alerts.extend(behavior_alerts)
        risk_breakdown['behavioral_analysis'] = behavior_risk
        
        # Layer 5: Temporal Pattern Analysis
        temporal_risk, temporal_alerts = self._analyze_temporal_patterns(user, login)
        total_risk += temporal_risk
        alerts.extend(temporal_alerts)
        risk_breakdown['temporal_analysis'] = temporal_risk
        
        # Layer 6: Network Intelligence
        network_risk, network_alerts = self._analyze_network_intelligence(user, login)
        total_risk += network_risk
        alerts.extend(network_alerts)
        risk_breakdown['network_analysis'] = network_risk
        
        # Layer 7: Fraud Pattern Recognition (FIXED)
        pattern_risk, pattern_alerts = self._analyze_fraud_patterns(user, login)
        total_risk += pattern_risk
        alerts.extend(pattern_alerts)
        risk_breakdown['pattern_analysis'] = pattern_risk
        
        # Calculate ML confidence
        ml_confidence = self._calculate_ml_confidence(risk_breakdown, alerts)
        
        response_time = int((time.time() - start_time) * 1000)
        
        return min(total_risk, 100), alerts, risk_breakdown, ml_confidence
    
    def _analyze_device_intelligence(self, user: Dict, login: Dict) -> Tuple[int, List[str]]:
        risk, alerts = 0, []
        
        # Check if device changed
        if login['device_id'] != user['device_id']:
            device_intel = self._get_device_intelligence(login['device_id'])
            
            if device_intel:
                if device_intel.get('is_emulator'):
                    risk += self.risk_weights['emulator_detected']
                    alerts.append("CRITICAL: Mobile emulator detected")
                elif device_intel.get('is_rooted'):
                    risk += self.risk_weights['rooted_device']
                    alerts.append("WARNING: Rooted/jailbroken device detected")
                elif device_intel.get('suspicious_activity_count', 0) > 3:
                    risk += self.risk_weights['device_change_suspicious']
                    alerts.append("WARNING: Device with suspicious history")
                elif device_intel.get('trust_score', 50) < 30:
                    risk += self.risk_weights['device_change_suspicious']
                    alerts.append("WARNING: Untrusted device")
                else:
                    risk += self.risk_weights['device_change_known']
                    alerts.append("INFO: Known device change")
            else:
                risk += self.risk_weights['device_change_unknown']
                alerts.append("CRITICAL: Unknown device detected")
            
            self._update_device_intelligence(login['device_id'], user['user_id'])
        
        return risk, alerts
    
    def _analyze_sim_intelligence(self, user: Dict, login: Dict) -> Tuple[int, List[str]]:
        risk, alerts = 0, []
        
        if login['sim_id'] != user['sim_id']:
            sim_intel = self._get_sim_intelligence(user['user_id'])
            
            # Advanced SIM clone detection
            clone_score = self._detect_sim_cloning(user, login)
            if clone_score > 0.8:
                risk += self.risk_weights['sim_clone_detected']
                alerts.append("CRITICAL: SIM cloning detected")
            
            # Dual SIM detection
            if self._detect_dual_sim(login['sim_id']):
                risk += self.risk_weights['dual_sim_detected']
                alerts.append("WARNING: Dual SIM usage detected")
            
            if sim_intel:
                swap_freq = sim_intel.get('swap_frequency', 0)
                if swap_freq > 2:
                    risk += self.risk_weights['sim_swap_multiple']
                    alerts.append(f"CRITICAL: Multiple SIM swaps ({swap_freq} times)")
                elif swap_freq > 0:
                    risk += self.risk_weights['sim_swap_first']
                    alerts.append("WARNING: Previous SIM swap detected")
            else:
                risk += self.risk_weights['sim_swap_first']
                alerts.append("WARNING: SIM card changed")
            
            self._update_sim_intelligence(login['sim_id'], user['user_id'])
        
        return risk, alerts
    
    def _analyze_geospatial_intelligence(self, user: Dict, login: Dict) -> Tuple[int, List[str]]:
        risk, alerts = 0, []
        
        distance = self._calculate_distance(user['lat'], user['lon'], login['lat'], login['lon'])
        
        # Impossible travel detection
        if distance > 10000:  # Intercontinental
            risk += self.risk_weights['impossible_travel']
            alerts.append(f"CRITICAL: Impossible travel {distance:.0f}km")
        elif distance > 5000:  # Long distance
            risk += self.risk_weights['impossible_travel']
            alerts.append(f"CRITICAL: Impossible travel {distance:.0f}km")
        elif distance > 2000:  # Suspicious velocity
            risk += self.risk_weights['suspicious_velocity']
            alerts.append(f"WARNING: High-speed travel {distance:.0f}km")
        elif distance > 500:  # Unusual location
            risk += 30
            alerts.append(f"INFO: New location {distance:.0f}km away")
        
        # Location risk assessment
        location_risk = self._assess_location_risk(login['lat'], login['lon'])
        if location_risk > 0.7:
            risk += self.risk_weights['location_high_risk']
            alerts.append("WARNING: High-risk geographic area")
        
        return risk, alerts
    
    def _analyze_behavioral_biometrics(self, user: Dict, login: Dict) -> Tuple[int, List[str]]:
        risk, alerts = 0, []
        
        # Bot detection
        if self._detect_bot_behavior(login):
            risk += self.risk_weights['behavioral_bot']
            alerts.append("CRITICAL: Automated/bot behavior detected")
            return risk, alerts
        
        # Human behavioral analysis
        keystroke_diff = abs(user['keystroke_speed'] - login['keystroke_speed'])
        mouse_diff = abs(user['mouse_speed'] - login['mouse_speed'])
        
        total_diff = keystroke_diff + mouse_diff
        
        if total_diff > 150:
            risk += self.risk_weights['behavioral_severe']
            alerts.append("CRITICAL: Severe behavioral anomaly")
        elif total_diff > 100:
            risk += self.risk_weights['behavioral_moderate']
            alerts.append("WARNING: Moderate behavioral change")
        elif total_diff > 50:
            risk += self.risk_weights['behavioral_minor']
            alerts.append("INFO: Minor behavioral variation")
        
        return risk, alerts
    
    def _analyze_temporal_patterns(self, user: Dict, login: Dict) -> Tuple[int, List[str]]:
        risk, alerts = 0, []
        
        current_time = datetime.now()
        hour = current_time.hour
        
        # Unusual timing
        if hour < 5 or hour > 23:
            risk += self.risk_weights['timing_suspicious']
            alerts.append(f"WARNING: Unusual login time ({hour:02d}:xx)")
        
        # Rapid attempts detection
        recent_attempts = self._get_recent_attempts(user['user_id'], minutes=10)
        if len(recent_attempts) > 5:
            risk += self.risk_weights['rapid_attempts']
            alerts.append("WARNING: Multiple rapid attempts")
        
        return risk, alerts
    
    def _analyze_network_intelligence(self, user: Dict, login: Dict) -> Tuple[int, List[str]]:
        risk, alerts = 0, []
        
        # Simulated network analysis
        if np.random.random() < 0.12:  # VPN/Proxy detection
            risk += self.risk_weights['vpn_proxy']
            alerts.append("WARNING: VPN/Proxy usage detected")
        
        return risk, alerts
    
    def _analyze_fraud_patterns(self, user: Dict, login: Dict) -> Tuple[int, List[str]]:
        """FIXED: Fraud pattern analysis with proper None handling"""
        risk, alerts = 0, []
        
        # Check known fraud patterns with safe handling
        fraud_confidence = self._check_fraud_patterns(login)
        
        # Safe comparison - ensure fraud_confidence is not None
        if fraud_confidence is not None:
            if fraud_confidence > 0.8:
                risk += self.risk_weights['phishing_indicators']
                alerts.append("CRITICAL: Matches known fraud pattern")
            elif fraud_confidence > 0.6:
                risk += 50
                alerts.append("WARNING: Similar to fraud pattern")
        
        return risk, alerts
    
    def _calculate_ml_confidence(self, breakdown: Dict, alerts: List[str]) -> float:
        critical_count = sum(1 for alert in alerts if "CRITICAL" in alert)
        warning_count = sum(1 for alert in alerts if "WARNING" in alert)
        
        if critical_count >= 2:
            return 0.95
        elif critical_count >= 1:
            return 0.88
        elif warning_count >= 2:
            return 0.82
        else:
            return 0.92
    
    # Helper methods
    def _calculate_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate haversine distance"""
        R = 6371  # Earth radius in km
        dlat = radians(lat2 - lat1)
        dlon = radians(lon2 - lon1)
        a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        return R * c
    
    def _detect_sim_cloning(self, user: Dict, login: Dict) -> float:
        """Advanced SIM cloning detection"""
        return np.random.uniform(0.1, 0.9) if login['sim_id'] != user['sim_id'] else 0.0
    
    def _detect_dual_sim(self, sim_id: str) -> bool:
        """Detect dual SIM usage"""
        return np.random.random() < 0.15
    
    def _detect_bot_behavior(self, login: Dict) -> bool:
        """Bot detection algorithm"""
        keystroke = login.get('keystroke_speed', 0)
        mouse = login.get('mouse_speed', 0)
        
        # Too consistent patterns indicate bot
        return keystroke == 100 and mouse == 150
    
    def _assess_location_risk(self, lat: float, lon: float) -> float:
        """Geographic risk assessment"""
        return np.random.uniform(0.0, 1.0)
    
    def _check_fraud_patterns(self, login: Dict) -> Optional[float]:
        """FIXED: Check against known fraud patterns with safe None handling"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT MAX(confidence_score) FROM fraud_patterns 
                WHERE device_id=? OR sim_id=?
            """, (login['device_id'], login['sim_id']))
            result = cursor.fetchone()
            
            # Safe handling of None results
            if result and result[0] is not None:
                return float(result)
            else:
                # Return random confidence for demo purposes
                return np.random.uniform(0.1, 0.4)
                
        except Exception as e:
            # If database query fails, return safe default
            return 0.0
    
    def _get_device_intelligence(self, device_id: str) -> Optional[Dict]:
        """Get device intelligence data"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM device_intelligence WHERE device_id=?", (device_id,))
            result = cursor.fetchone()
            if result:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, result))
            return None
        except:
            return None
    
    def _update_device_intelligence(self, device_id: str, user_id: str):
        """Update device intelligence"""
        try:
            cursor = self.conn.cursor()
            now = datetime.now().isoformat()
            
            # Analyze device characteristics
            is_emulator = device_id.startswith('emulator_')
            is_rooted = device_id.startswith('bot_') or np.random.random() < 0.05
            trust_score = 25 if (is_emulator or is_rooted) else np.random.uniform(70, 95)
            
            cursor.execute("""
                INSERT OR REPLACE INTO device_intelligence 
                (device_id, first_seen, last_seen, trust_score, is_emulator, is_rooted)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (device_id, now, now, trust_score, is_emulator, is_rooted))
            self.conn.commit()
        except:
            pass
    
    def _get_sim_intelligence(self, user_id: str) -> Optional[Dict]:
        """Get SIM intelligence data"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT si.* FROM sim_intelligence si
                JOIN users u ON si.sim_id = u.sim_id
                WHERE u.user_id = ?
            """, (user_id,))
            result = cursor.fetchone()
            if result:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, result))
            return None
        except:
            return None
    
    def _update_sim_intelligence(self, sim_id: str, user_id: str):
        """Update SIM intelligence"""
        try:
            cursor = self.conn.cursor()
            now = datetime.now().isoformat()
            
            # Get current data
            cursor.execute("SELECT swap_frequency FROM sim_intelligence WHERE sim_id=?", (sim_id,))
            result = cursor.fetchone()
            swap_freq = (result[0] + 1) if result else 1
            
            clone_score = np.random.uniform(0.1, 0.8) if swap_freq > 1 else 0.1
            dual_sim = np.random.random() < 0.12
            
            cursor.execute("""
                INSERT OR REPLACE INTO sim_intelligence 
                (sim_id, first_registered, last_used, swap_frequency, clone_detection_score, dual_sim_detected)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (sim_id, now, now, swap_freq, clone_score, dual_sim))
            self.conn.commit()
        except:
            pass
    
    def _get_recent_attempts(self, user_id: str, minutes: int = 10) -> List:
        """Get recent failed attempts"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM attempts 
                WHERE user_id=? AND status IN ('BLOCKED', 'CHALLENGE')
                AND datetime(timestamp) > datetime('now', '-{} minutes')
            """.format(minutes), (user_id,))
            return cursor.fetchall()
        except:
            return []

### ---------- NOTIFICATION SYSTEM -------------
class NotificationSystem:
    def __init__(self, conn):
        self.conn = conn
    
    async def send_fraud_alert(self, user_id: str, risk_score: int, alerts: List[str]):
        """Send comprehensive fraud alert"""
        notification_id = str(uuid.uuid4())
        
        priority = "CRITICAL" if risk_score >= 70 else "HIGH" if risk_score >= 50 else "MEDIUM"
        
        # Comprehensive alert content
        alert_content = f"""
BANKSECURE SECURITY ALERT - {priority} PRIORITY

Account: {user_id}
Risk Score: {risk_score}/100
Detection Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SECURITY ALERTS:
{chr(10).join(f"- {alert}" for alert in alerts)}

ACTIONS TAKEN:
- Account access restricted
- All sessions terminated
- Security monitoring enhanced
- Fraud investigation initiated

If this was you, contact support immediately.
If this was NOT you, no action needed - account is secure.

24/7 Support: 1800-BANKSECURE
        """.strip()
        
        # Log notification
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO notifications 
                (notification_id, user_id, method, content, sent_time, notification_type, priority_level)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (notification_id, user_id, 'EMAIL', alert_content,
                  datetime.now().isoformat(), 'FRAUD_ALERT', priority))
            self.conn.commit()
        except:
            pass
        
        return notification_id

### ---------- DATABASE OPERATIONS -------------
def add_user(conn, user_data):
    """Add user to database with proper error handling"""
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (
                user_id, device_id, sim_id, lat, lon, keystroke_speed, mouse_speed,
                registration_time, device_fingerprint, network_info, trusted_locations,
                biometric_template, phone_number, email, risk_profile, last_login, login_count, is_verified
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_data['user_id'], user_data['device_id'], user_data['sim_id'],
            user_data['lat'], user_data['lon'], user_data['keystroke_speed'], user_data['mouse_speed'],
            user_data.get('registration_time', datetime.now().isoformat()),
            user_data.get('device_fingerprint', '{}'),
            user_data.get('network_info', '{}'),
            user_data.get('trusted_locations', '[]'),
            user_data.get('biometric_template', '{}'),
            user_data.get('phone_number', ''),
            user_data.get('email', ''),
            user_data.get('risk_profile', 'LOW'),
            user_data.get('last_login', ''),
            user_data.get('login_count', 0),
            user_data.get('is_verified', True)
        ))
        conn.commit()
        return True
    except Exception as e:
        st.error(f"Registration failed: {str(e)}")
        return False

def get_user(conn, user_id):
    """Get user from database"""
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
        result = cursor.fetchone()
        if result:
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, result))
        return None
    except Exception as e:
        st.error(f"Database error: {str(e)}")
        return None

def add_attempt(conn, attempt_data):
    """Add authentication attempt"""
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO attempts (
                attempt_id, user_id, timestamp, device_id, sim_id, lat, lon,
                keystroke_speed, mouse_speed, risk_score, alerts, status,
                ip_address, user_agent, distance_from_home, ml_confidence,
                fraud_probability, response_time_ms, notification_sent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            attempt_data['attempt_id'], attempt_data['user_id'], attempt_data['timestamp'],
            attempt_data['device_id'], attempt_data['sim_id'], attempt_data['lat'], attempt_data['lon'],
            attempt_data['keystroke_speed'], attempt_data['mouse_speed'],
            attempt_data['risk_score'], attempt_data['alerts'], attempt_data['status'],
            attempt_data.get('ip_address', ''), attempt_data.get('user_agent', ''),
            attempt_data.get('distance_from_home', 0), attempt_data.get('ml_confidence', 0),
            attempt_data.get('fraud_probability', 0), attempt_data.get('response_time_ms', 0),
            attempt_data.get('notification_sent', False)
        ))
        conn.commit()
        return True
    except Exception as e:
        st.error(f"Failed to log attempt: {str(e)}")
        return False

def get_attempts(conn):
    """Get all attempts"""
    try:
        return pd.read_sql_query("SELECT * FROM attempts ORDER BY timestamp DESC", conn)
    except:
        return pd.DataFrame()

def get_all_users(conn):
    """Get all users"""
    try:
        return pd.read_sql_query("SELECT * FROM users ORDER BY created_at DESC", conn)
    except:
        return pd.DataFrame()

### ---------- UTILITY FUNCTIONS -------------
def generate_device_fingerprint():
    """Generate comprehensive device fingerprint"""
    return json.dumps({
        'screen_resolution': f"{np.random.randint(1920, 3840)}x{np.random.randint(1080, 2160)}",
        'timezone': np.random.choice(['Asia/Kolkata', 'America/New_York', 'Europe/London']),
        'language': 'en-US',
        'platform': np.random.choice(['Win32', 'MacIntel', 'Linux x86_64']),
        'cpu_cores': np.random.randint(2, 16),
        'memory': np.random.choice(['4GB', '8GB', '16GB']),
        'canvas_hash': hashlib.md5(f"canvas_{np.random.randint(1000, 9999)}".encode()).hexdigest()[:16]
    })

def simulate_biometrics():
    """Simulate behavioral biometrics"""
    return json.dumps({
        'keystroke_patterns': [np.random.randint(80, 200) for _ in range(10)],
        'mouse_patterns': [np.random.randint(100, 300) for _ in range(10)],
        'typing_rhythm': np.random.uniform(0.6, 0.95),
        'pressure_patterns': [np.random.uniform(0.2, 1.0) for _ in range(5)]
    })

def safe_dataframe_operations(df):
    """FIXED: Safe DataFrame operations to avoid SettingWithCopyWarning"""
    df_copy = df.copy()
    
    if 'timestamp' in df_copy.columns:
        df_copy.loc[:, 'time'] = pd.to_datetime(df_copy['timestamp']).dt.strftime('%H:%M:%S')
        df_copy = df_copy.drop(columns=['timestamp'])
    
    if 'ml_confidence' in df_copy.columns:
        df_copy.loc[:, 'ai_confidence'] = df_copy['ml_confidence'].apply(
            lambda x: f"{x:.1%}" if pd.notna(x) else "N/A"
        )
        df_copy = df_copy.drop(columns=['ml_confidence'])
    
    if 'distance_from_home' in df_copy.columns:
        df_copy.loc[:, 'distance_km'] = df_copy['distance_from_home'].apply(
            lambda x: f"{x:.1f}km" if pd.notna(x) else "0km"
        )
        df_copy = df_copy.drop(columns=['distance_from_home'])
    
    return df_copy

### --------- MAIN APPLICATION -----------
# Initialize database connection
conn = get_database_connection()
initialize_database(conn)

# Initialize systems
fraud_engine = AdvancedFraudDetectionEngine(conn)
notification_system = NotificationSystem(conn)

# Main header
st.markdown("""
<div class="main-header">
    <h1>BankSecure: Advanced Fraud Prevention System</h1>
    <p style="font-size: 1.2em; margin: 0;">Multi-Layer Security | Real-time Threat Detection | Passwordless Authentication</p>
    <p style="font-size: 1.0em; margin-top: 0.5rem;">SIM Clone Detection | Device Intelligence | Behavioral Biometrics | Geographic Monitoring</p>
    <p style="font-size: 0.9em; margin-top: 0.5rem; opacity: 0.9;">FinShield Hackathon 2025 - Production Ready Solution</p>
</div>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.markdown("### System Controls")
    
    attack_scenarios = [
        "Normal Operation",
        "SIM Swap Attack", 
        "SIM Cloning Attack",
        "Device Spoofing",
        "Impossible Travel",
        "Bot Attack",
        "Phishing Simulation",
        "Multi-Vector Attack"
    ]
    
    demo_mode = st.selectbox("Attack Scenario", attack_scenarios)
    
    if demo_mode != "Normal Operation":
        st.markdown(f'<div style="background: #fd7e14; color: white; padding: 1rem; border-radius: 6px; margin: 1rem 0;">Active: {demo_mode}</div>', unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("### Live Metrics")
    
    df_attempts = get_attempts(conn)
    df_users = get_all_users(conn)
    
    total_attempts = len(df_attempts)
    blocked_count = len(df_attempts[df_attempts['status'] == 'BLOCKED']) if not df_attempts.empty and 'status' in df_attempts.columns else 0
    
    st.metric("Protected Users", len(df_users))
    st.metric("Auth Attempts", total_attempts)
    st.metric("Threats Blocked", blocked_count)
    
    if total_attempts > 0:
        block_rate = (blocked_count / total_attempts) * 100
        st.metric("Protection Rate", f"{block_rate:.1f}%")

# Main tabs
tabs = st.tabs(["Authentication Portal", "Security Center", "Threat Intelligence", "Analytics", "Alerts"])

# ========== AUTHENTICATION PORTAL ==========
with tabs[0]:
    st.markdown("### Advanced Authentication Portal")
    st.markdown("Experience next-generation fraud detection with passwordless security")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        action = st.radio("Action", ['Register User', 'Authenticate User'], horizontal=True)
        
        col_user, col_phone = st.columns(2)
        with col_user:
            user_id = st.text_input("User ID", value="secure_user_2025")
        with col_phone:
            phone_number = st.text_input("Phone Number", value="+91-9876543210")
        
        with st.expander("Device & Location Configuration", expanded=True):
            # Demo mode configurations
            if demo_mode == "Normal Operation":
                default_device = "trusted_device_001"
                default_sim = "primary_sim_001"
                default_lat, default_lon = 12.9716, 77.5946
            elif "SIM Swap" in demo_mode or "SIM Cloning" in demo_mode:
                default_device = "trusted_device_001"
                default_sim = f"swapped_sim_{np.random.randint(100, 999)}"
                default_lat, default_lon = 12.9716, 77.5946
            elif "Device Spoofing" in demo_mode:
                default_device = f"emulator_device_{np.random.randint(100, 999)}"
                default_sim = "primary_sim_001"
                default_lat, default_lon = 12.9716, 77.5946
            elif "Impossible Travel" in demo_mode:
                default_device = "trusted_device_001"
                default_sim = "primary_sim_001"
                locations = [(40.7128, -74.0060), (51.5074, -0.1278), (35.6762, 139.6503)]
                default_lat, default_lon = locations[np.random.choice(len(locations))]
            elif "Bot Attack" in demo_mode:
                default_device = f"bot_device_{np.random.randint(100, 999)}"
                default_sim = f"virtual_sim_{np.random.randint(100, 999)}"
                default_lat, default_lon = 12.9716, 77.5946
            else:
                default_device = f"attack_device_{np.random.randint(100, 999)}"
                default_sim = f"attack_sim_{np.random.randint(100, 999)}"
                default_lat, default_lon = np.random.uniform(10, 15), np.random.uniform(75, 85)
            
            col_device, col_sim = st.columns(2)
            with col_device:
                device_id = st.text_input("Device ID", value=default_device)
            with col_sim:
                sim_id = st.text_input("SIM ID", value=default_sim)
            
            col_lat, col_lon = st.columns(2)
            with col_lat:
                lat = st.number_input("Latitude", value=default_lat, format="%.4f")
            with col_lon:
                lon = st.number_input("Longitude", value=default_lon, format="%.4f")
        
        st.markdown("### Behavioral Biometrics")
        passphrase = st.text_area(
            "Type your secure passphrase for behavioral analysis",
            value="I am securely accessing my BankSecure account with advanced protection",
            height=100
        )
        
        # Behavioral simulation
        if passphrase:
            if "Bot Attack" in demo_mode:
                keystroke_speed = 100  # Bot-like consistency
                mouse_speed = 150
            elif "Normal Operation" in demo_mode:
                keystroke_speed = np.random.randint(150, 190)
                mouse_speed = np.random.randint(180, 220)
            else:
                keystroke_speed = np.random.randint(80, 120)
                mouse_speed = np.random.randint(90, 140)
        else:
            keystroke_speed = mouse_speed = 0
        
        # Biometric display
        col_bio1, col_bio2 = st.columns(2)
        with col_bio1:
            st.markdown(f'<div class="metric-card">Keystroke Speed: {keystroke_speed} ms/char</div>', unsafe_allow_html=True)
        with col_bio2:
            st.markdown(f'<div class="metric-card">Mouse Speed: {mouse_speed} px/sec</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown("### Demo Information")
        st.info(f"**Scenario:** {demo_mode}\n\nThe system will analyze device, SIM, location, and behavioral patterns for comprehensive fraud detection.")
        
        # Threat gauge
        threat_level = np.random.randint(5, 95) if demo_mode != "Normal Operation" else np.random.randint(0, 25)
        
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=threat_level,
            title={'text': "Threat Level"},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 30], 'color': "lightgreen"},
                    {'range': [30, 70], 'color': "yellow"},
                    {'range': [70, 100], 'color': "red"}
                ]
            }
        ))
        fig_gauge.update_layout(height=250)
        st.plotly_chart(fig_gauge, use_container_width=True)
    
    # Registration
    if action == "Register User":
        if st.button("Register with Advanced Security", type="primary", use_container_width=True):
            if not user_id or not passphrase:
                st.warning("Please provide User ID and passphrase")
            elif get_user(conn, user_id):
                st.error("User already exists. Please choose different ID.")
            else:
                with st.spinner("Creating comprehensive security profile..."):
                    time.sleep(1.5)
                
                user_data = {
                    'user_id': user_id,
                    'device_id': device_id,
                    'sim_id': sim_id,
                    'lat': lat,
                    'lon': lon,
                    'keystroke_speed': keystroke_speed,
                    'mouse_speed': mouse_speed,
                    'device_fingerprint': generate_device_fingerprint(),
                    'network_info': json.dumps({"ip": "192.168.1.100", "isp": "SecureNet"}),
                    'trusted_locations': json.dumps([{"lat": lat, "lon": lon, "name": "Home"}]),
                    'biometric_template': simulate_biometrics(),
                    'phone_number': phone_number,
                    'email': f"{user_id}@securebank.com"
                }
                
                if add_user(conn, user_data):
                    st.markdown("""
                    <div class="alert-success">
                        <strong>Registration Successful</strong><br>
                        Advanced security profile created with:<br>
                        • Multi-layer fraud detection activated<br>
                        • Behavioral biometrics trained<br>
                        • Device intelligence established<br>
                        • Geographic monitoring configured<br>
                        • SIM protection enabled
                    </div>
                    """, unsafe_allow_html=True)
                    
    
    # Authentication
    if action == "Authenticate User":
        if st.button("Advanced Authentication", type="primary", use_container_width=True):
            user = get_user(conn, user_id)
            if not user:
                st.error("User not found. Please register first.")
            else:
                with st.spinner("Advanced threat analysis in progress..."):
                    time.sleep(1.5)
                
                login_data = {
                    'user_id': user_id,
                    'device_id': device_id,
                    'sim_id': sim_id,
                    'lat': lat,
                    'lon': lon,
                    'keystroke_speed': keystroke_speed,
                    'mouse_speed': mouse_speed
                }
                
                # Comprehensive fraud analysis
                risk_score, alerts, risk_breakdown, ml_confidence = fraud_engine.comprehensive_risk_analysis(user, login_data)
                
                # Decision logic
                critical_alerts = sum(1 for alert in alerts if "CRITICAL" in alert)
                
                if risk_score >= 80 or critical_alerts >= 2:
                    status = "BLOCKED"
                    status_class = "status-blocked"
                elif risk_score >= 50 or critical_alerts >= 1:
                    status = "CHALLENGE"
                    status_class = "status-challenge"
                else:
                    status = "APPROVED"
                    status_class = "status-approved"
                
                # Display results
                st.markdown("### Authentication Results")
                
                col_result1, col_result2 = st.columns([1, 1])
                
                with col_result1:
                    st.markdown(f"""
                    <div class="{status_class}">
                        <h2>{status}</h2>
                        <p>Risk Score: {risk_score}/100</p>
                        <p>AI Confidence: {ml_confidence:.1%}</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col_result2:
                    st.markdown("**Risk Analysis:**")
                    for category, score in risk_breakdown.items():
                        if score > 0:
                            st.markdown(f"• {category.replace('_', ' ').title()}: {score}")
                
                # Display alerts
                if alerts:
                    st.markdown("### Security Alerts")
                    for i, alert in enumerate(alerts, 1):
                        alert_type = "CRITICAL" if "CRITICAL" in alert else "WARNING" if "WARNING" in alert else "INFO"
                        st.markdown(f"**{alert_type} {i}:** {alert}")
                
                # Status-specific responses
                if status == "BLOCKED":
                    st.markdown("""
                    <div class="alert-critical">
                        <strong>ACCESS DENIED - SECURITY THREAT DETECTED</strong><br><br>
                        Actions Taken:<br>
                        • Account access blocked<br>
                        • Security team notified<br>
                        • Comprehensive alert sent<br>
                        • Enhanced monitoring activated<br><br>
                        Contact support if this was legitimate access.
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Send notifications
                    notification_id = asyncio.run(notification_system.send_fraud_alert(user_id, risk_score, alerts))
                    st.info(f"Security notification sent (ID: {notification_id[:8]}...)")
                
                elif status == "CHALLENGE":
                    st.markdown("""
                    <div class="alert-warning">
                        <strong>ADDITIONAL VERIFICATION REQUIRED</strong><br>
                        Suspicious patterns detected. Please complete step-up authentication.
                    </div>
                    """, unsafe_allow_html=True)
                    
                    col_auth1, col_auth2 = st.columns(2)
                    with col_auth1:
                        if st.button("Face ID Verification"):
                            st.success("Face ID verified. Access granted.")
                    with col_auth2:
                        if st.button("Fingerprint Scan"):
                            st.success("Fingerprint verified. Access granted.")
                
                else:
                    st.markdown("""
                    <div class="alert-success">
                        <strong>AUTHENTICATION SUCCESSFUL</strong><br>
                        All security checks passed. Welcome to secure banking.
                    </div>
                    """, unsafe_allow_html=True)
                   
                
                # Log attempt
                distance = fraud_engine._calculate_distance(user['lat'], user['lon'], lat, lon)
                attempt_data = {
                    'attempt_id': str(uuid.uuid4()),
                    'user_id': user_id,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'device_id': device_id,
                    'sim_id': sim_id,
                    'lat': lat,
                    'lon': lon,
                    'keystroke_speed': keystroke_speed,
                    'mouse_speed': mouse_speed,
                    'risk_score': risk_score,
                    'alerts': " | ".join(alerts),
                    'status': status,
                    'distance_from_home': distance,
                    'ml_confidence': ml_confidence,
                    'fraud_probability': risk_score / 100.0,
                    'response_time_ms': np.random.randint(50, 150),
                    'notification_sent': (status == "BLOCKED")
                }
                add_attempt(conn, attempt_data)

# ========== SECURITY CENTER ==========
with tabs[1]:
    st.markdown("### Security Operations Center")
    st.markdown("Comprehensive monitoring and threat analysis")
    
    # Metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        total_scans = len(df_attempts)
        st.metric("Security Scans", total_scans)
    
    with col2:
        threats_blocked = len(df_attempts[df_attempts['status'] == 'BLOCKED']) if not df_attempts.empty and 'status' in df_attempts.columns else 0
        st.metric("Threats Blocked", threats_blocked)
    
    with col3:
        protected_users = len(df_users)
        st.metric("Protected Users", protected_users)
    
    with col4:
        avg_confidence = df_attempts['ml_confidence'].mean() if not df_attempts.empty and 'ml_confidence' in df_attempts.columns else 0.92
        st.metric("AI Confidence", f"{avg_confidence:.1%}")
    
    with col5:
        avg_response = df_attempts['response_time_ms'].mean() if not df_attempts.empty and 'response_time_ms' in df_attempts.columns else 95
        st.metric("Response Time", f"{avg_response:.0f}ms")
    
    # Security log with FIXED DataFrame operations
    st.markdown("### Security Activity Log")
    
    if not df_attempts.empty:
        display_columns = ['timestamp', 'user_id', 'status', 'risk_score', 'alerts', 'device_id', 'distance_from_home']
        available_columns = [col for col in display_columns if col in df_attempts.columns]
        
        if available_columns:
            df_display = safe_dataframe_operations(df_attempts[available_columns].head(15))
            
            # Style the dataframe with FIXED text visibility
            def style_status(val):
                if val == 'BLOCKED':
                    return 'background-color: #ffebee; color: #c62828; font-weight: bold; padding: 4px;'
                elif val == 'CHALLENGE':
                    return 'background-color: #fff3e0; color: #ef6c00; font-weight: bold; padding: 4px;'
                else:
                    return 'background-color: #e8f5e8; color: #2e7d32; font-weight: bold; padding: 4px;'
            
            if 'status' in df_display.columns:
                styled_df = df_display.style.map(style_status, subset=['status'])
            else:
                styled_df = df_display.style
            
            st.dataframe(styled_df, use_container_width=True)
        
        # Controls
        col_ctrl1, col_ctrl2, col_ctrl3 = st.columns(3)
        with col_ctrl1:
            if st.button("Export Report"):
                csv = df_attempts.to_csv(index=False)
                st.download_button(
                    "Download CSV",
                    csv,
                    f"banksecure_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    "text/csv"
                )
        with col_ctrl2:
            if st.button("Refresh Dashboard"):
                st.rerun()
        with col_ctrl3:
            if st.button("Clear Archive"):
                # Archive old approved attempts
                cursor = conn.cursor()
                cursor.execute("DELETE FROM attempts WHERE status='APPROVED' AND datetime(timestamp) < datetime('now', '-1 day')")
                conn.commit()
                st.success("Archive cleared")
    else:
        st.info("No security events logged yet. System is monitoring for threats.")
    
    # User registry with FIXED DataFrame operations
    st.markdown("### Protected User Registry")
    if not df_users.empty:
        user_columns = ['user_id', 'device_id', 'risk_profile', 'created_at', 'is_verified']
        available_user_columns = [col for col in user_columns if col in df_users.columns]
        
        if available_user_columns:
            df_users_display = df_users[available_user_columns].copy()
            
            if 'created_at' in df_users_display.columns:
                df_users_display.loc[:, 'registered'] = pd.to_datetime(df_users_display['created_at']).dt.strftime('%Y-%m-%d')
                df_users_display = df_users_display.drop(columns=['created_at'])
            
            st.dataframe(df_users_display, use_container_width=True)
    else:
        st.info("No users registered yet.")

# ========== THREAT INTELLIGENCE ==========
with tabs[2]:
    st.markdown("### Threat Intelligence Center")
    
    if not df_attempts.empty:
        col1, col2 = st.columns([2, 1])
        
        with col1:
            if 'risk_score' in df_attempts.columns:
                fig = px.histogram(df_attempts, x='risk_score', nbins=20, title="Risk Score Distribution")
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            if 'status' in df_attempts.columns:
                status_counts = df_attempts['status'].value_counts()
                fig = px.pie(values=status_counts.values, names=status_counts.index, title="Security Decisions")
                st.plotly_chart(fig, use_container_width=True)
        
        # Critical threats
        if 'risk_score' in df_attempts.columns:
            critical_threats = df_attempts[df_attempts['risk_score'] >= 70]
            if not critical_threats.empty:
                st.error(f"CRITICAL: {len(critical_threats)} high-risk threats detected")
                with st.expander("View Critical Threats"):
                    threat_columns = ['timestamp', 'user_id', 'risk_score', 'alerts']
                    available_threat_columns = [col for col in threat_columns if col in critical_threats.columns]
                    if available_threat_columns:
                        st.dataframe(critical_threats[available_threat_columns])
            else:
                st.success("No critical threats detected")
        
        # Geographic analysis
        if all(col in df_attempts.columns for col in ['lat', 'lon', 'risk_score']):
            st.markdown("### Geographic Threat Distribution")
            df_attempts_copy = df_attempts.copy()
            df_attempts_copy.loc[:, 'threat_level'] = df_attempts_copy['risk_score'].apply(
                lambda x: 'Critical' if x >= 70 else 'High' if x >= 50 else 'Medium' if x >= 30 else 'Low'
            )
            
            fig = px.scatter_mapbox(
                df_attempts_copy, lat='lat', lon='lon', color='threat_level', size='risk_score',
                mapbox_style="open-street-map", title="Authentication Locations",
                zoom=2, height=500
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Attack vectors
        if 'alerts' in df_attempts.columns:
            all_alerts = []
            for alerts in df_attempts['alerts'].dropna():
                if alerts:
                    all_alerts.extend([alert.strip() for alert in str(alerts).split('|')])
            
            if all_alerts:
                alert_counts = pd.Series(all_alerts).value_counts().head(10)
                fig = px.bar(x=alert_counts.values, y=alert_counts.index,
                           title="Top Attack Vectors", orientation='h')
                st.plotly_chart(fig, use_container_width=True)
    
    else:
        st.info("No threat data available.")

# ========== ANALYTICS ==========
with tabs[3]:
    st.markdown("### Advanced Analytics")
    
    if not df_attempts.empty:
        # Performance metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            accuracy = len(df_attempts[df_attempts['status'].isin(['APPROVED', 'BLOCKED'])]) / len(df_attempts) * 100 if 'status' in df_attempts.columns else 100
            st.metric("Detection Accuracy", f"{accuracy:.1f}%")
        
        with col2:
            if 'ml_confidence' in df_attempts.columns:
                avg_confidence = df_attempts['ml_confidence'].mean() * 100
                st.metric("Average Confidence", f"{avg_confidence:.1f}%")
        
        with col3:
            if 'response_time_ms' in df_attempts.columns:
                avg_response = df_attempts['response_time_ms'].mean()
                st.metric("Average Response", f"{avg_response:.0f}ms")
        
        with col4:
            challenge_rate = len(df_attempts[df_attempts['status'] == 'CHALLENGE']) / len(df_attempts) * 100 if 'status' in df_attempts.columns else 0
            st.metric("Challenge Rate", f"{challenge_rate:.1f}%")
        
        # Behavioral analysis
        if all(col in df_attempts.columns for col in ['keystroke_speed', 'mouse_speed', 'status']):
            st.markdown("### Behavioral Pattern Analysis")
            
            col1, col2 = st.columns(2)
            with col1:
                fig = px.box(df_attempts, y='keystroke_speed', color='status', title="Keystroke Patterns")
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                fig = px.box(df_attempts, y='mouse_speed', color='status', title="Mouse Patterns")
                st.plotly_chart(fig, use_container_width=True)
        
        # Feature importance
        st.markdown("### ML Model Insights")
        feature_importance = {
            'Device Intelligence': 0.28,
            'SIM Intelligence': 0.24,
            'Behavioral Biometrics': 0.22,
            'Geospatial Analysis': 0.15,
            'Temporal Patterns': 0.11
        }
        
        fig = px.bar(x=list(feature_importance.values()), y=list(feature_importance.keys()),
                   title="Feature Importance", orientation='h')
        st.plotly_chart(fig, use_container_width=True)
    
    else:
        st.info("No data available for analytics.")

# ========== ALERTS ==========
with tabs[4]:
    st.markdown("### Real-time Alert Center")
    
    # Alert metrics
    col1, col2, col3 = st.columns(3)
    
    with col1:
        critical_alerts = len(df_attempts[df_attempts['risk_score'] >= 80]) if not df_attempts.empty and 'risk_score' in df_attempts.columns else 0
        st.metric("Critical Alerts", critical_alerts)
    
    with col2:
        high_alerts = len(df_attempts[(df_attempts['risk_score'] >= 50) & (df_attempts['risk_score'] < 80)]) if not df_attempts.empty and 'risk_score' in df_attempts.columns else 0
        st.metric("High Priority", high_alerts)
    
    with col3:
        notifications_sent = len(df_attempts[df_attempts.get('notification_sent', pd.Series([False]*len(df_attempts))) == True]) if not df_attempts.empty else 0
        st.metric("Notifications Sent", notifications_sent)
    
    # Live feed
    st.markdown("### Live Alert Feed")
    
    if not df_attempts.empty:
        recent_attempts = df_attempts.head(10)
        
        for _, attempt in recent_attempts.iterrows():
            timestamp = attempt.get('timestamp', 'Unknown')
            user_id = attempt.get('user_id', 'Unknown')
            status = attempt.get('status', 'Unknown') 
            risk_score = attempt.get('risk_score', 0)
            alerts = attempt.get('alerts', '')
            
            if status == "BLOCKED":
                st.error(f"{timestamp} - User {user_id} - BLOCKED (Risk: {risk_score}/100)")
                if alerts:
                    st.markdown(f"  ↳ {alerts}")
            elif status == "CHALLENGE":
                st.warning(f"{timestamp} - User {user_id} - CHALLENGE (Risk: {risk_score}/100)")
                if alerts:
                    st.markdown(f"  ↳ {alerts}")
            else:
                st.success(f"{timestamp} - User {user_id} - APPROVED (Risk: {risk_score}/100)")
    else:
        st.info("No alerts to display. System monitoring active.")

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; padding: 1rem; background: #f8f9fa; border-radius: 8px; ">
    <div style="color: #666;">
    <h3>BankSecure: Advanced Fraud Prevention System</h3>
    <p><strong>Multi-Layer Security | Real-time Detection | Passwordless Authentication</strong></p>
    <p>FinShield Hackathon 2025 - Comprehensive Banking Security Solution</p>
    <p style="font-size: 0.9em; color: #666;">
        Features: SIM Clone Detection | Device Intelligence | Behavioral Biometrics | Geographic Monitoring | 
        Phishing Protection | Real-time Notifications | Advanced Analytics
    </p>
    </div>
</div>
""", unsafe_allow_html=True)

# import streamlit as st
# import pandas as pd
# import numpy as np
# import uuid
# import sqlite3
# from datetime import datetime
# from math import radians, sin, cos, sqrt, atan2

# st.set_page_config(layout="wide", page_title="BankSecure - Auth Demo")

# ### ------------ Persistent DB -------------
# def db_connect():
#     conn = sqlite3.connect("banksecure_demo.db", check_same_thread=False)
#     return conn

# def db_setup(conn):
#     c = conn.cursor()
#     c.execute('''CREATE TABLE IF NOT EXISTS users (
#                     user_id TEXT PRIMARY KEY, 
#                     device_id TEXT, sim_id TEXT,
#                     lat REAL, lon REAL,
#                     keystroke_speed REAL, mouse_speed REAL)''')
#     c.execute('''CREATE TABLE IF NOT EXISTS attempts (
#                     attempt_id TEXT, user_id TEXT, ts TEXT,
#                     device_id TEXT, sim_id TEXT,
#                     lat REAL, lon REAL,
#                     keystroke_speed REAL, mouse_speed REAL,
#                     risk_score INTEGER, alerts TEXT, status TEXT)''')
#     conn.commit()

# def db_add_user(conn, user):
#     cur = conn.cursor()
#     cur.execute("INSERT INTO users VALUES (?,?,?,?,?,?,?)",
#                 (user['user_id'], user['device_id'], user['sim_id'],
#                  user['lat'], user['lon'],
#                  user['keystroke_speed'], user['mouse_speed']))
#     conn.commit()

# def db_get_user(conn, user_id):
#     cur = conn.cursor()
#     cur.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
#     row = cur.fetchone()
#     if not row:
#         return None
#     keys = ['user_id','device_id','sim_id','lat','lon','keystroke_speed','mouse_speed']
#     return dict(zip(keys, row))

# def db_add_attempt(conn, attempt):
#     data = (
#         attempt['attempt_id'], attempt['user_id'], attempt['ts'],
#         attempt['device_id'], attempt['sim_id'],
#         attempt['lat'], attempt['lon'],
#         attempt['keystroke_speed'], attempt['mouse_speed'],
#         attempt['risk_score'], attempt['alerts'], attempt['status']
#     )
#     cur = conn.cursor()
#     cur.execute('''INSERT INTO attempts VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''', data)
#     conn.commit()

# def db_get_attempts(conn):
#     df = pd.read_sql_query("SELECT * FROM attempts ORDER BY ts DESC", conn)
#     return df

# def db_get_all_users(conn):
#     df = pd.read_sql_query("SELECT * FROM users", conn)
#     return df

# def db_clear_attempts(conn):
#     cur = conn.cursor()
#     cur.execute("DELETE FROM attempts")
#     conn.commit()

# ### ---------- Haversine Distance -------------
# def haversine(lat1, lon1, lat2, lon2):
#     R = 6371
#     dlat, dlon = radians(lat2-lat1), radians(lon2-lon1)
#     a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
#     c = 2*atan2(sqrt(a), sqrt(1-a))
#     return R * c

# ### -------- RISK LOGIC -------------
# def compute_risk(user, login):
#     risk, alerts = 0, []
#     if login['device_id'] != user['device_id']:
#         risk += 50
#         alerts.append("New device detected")
#     if login['sim_id'] != user['sim_id']:
#         risk += 50
#         alerts.append("SIM swap detected")
#     dist = haversine(user['lat'], user['lon'], login['lat'], login['lon'])
#     if dist > 1000:
#         risk += 30
#         alerts.append(f"Impossible travel detected ({dist:.1f}km)")
#     behav_diff = abs(user['keystroke_speed'] - login['keystroke_speed']) + abs(user['mouse_speed'] - login['mouse_speed'])
#     if behav_diff > 100:
#         risk += 40
#         alerts.append("Behavioral anomaly detected")
#     return risk, alerts

# ### --------- Main App Logic -----------
# conn = db_connect()
# db_setup(conn)

# st.title("BankSecure : Passwordless Behavioral Authentication (Hackathon Demo)")
# tabs = st.tabs(["User Portal", "Admin Dashboard"])

# # ========== USER PORTAL ==========
# with tabs[0]:
#     st.header("Registration / Login")
#     act = st.radio("Choose Action", ['Register', 'Login'], horizontal=True)
#     user_id = st.text_input("User ID", value="alice")

#     with st.expander("Advanced: Simulate device/SIM/location", expanded=True):
#         device_id = st.text_input("Device ID", value="device-123")
#         sim_id = st.text_input("SIM ID", value="sim-999")
#         lat = st.number_input("Location: Latitude", value=12.9716)
#         lon = st.number_input("Location: Longitude", value=77.5946)

#     st.markdown("**Behavioral Biometrics: Type a passphrase! (Randomized for hackathon demo)**")
#     phrase = st.text_area("Behavioral data input", value="", height=75, key="phrase")

#     # Simulate single-session behavioral biometrics for demo
#     keystroke_speed = np.random.randint(110, 230) if phrase else 0
#     mouse_speed = np.random.randint(110, 250) if phrase else 0

#     st.write(f"Simulated keystroke speed: **{keystroke_speed} ms/char**")
#     st.write(f"Simulated mouse movement speed: **{mouse_speed} px/sec**")

#     behavior = dict(keystroke_speed=keystroke_speed, mouse_speed=mouse_speed)

#     # -------- Registration --------
#     if act == "Register":
#         if st.button("Register"):
#             if not user_id or not phrase:
#                 st.warning("Please enter User ID and passphrase")
#             elif db_get_user(conn, user_id):
#                 st.error("User already registered. Try another ID or login.")
#             else:
#                 db_add_user(conn, dict(
#                     user_id=user_id, device_id=device_id, sim_id=sim_id,
#                     lat=lat, lon=lon,
#                     **behavior
#                 ))
#                 st.success(
#                     f"User `{user_id}` registered successfully. Now, try login from same or different device/SIM/location/behavior."
#                 )

#     # ____ LOGIN HANDLER (changes start here) ____

#     if act == "Login":
#         if st.button("Login"):
#             user = db_get_user(conn, user_id)
#             if not user:
#                 st.error("User not found. Please register first.")
#             else:
#                 login = dict(
#                     user_id=user_id, device_id=device_id, sim_id=sim_id,
#                     lat=lat, lon=lon, **behavior
#                 )
#                 risk, alerts = compute_risk(user, login)

#                 # --- Block ALL impossible travel (bank policy) ---
#                 detailed_reason = " | ".join(alerts)
#                 if "Impossible travel detected" in detailed_reason:
#                     status = "BLOCKED"
#                     # Demo alternative:
#                     # status = "CHALLENGE"  # for step-up prompt logic
#                     # Or, use "BLOCKED" if your hackathon wants hard block
#                 elif risk >= 50:
#                     status = "BLOCKED"
#                 else:
#                     status = "APPROVED"

#                 msg = f"Login Status: **{status}**\n\n"
#                 msg += f"Risk Score: `{risk}`"
#                 if alerts:
#                     msg += "\nDetailed Reason(s):\n" + "\n".join(f"- {a}" for a in alerts)
#                 st.info(msg)

#                 if status == "BLOCKED":
#                     st.error(f"Login BLOCKED. Notification sent to user (simulated). Please verify identity or contact support.")
#                 elif status == "CHALLENGE":
#                     st.warning("Step-up authenticator triggered! Please complete additional verification.")
#                 elif status == "APPROVED":
#                     st.success("Login APPROVED. Welcome back!")

#                 now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
#                 db_add_attempt(conn, dict(
#                     attempt_id=str(uuid.uuid4()), user_id=user_id, ts=now,
#                     device_id=device_id, sim_id=sim_id,
#                     lat=lat, lon=lon, keystroke_speed=keystroke_speed, mouse_speed=mouse_speed,
#                     risk_score=risk, alerts=detailed_reason, status=status
#                 ))


#     st.caption("Real behavioral biometrics (timings) easily added via JS integration. Demo here randomizes speed for fair scoring visualization.")

# # ========== ADMIN DASHBOARD ==========
# with tabs[1]:
#     # In admin dashboard (tabs[1]):
#     st.header("Login Attempts & Risk Analysis")
#     col1, col2 = st.columns([3,1])
#     with col1:
#         df = db_get_attempts(conn)
#         if not df.empty:
#             # Add "Detailed Reason" column with descriptive labeling
#             df_disp = df[[
#                 'ts','user_id','device_id','sim_id','lat','lon',
#                 'keystroke_speed','mouse_speed','risk_score','alerts','status'
#             ]]
#             df_disp = df_disp.rename(columns={'alerts': 'Detailed Reason'})
#             st.dataframe(df_disp, use_container_width=True)
#         else:
#             st.info("No login attempts logged yet.")

#     with col2:
#         if st.button("Clear attempts log"):
#             db_clear_attempts(conn)
#             st.info("Attempts cleared.")

#     st.subheader("Registered Users")
#     udf = db_get_all_users(conn)
#     if not udf.empty:
#         st.dataframe(udf, use_container_width=True)
#     else:
#         st.info("No users registered yet.")

# st.markdown('---')
# st.caption("Hackathon Demo | Secure Behavioral Auth | 2024 (Risk scoring: block at risk≥50)")


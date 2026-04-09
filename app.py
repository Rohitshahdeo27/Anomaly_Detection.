from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
import io
import csv
import os
import pytz
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- EMAIL CONFIGURATION ---
EMAIL_SENDER = "rohitshahdeo3@gmail.com"    
EMAIL_PASSWORD = "bymx vouo mdci znej"
EMAIL_RECEIVER = "rohitshahde@gmail.com"

def get_ist():
    return datetime.now(pytz.timezone('Asia/Kolkata'))

def send_email_alert(anomaly_data):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = EMAIL_RECEIVER
        msg['Subject'] = "🚨 CRITICAL: Medical Network Anomaly Detected"

        body = f"""
        Warning: Medical Anomaly Detection System Alert.
        
        --- EVENT DETAILS ---
        Timestamp: {get_ist().strftime('%Y-%m-%d %H:%M:%S')}
        Source IP: {anomaly_data.get('ip.src')}
        Anomaly Reason: {anomaly_data.get('reason')}
        Anomaly Score: {anomaly_data.get('score')}
        
        Please check the Firewall and Live Dashboard.
        """
        msg.attach(MIMEText(body, 'plain'))
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        server.quit()
        print("✅ Email Alert Sent Successfully")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///medical_logs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# --- DATABASE MODELS ---
class TrafficLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=get_ist)
    frame_len = db.Column(db.Float)
    tcp_len = db.Column(db.Float)
    ip_source = db.Column(db.String(50))
    is_anomaly = db.Column(db.Boolean)
    anomaly_score = db.Column(db.Float)
    reason = db.Column(db.String(100)) # Added this column

class BlacklistedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)
    reason = db.Column(db.String(100))
    banned_at = db.Column(db.DateTime, default=get_ist)

with app.app_context():
    db.create_all()

# --- LOAD AI MODELS ---
model = joblib.load('iso_forest_model.pkl')
scaler = joblib.load('scaler.pkl')
features = ['frame.len', 'tcp.len', 'tcp.time_delta', 'tcp.window_size_value', 'mqtt.len', 'mqtt.msgtype', 'mqtt.qos', 'ip.ttl']

# --- PAGE ROUTING ---
@app.route('/')
def index():
    from sqlalchemy import func
    total_count = TrafficLog.query.count()
    anomaly_count = TrafficLog.query.filter_by(is_anomaly=True).count()
    threat_rate = round((anomaly_count / total_count) * 100, 2) if total_count > 0 else 0
    peak_val = db.session.query(func.max(TrafficLog.frame_len)).scalar() or 0
    
    # 1. Fetch data for the Chart
    recent_logs = TrafficLog.query.order_by(TrafficLog.timestamp.desc()).limit(20).all()
    recent_logs.reverse() 
    initial_labels = [log.timestamp.strftime("%H:%M:%S") for log in recent_logs]
    initial_data = [log.frame_len for log in recent_logs]

    # 2. NEW: Fetch the last 5 anomalies for the Alert List
    recent_anomalies = TrafficLog.query.filter_by(is_anomaly=True).order_by(TrafficLog.timestamp.desc()).limit(5).all()

    return render_template('index.html', 
                           active_page='dashboard',
                           total=total_count,
                           anomalies=anomaly_count,
                           rate=threat_rate,
                           peak=peak_val,
                           initial_labels=initial_labels,
                           initial_data=initial_data,
                           recent_anomalies=recent_anomalies)

@app.route('/history')
def history():
    all_logs = TrafficLog.query.order_by(TrafficLog.timestamp.desc()).all()
    return render_template('history.html', logs=all_logs, active_page='history')

@app.route('/firewall')
def firewall():
    blocked = BlacklistedIP.query.order_by(BlacklistedIP.banned_at.desc()).all()
    return render_template('firewall.html', blocked_ips=blocked, active_page='firewall')

@app.route('/settings')
def settings():
    log_count = TrafficLog.query.count()
    return render_template('settings.html', log_count=log_count, active_page='settings')

# --- API ENDPOINTS ---
@app.route('/api/vitals', methods=['POST'])
def process_vitals():
    data = request.json
    src_ip = data.get('ip.src', '192.168.1.1')

    # 1. Firewall Check (Immediate Exit if Banned)
    if BlacklistedIP.query.filter_by(ip_address=src_ip).first():
        return jsonify({"status": "blocked", "message": "IP Blacklisted"}), 403

    # 2. AI Prediction
    input_data = [data.get(f, 0) for f in features]
    input_df = pd.DataFrame([input_data], columns=features)
    scaled_input = scaler.transform(input_df)
    prediction = model.predict(scaled_input)[0]
    score = model.decision_function(scaled_input)[0] 
    is_anomaly = True if prediction == -1 else False
    
    # 3. Explainable AI Reason
    reason = "Normal Traffic"
    if is_anomaly:
        if data.get('frame.len', 0) > 1000: reason = "DoS Attack Pattern"
        elif data.get('mqtt.msgtype', 0) > 10: reason = "Protocol Violation"
        elif data.get('tcp.window_size_value', 0) == 0: reason = "Connection Hijack"
        else: reason = "Statistical Outlier"

        # 4. AUTO-BLOCK (Threshold adjusted to be more sensitive)
        # If score is less than 0.05, we consider it a blockable threat
        if score < 0.05: 
            if not BlacklistedIP.query.filter_by(ip_address=src_ip).first():
                new_ban = BlacklistedIP(ip_address=src_ip, reason=reason)
                db.session.add(new_ban)
                # We commit immediately so the Firewall page can see it
                db.session.commit() 
                send_email_alert({'ip.src': src_ip, 'reason': reason, 'score': round(score, 4)})

    # 5. Save and Emit
    new_log = TrafficLog(
        frame_len=float(data.get('frame.len', 0)),
        tcp_len=float(data.get('tcp.len', 0)),
        ip_source=src_ip,
        is_anomaly=is_anomaly,
        anomaly_score=float(score),
        reason=reason
    )
    db.session.add(new_log)
    db.session.commit()
    
    socketio.emit('update_dashboard', {
        'vitals': data, 'is_anomaly': is_anomaly, 'reason': reason,
        'score': round(score, 4), 'time': get_ist().strftime("%H:%M:%S")
    })
    return {"status": "success"}

@app.route('/api/unblock/<int:ip_id>', methods=['POST'])
def unblock_ip(ip_id):
    ip_to_remove = BlacklistedIP.query.get_or_404(ip_id)
    db.session.delete(ip_to_remove)
    db.session.commit()
    return jsonify({"status": "success"})

@app.route('/api/clear', methods=['POST'])
def clear_logs():
    db.session.query(TrafficLog).delete()
    db.session.commit()
    return jsonify({"status": "success"})

@app.route('/api/export')
def export_logs():
    logs = TrafficLog.query.all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Source IP', 'Frame Len', 'Anomaly', 'Score', 'Reason'])
    for log in logs:
        writer.writerow([log.timestamp, log.ip_source, log.frame_len, log.is_anomaly, log.anomaly_score, log.reason])
    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8'))
    mem.seek(0)
    return send_file(mem, mimetype='text/csv', as_attachment=True, download_name='security_report.csv')

if __name__ == '__main__':
    socketio.run(app, debug=True)
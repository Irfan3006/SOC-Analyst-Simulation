import os
import random
import time
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from dotenv import load_dotenv

class SOCSimulator:
    def __init__(self):
        self._threat_types = [
            "Brute Force", "DDoS Attack", "Malware Activity", "SQL Injection", 
            "Cross-Site Scripting (XSS)", "Phishing Attempt", "Ransomware Distribution",
            "Unauthorized Login", "Data Exfiltration", "Port Scanning",
            "Man-in-the-Middle (MITM)", "Zero-Day Exploit", "DNS Poisoning",
            "Botnet Command & Control", "Privilege Escalation",
            "Advanced Persistent Threat (APT)", "Supply Chain Compromise", 
            "AI-Driven Phishing", "Ransomware-as-a-Service (RaaS)", 
            "Zero-Day Remote Code Execution", "Business Email Compromise (BEC)",
            "Cloud Storage Exfiltration", "MFA Fatigue Attack",
            "API Broken Object Authorization", "Kerberoasting (Active Directory)",
            "Golden Ticket Forge", "Living off the Land (LotL)",
            "DNS Tunneling Exfiltration", "In-Memory Malware Injection",
            "Credential Stuffing Attack", "Lateral Movement (SMB Relay)",
            "Data Exfiltration via Webhooks", "Kubernetes Namespace Escape",
            "Docker Container Breakout", "UAC Bypass Escalation"
        ]
        
        self._ips = self._generate_ips(100)
        
        self._targets = [
            "SSH Server (Port 22)", "Web Server (Port 443)", "Database Server (Port 3306)", 
            "Mail Server (Port 587)", "Active Directory", "Internal ERP System",
            "Customer Database", "Cloud Storage Gateway", "HR Information System",
            "AWS S3 Bucket (Production Data)", "Azure AD (Authentication)", 
            "Kubernetes Control Plane", "Jenkins CI/CD Pipeline",
            "Employee Laptop (Remote/VPN)", "IoT Terminal Gateway"
        ]

    def _generate_ips(self, count):
        ips = []
        ips.extend(["8.8.8.8", "1.1.1.1", "192.168.1.1", "10.0.0.1"])
        
        while len(ips) < count:
            if random.random() < 0.3:
                prefix = random.choice(["192.168", "10", "172.16"])
                if prefix == "192.168":
                    ips.append(f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}")
                elif prefix == "10":
                    ips.append(f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}")
                else:
                    ips.append(f"172.16.{random.randint(0, 31)}.{random.randint(1, 254)}")
            else:
                ips.append(f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}")
        
        return list(set(ips))

    def evaluate_log_severity(self, source_ip):
        is_false_positive = False
        confidence_score = random.randint(10, 99)
        
        if source_ip.startswith(("192.168.", "10.", "172.")):
            if random.random() < 0.7:
                is_false_positive = True
                confidence_score = random.randint(10, 45)
        
        if not is_false_positive:
            confidence_score = random.randint(30, 99)
            
        severity = "Low"
        if confidence_score > 90:
            severity = "Critical"
        elif confidence_score > 75:
            severity = "High"
        elif confidence_score > 50:
            severity = "Medium"
            
        return is_false_positive, confidence_score, severity

    def generate_telemetry_log(self):
        threat_type = random.choice(self._threat_types)
        source_ip = random.choice(self._ips)
        target = random.choice(self._targets)
        
        is_fp, conf_score, severity = self.evaluate_log_severity(source_ip)
        
        return {
            "id": int(time.time() * 1000) + random.randint(1, 1000),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": threat_type,
            "source": source_ip,
            "target": target,
            "confidence_score": conf_score,
            "severity": severity,
            "is_false_positive": is_fp
        }

class SOCDashboardApp:
    def __init__(self):
        self.app = Flask(__name__)
        load_dotenv()
        self.simulator = SOCSimulator()
        self._register_routes()

    @staticmethod
    def generate_standard_report(log_data):
        return f"""
# System Security Incident Report
*(Automatically Generated via SIEM Engine)*

### Incident Metadata
- **Incident ID**: #{log_data['id']}
- **Detection Time**: {log_data['timestamp']}
- **Severity Level**: {log_data['severity']}

### Threat Information
- **Attack Type**: {log_data['type']}
- **Target System**: {log_data['target']}

### Network Details
- **Source IP (Attacker)**: `{log_data['source']}`

### Security Evaluation
- **Identification Status**: {'False Positive' if log_data['is_false_positive'] else 'True Positive'}
- **Confidence Score**: {log_data['confidence_score']}%

***
**Technical Summary:** Immediately initiate firewall blocking for the source IP and monitor anomalous activity on the target system.
        """

    def _register_routes(self):
        self.app.add_url_rule('/', 'index', self.render_index)
        self.app.add_url_rule('/api/generate_log', 'api_generate_log', self.api_generate_log, methods=['POST'])
        self.app.add_url_rule('/api/generate_ondemand_report', 'api_generate_ondemand_report', self.api_generate_ondemand_report, methods=['POST'])

    def render_index(self):
        return render_template('index.html')

    def api_generate_log(self):
        log = self.simulator.generate_telemetry_log()
        return jsonify({"status": "success", "log": log})

    def api_generate_ondemand_report(self):
        data = request.json
        log_data = data.get("log_data")
        report_type = data.get("type", "standard")
        manual_content = data.get("manual_content")
        
        if not log_data:
            return jsonify({"status": "error", "message": "Log data not provided"}), 400

        if report_type == "manual" and manual_content:
            report_text = manual_content
        else:
            report_text = self.generate_standard_report(log_data)
            
        return jsonify({
            "status": "success", 
            "report": {
                "id": log_data["id"],
                "content": report_text
            }
        })

    def run(self, port=5000):
        debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
        self.app.run(debug=debug_mode, port=port)

dashboard = SOCDashboardApp()
app = dashboard.app

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    dashboard.run(port=port)

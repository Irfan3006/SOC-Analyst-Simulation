import os
import random
import time
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from dotenv import load_dotenv

class SOCDataStore:
    def __init__(self, max_logs=50, max_reports=20):
        self._max_logs = max_logs
        self._max_reports = max_reports
        self._log_history = []
        self._auto_reports = []
        self._stats = {
            "total_logs": 0,
            "threats_detected": 0,
            "false_positives": 0,
            "reports_generated": 0,
            "manual_reports": 0
        }

    def add_log(self, log):
        self._log_history.insert(0, log)
        if len(self._log_history) > self._max_logs:
            self._log_history.pop()

        self._stats["total_logs"] += 1
        if log["is_false_positive"]:
            self._stats["false_positives"] += 1
        else:
            self._stats["threats_detected"] += 1

    def get_log_by_id(self, log_id):
        return next((log for log in self._log_history if log["id"] == log_id), None)

    def add_report(self, report):
        self._auto_reports.insert(0, report)
        if report.get("is_manual"):
            self._stats["manual_reports"] += 1
        else:
            self._stats["reports_generated"] += 1
            
        if len(self._auto_reports) > self._max_reports:
            self._auto_reports.pop()

    @property
    def logs(self):
        return self._log_history
    
    @property
    def reports(self):
        return self._auto_reports
    
    @property
    def stats(self):
        return self._stats


class SOCSimulator:
    def __init__(self):
        self._threat_types = [
            "Brute Force", "DDoS Attack", "Malware Activity", "SQL Injection", 
            "Cross-Site Scripting (XSS)", "Phishing Attempt", "Ransomware Distribution",
            "Unauthorized Login", "Data Exfiltration", "Port Scanning",
            "Man-in-the-Middle (MITM)", "Zero-Day Exploit", "DNS Poisoning",
            "Botnet Command & Control", "Privilege Escalation"
        ]
        
        self._ips = self._generate_ips(100)
        
        self._targets = [
            "SSH Server (Port 22)", "Web Server (Port 443)", "Database Server (Port 3306)", 
            "Mail Server (Port 587)", "Active Directory", "Internal ERP System",
            "Customer Database", "Cloud Storage Gateway", "HR Information System"
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
            confidence_score = random.randint(65, 99)
            
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
        self.store = SOCDataStore()
        self.simulator = SOCSimulator()
        self._register_routes()

    @staticmethod
    def generate_standard_report(log_data):
        return f"""
# Laporan Insiden Keamanan Sistem
*(Di-generate secara Otomatis via SIEM Engine)*

### Metadata Insiden
- **Nomor ID Insiden**: #{log_data['id']}
- **Waktu Terdeteksi**: {log_data['timestamp']}
- **Tingkat Keparahan (Severity)**: {log_data['severity']}

### Informasi Ancaman
- **Tipe Serangan**: {log_data['type']}
- **Target System**: {log_data['target']}

### Detail Jaringan
- **IP Sumber (Attacker)**: `{log_data['source']}`

### Evaluasi Keamanan
- **Status Identifikasi**: {'False Positive' if log_data['is_false_positive'] else 'True Positive'}
- **Confidence Score**: {log_data['confidence_score']}%

***
**Kesimpulan Standar:** Segera lakukan pemblokiran IP source pada firewall dan pantau aktivitas tidak wajar pada sistem target.
        """

    def _register_routes(self):
        self.app.add_url_rule('/', 'index', self.render_index)
        self.app.add_url_rule('/api/generate_log', 'api_generate_log', self.api_generate_log, methods=['POST'])
        self.app.add_url_rule('/api/generate_ondemand_report', 'api_generate_ondemand_report', self.api_generate_ondemand_report, methods=['POST'])
        self.app.add_url_rule('/api/logs', 'api_get_logs', self.api_get_logs)
        self.app.add_url_rule('/api/reports', 'api_get_reports', self.api_get_reports)
        self.app.add_url_rule('/api/stats', 'api_get_stats', self.api_get_stats)

    def render_index(self):
        return render_template('index.html')

    def api_generate_log(self):
        log = self.simulator.generate_telemetry_log()
        self.store.add_log(log)
        return jsonify({"status": "success", "log": log, "stats": self.store.stats})

    def api_generate_ondemand_report(self):
        data = request.json
        log_id = data.get("log_id")
        report_type = data.get("type", "standard")
        manual_content = data.get("manual_content")
        
        log_data = self.store.get_log_by_id(log_id)
        if not log_data:
            return jsonify({"status": "error", "message": "Log not found"}), 404

        if report_type == "manual" and manual_content:
            report_text = manual_content
            is_manual = True
        else:
            report_text = self.generate_standard_report(log_data)
            is_manual = False
            
        report_obj = {
            "id": log_data["id"],
            "timestamp": log_data["timestamp"],
            "threat_type": log_data["type"],
            "severity": log_data["severity"],
            "content": report_text,
            "is_manual": is_manual
        }
        
        self.store.add_report(report_obj)
        return jsonify({"status": "success", "report": report_obj, "stats": self.store.stats})

    def api_get_logs(self):
        return jsonify(self.store.logs)

    def api_get_reports(self):
        return jsonify(self.store.reports)

    def api_get_stats(self):
        return jsonify(self.store.stats)

    def run(self, port=5000):
        debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
        self.app.run(debug=debug_mode, port=port)

dashboard = SOCDashboardApp()
app = dashboard.app

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    dashboard.run(port=port)

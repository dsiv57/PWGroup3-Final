from datetime import datetime, timedelta
from sqlalchemy import func
from . import db
from .log import Log

class SecurityAnalyzer:
    """Analizza i log per rilevare attività sospette"""
    
    @staticmethod
    def detect_brute_force(minutes=5, threshold=5):
        """
        Rileva tentativi di brute force
        
        Args:
            minutes: Finestra temporale in minuti (default: 5)
            threshold: Numero minimo di tentativi falliti (default: 5)
        
        Returns:
            Lista di alert con IP sospetti
        """
        time_threshold = datetime.now() - timedelta(minutes=minutes)
        
        results = db.session.query(
            Log.ip,
            func.count(Log.id).label('attempts'),
            func.max(Log.timestamp).label('last_attempt')
        ).filter(
            Log.type == 'LOGIN_FAILED',
            Log.timestamp >= time_threshold
        ).group_by(Log.ip).all()
        
        alerts = []
        for ip, attempts, last_attempt in results:
            if attempts >= threshold:
                alerts.append({
                    'type': 'BRUTE_FORCE',
                    'severity': 'CRITICAL',
                    'ip': ip,
                    'attempts': attempts,
                    'last_attempt': last_attempt,
                    'time_window': f'{minutes} minuti',
                    'message': f'🚨 {attempts} tentativi di login falliti da {ip}'
                })
        
        return alerts
    
    @staticmethod
    def detect_suspicious_ips(hours=24, threshold=10):
        """
        Rileva IP con attività sospetta (troppi errori)
        
        Args:
            hours: Finestra temporale in ore (default: 24)
            threshold: Numero minimo di errori (default: 10)
        
        Returns:
            Lista di IP sospetti
        """
        time_threshold = datetime.now() - timedelta(hours=hours)
        
        results = db.session.query(
            Log.ip,
            func.count(Log.id).label('error_count')
        ).filter(
            Log.is_error == True,
            Log.timestamp >= time_threshold
        ).group_by(Log.ip).all()
        
        suspicious = []
        for ip, error_count in results:
            if error_count >= threshold:
                suspicious.append({
                    'type': 'SUSPICIOUS_IP',
                    'severity': 'WARNING',
                    'ip': ip,
                    'error_count': error_count,
                    'time_window': f'{hours} ore',
                    'message': f'⚠️ {error_count} errori da {ip} nelle ultime {hours} ore'
                })
        
        return suspicious
    
    @staticmethod
    def get_all_alerts():
        """
        Ottiene tutti gli alert combinati
        
        Returns:
            Dizionario con tutti i tipi di alert
        """
        return {
            'brute_force': SecurityAnalyzer.detect_brute_force(),
            'suspicious_ips': SecurityAnalyzer.detect_suspicious_ips(),
            'malicious_inputs': SecurityAnalyzer.detect_malicious_inputs(),
            'total_alerts': len(SecurityAnalyzer.detect_brute_force()) + 
                          len(SecurityAnalyzer.detect_suspicious_ips()) +
                          len(SecurityAnalyzer.detect_malicious_inputs())
        }
    
    @staticmethod
    def detect_malicious_inputs(hours=24):
        """
        Rileva tentativi di input malevoli (SQL Injection, XSS, ecc.)
        
        Args:
            hours: Finestra temporale in ore (default: 24)
        
        Returns:
            Dizionario con statistiche per tipo di attacco
        """
        time_threshold = datetime.now() - timedelta(hours=hours)
        
        attack_types = ['SQL_INJECTION', 'XSS', 'COMMAND_INJECTION', 'PATH_TRAVERSAL']
        
        results = {
            'sql_injection': {'count': 0, 'ips': [], 'recent': []},
            'xss': {'count': 0, 'ips': [], 'recent': []},
            'command_injection': {'count': 0, 'ips': [], 'recent': []},
            'path_traversal': {'count': 0, 'ips': [], 'recent': []}
        }
        
        for attack_type in attack_types:
            log_type = f'MALICIOUS_INPUT_{attack_type}'
            
            logs = Log.query.filter(
                Log.type == log_type,
                Log.timestamp >= time_threshold
            ).all()
            
            ip_counts = {}
            for log in logs:
                if log.ip not in ip_counts:
                    ip_counts[log.ip] = 0
                ip_counts[log.ip] += 1
            
            key = attack_type.lower()
            results[key]['count'] = len(logs)
            results[key]['ips'] = [
                {'ip': ip, 'attempts': count} 
                for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
            ][:5]
            results[key]['recent'] = logs[:10]
        
        return results
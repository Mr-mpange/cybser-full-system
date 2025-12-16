"""
Alert Service for IntelliGuard
Handles threat alerts and notifications
"""

import smtplib
import requests
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Any, Optional
from datetime import datetime

from ..models.data_models import AlertConfig, PredictionResult, SeverityLevel
from ..core.config import settings
from ..utils.logger import get_logger

logger = get_logger(__name__)


class AlertService:
    """Service for handling threat alerts and notifications"""
    
    def __init__(self):
        self.alert_config = AlertConfig()
        self.alert_history = []
    
    def update_config(self, config: AlertConfig):
        """Update alert configuration"""
        self.alert_config = config
        logger.info("Alert configuration updated")
    
    async def send_threat_alerts(self, threats: List[PredictionResult]):
        """
        Send alerts for detected threats
        """
        try:
            if not threats:
                return
            
            # Filter threats by severity threshold
            filtered_threats = [
                threat for threat in threats
                if self._should_alert(threat)
            ]
            
            if not filtered_threats:
                return
            
            logger.info(f"Sending alerts for {len(filtered_threats)} threats")
            
            # Send email alerts
            if self.alert_config.email_enabled and self.alert_config.email_recipients:
                await self._send_email_alerts(filtered_threats)
            
            # Send Telegram alerts
            if self.alert_config.telegram_enabled:
                await self._send_telegram_alerts(filtered_threats)
            
            # Send webhook alerts
            if self.alert_config.webhook_enabled and self.alert_config.webhook_url:
                await self._send_webhook_alerts(filtered_threats)
            
            # Store in alert history
            alert_record = {
                'timestamp': datetime.utcnow(),
                'threats': [threat.dict() for threat in filtered_threats],
                'alert_methods': self._get_enabled_methods()
            }
            self.alert_history.append(alert_record)
            
        except Exception as e:
            logger.error(f"Error sending threat alerts: {str(e)}")
    
    def _should_alert(self, threat: PredictionResult) -> bool:
        """Check if threat meets alert criteria"""
        severity_levels = {
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4
        }
        
        threat_level = severity_levels.get(threat.severity_level, 1)
        threshold_level = severity_levels.get(self.alert_config.severity_threshold, 2)
        
        return threat_level >= threshold_level
    
    async def _send_email_alerts(self, threats: List[PredictionResult]):
        """Send email alerts"""
        try:
            if not settings.SMTP_HOST or not settings.SMTP_USER:
                logger.warning("SMTP not configured, skipping email alerts")
                return
            
            # Create email content
            subject = f"🚨 IntelliGuard Alert: {len(threats)} Threat(s) Detected"
            body = self._create_email_body(threats)
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = settings.SMTP_USER
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'html'))
            
            # Send to all recipients
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                server.starttls()
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                
                for recipient in self.alert_config.email_recipients:
                    msg['To'] = recipient
                    server.send_message(msg)
                    del msg['To']
            
            logger.info(f"Email alerts sent to {len(self.alert_config.email_recipients)} recipients")
            
        except Exception as e:
            logger.error(f"Error sending email alerts: {str(e)}")
    
    async def _send_telegram_alerts(self, threats: List[PredictionResult]):
        """Send Telegram alerts"""
        try:
            if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
                logger.warning("Telegram not configured, skipping Telegram alerts")
                return
            
            message = self._create_telegram_message(threats)
            
            url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
            payload = {
                'chat_id': settings.TELEGRAM_CHAT_ID,
                'text': message,
                'parse_mode': 'HTML'
            }
            
            async with requests.Session() as session:
                response = session.post(url, json=payload)
                response.raise_for_status()
            
            logger.info("Telegram alert sent successfully")
            
        except Exception as e:
            logger.error(f"Error sending Telegram alert: {str(e)}")
    
    async def _send_webhook_alerts(self, threats: List[PredictionResult]):
        """Send webhook alerts"""
        try:
            payload = {
                'timestamp': datetime.utcnow().isoformat(),
                'alert_type': 'threat_detection',
                'threats': [threat.dict() for threat in threats],
                'system': 'IntelliGuard',
                'version': settings.APP_VERSION
            }
            
            async with requests.Session() as session:
                response = session.post(
                    self.alert_config.webhook_url,
                    json=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )
                response.raise_for_status()
            
            logger.info("Webhook alert sent successfully")
            
        except Exception as e:
            logger.error(f"Error sending webhook alert: {str(e)}")
    
    def _create_email_body(self, threats: List[PredictionResult]) -> str:
        """Create HTML email body"""
        severity_colors = {
            SeverityLevel.LOW: '#28a745',
            SeverityLevel.MEDIUM: '#ffc107',
            SeverityLevel.HIGH: '#fd7e14',
            SeverityLevel.CRITICAL: '#dc3545'
        }
        
        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; margin: 20px;">
            <h2 style="color: #dc3545;">🚨 IntelliGuard Security Alert</h2>
            <p><strong>Detected {len(threats)} threat(s) at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</strong></p>
            
            <table style="border-collapse: collapse; width: 100%; margin-top: 20px;">
                <tr style="background-color: #f8f9fa;">
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">Attack Type</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">Severity</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">Confidence</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">Zero-Day</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">Timestamp</th>
                </tr>
        """
        
        for threat in threats:
            color = severity_colors.get(threat.severity_level, '#6c757d')
            html += f"""
                <tr>
                    <td style="border: 1px solid #dee2e6; padding: 8px;">{threat.attack_type.value}</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; color: {color}; font-weight: bold;">
                        {threat.severity_level.value}
                    </td>
                    <td style="border: 1px solid #dee2e6; padding: 8px;">{threat.confidence_score:.2%}</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px;">
                        {'🔴 Yes' if threat.is_zero_day else '🟢 No'}
                    </td>
                    <td style="border: 1px solid #dee2e6; padding: 8px;">
                        {threat.timestamp.strftime('%H:%M:%S')}
                    </td>
                </tr>
            """
        
        html += """
            </table>
            
            <div style="margin-top: 20px; padding: 15px; background-color: #e9ecef; border-radius: 5px;">
                <h4>Recommended Actions:</h4>
                <ul>
                    <li>Review network traffic logs</li>
                    <li>Check firewall rules and access controls</li>
                    <li>Monitor system resources and performance</li>
                    <li>Consider blocking suspicious IP addresses</li>
                    <li>Update security policies if necessary</li>
                </ul>
            </div>
            
            <p style="margin-top: 20px; color: #6c757d; font-size: 12px;">
                This alert was generated by IntelliGuard Cyber Attack Detection System.<br>
                For support, please contact your security team.
            </p>
        </body>
        </html>
        """
        
        return html
    
    def _create_telegram_message(self, threats: List[PredictionResult]) -> str:
        """Create Telegram message"""
        message = f"🚨 <b>IntelliGuard Alert</b>\n\n"
        message += f"<b>Detected {len(threats)} threat(s)</b>\n"
        message += f"<b>Time:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n"
        
        for i, threat in enumerate(threats[:5], 1):  # Limit to 5 threats
            severity_emoji = {
                SeverityLevel.LOW: '🟡',
                SeverityLevel.MEDIUM: '🟠',
                SeverityLevel.HIGH: '🔴',
                SeverityLevel.CRITICAL: '🚨'
            }.get(threat.severity_level, '⚪')
            
            message += f"<b>{i}. {threat.attack_type.value}</b>\n"
            message += f"   {severity_emoji} Severity: {threat.severity_level.value}\n"
            message += f"   📊 Confidence: {threat.confidence_score:.1%}\n"
            if threat.is_zero_day:
                message += f"   🔴 Zero-Day Detected!\n"
            message += "\n"
        
        if len(threats) > 5:
            message += f"... and {len(threats) - 5} more threats\n\n"
        
        message += "🔍 Check your IntelliGuard dashboard for details."
        
        return message
    
    def _get_enabled_methods(self) -> List[str]:
        """Get list of enabled alert methods"""
        methods = []
        if self.alert_config.email_enabled:
            methods.append('email')
        if self.alert_config.telegram_enabled:
            methods.append('telegram')
        if self.alert_config.webhook_enabled:
            methods.append('webhook')
        return methods
    
    def get_alert_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alert history"""
        return self.alert_history[-limit:]
"""
Enterprise Alert Service for IntelliGuard
Multi-channel alerting with escalation and notification management
"""

import asyncio
import smtplib
import json
import aiohttp
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from ..core.config import settings
from ..utils.logger import get_logger

logger = get_logger(__name__)


class AlertChannel(Enum):
    EMAIL = "email"
    TELEGRAM = "telegram"
    WEBHOOK = "webhook"
    SMS = "sms"
    SLACK = "slack"


class AlertSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AlertConfig:
    """Alert configuration for different severity levels"""
    channels: List[AlertChannel]
    recipients: List[str]
    escalation_time: int = 1800  # 30 minutes
    retry_count: int = 3
    retry_delay: int = 300  # 5 minutes


class EnterpriseAlertService:
    """Enterprise-grade alert service with multiple channels and escalation"""
    
    def __init__(self):
        self.alert_configs = {
            AlertSeverity.LOW: AlertConfig(
                channels=[AlertChannel.EMAIL],
                recipients=["admin@company.com"],
                escalation_time=3600
            ),
            AlertSeverity.MEDIUM: AlertConfig(
                channels=[AlertChannel.EMAIL, AlertChannel.TELEGRAM],
                recipients=["admin@company.com", "security@company.com"],
                escalation_time=1800
            ),
            AlertSeverity.HIGH: AlertConfig(
                channels=[AlertChannel.EMAIL, AlertChannel.TELEGRAM, AlertChannel.WEBHOOK],
                recipients=["admin@company.com", "security@company.com", "manager@company.com"],
                escalation_time=900
            ),
            AlertSeverity.CRITICAL: AlertConfig(
                channels=[AlertChannel.EMAIL, AlertChannel.TELEGRAM, AlertChannel.WEBHOOK, AlertChannel.SLACK],
                recipients=["admin@company.com", "security@company.com", "manager@company.com", "ciso@company.com"],
                escalation_time=300
            )
        }
        
        self.active_alerts = {}
        self.alert_history = []
        self.notification_templates = self._load_templates()
        
    async def initialize(self):
        """Initialize alert service"""
        logger.info("🚨 Initializing Enterprise Alert Service")
        
        # Test connections
        await self._test_email_connection()
        await self._test_telegram_connection()
        
        logger.info("✅ Alert service initialized successfully")
    
    async def send_alert(self, alert: Dict[str, Any]) -> bool:
        """Send alert through configured channels"""
        try:
            severity = AlertSeverity(alert.get('severity', 'medium'))
            config = self.alert_configs[severity]
            
            # Create alert record
            alert_record = {
                'id': f"alert_{int(datetime.utcnow().timestamp())}",
                'timestamp': datetime.utcnow(),
                'severity': severity.value,
                'name': alert['name'],
                'message': alert['message'],
                'channels': [ch.value for ch in config.channels],
                'recipients': config.recipients,
                'status': 'sending',
                'retry_count': 0
            }
            
            self.active_alerts[alert_record['id']] = alert_record
            
            # Send through all configured channels
            success_count = 0
            for channel in config.channels:
                try:
                    if await self._send_to_channel(channel, alert_record, config):
                        success_count += 1
                except Exception as e:
                    logger.error(f"Failed to send alert via {channel.value}: {str(e)}")
            
            # Update status
            if success_count > 0:
                alert_record['status'] = 'sent'
                logger.info(f"Alert sent successfully via {success_count}/{len(config.channels)} channels")
            else:
                alert_record['status'] = 'failed'
                logger.error("Alert failed to send via all channels")
            
            # Store in history
            self.alert_history.append(alert_record)
            
            # Schedule escalation if critical
            if severity == AlertSeverity.CRITICAL:
                asyncio.create_task(self._schedule_escalation(alert_record))
            
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Error sending alert: {str(e)}")
            return False
    
    async def _send_to_channel(self, channel: AlertChannel, alert: Dict[str, Any], config: AlertConfig) -> bool:
        """Send alert to specific channel"""
        try:
            if channel == AlertChannel.EMAIL:
                return await self._send_email(alert, config.recipients)
            elif channel == AlertChannel.TELEGRAM:
                return await self._send_telegram(alert)
            elif channel == AlertChannel.WEBHOOK:
                return await self._send_webhook(alert)
            elif channel == AlertChannel.SLACK:
                return await self._send_slack(alert)
            else:
                logger.warning(f"Unsupported alert channel: {channel}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending to {channel.value}: {str(e)}")
            return False
    
    async def _send_email(self, alert: Dict[str, Any], recipients: List[str]) -> bool:
        """Send email alert"""
        if not all([settings.SMTP_HOST, settings.SMTP_USER, settings.SMTP_PASSWORD]):
            logger.warning("Email configuration incomplete")
            return False
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[IntelliGuard {alert['severity'].upper()}] {alert['name']}"
            msg['From'] = settings.SMTP_USER
            msg['To'] = ', '.join(recipients)
            
            # HTML content
            html_content = self.notification_templates['email_html'].format(
                severity=alert['severity'].upper(),
                name=alert['name'],
                message=alert['message'],
                timestamp=alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC'),
                alert_id=alert['id']
            )
            
            # Text content
            text_content = self.notification_templates['email_text'].format(
                severity=alert['severity'].upper(),
                name=alert['name'],
                message=alert['message'],
                timestamp=alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC'),
                alert_id=alert['id']
            )
            
            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))
            
            # Send email
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                server.starttls()
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.send_message(msg)
            
            logger.info(f"Email alert sent to {len(recipients)} recipients")
            return True
            
        except Exception as e:
            logger.error(f"Email sending failed: {str(e)}")
            return False
    
    async def _send_telegram(self, alert: Dict[str, Any]) -> bool:
        """Send Telegram alert"""
        if not all([settings.TELEGRAM_BOT_TOKEN, settings.TELEGRAM_CHAT_ID]):
            logger.warning("Telegram configuration incomplete")
            return False
        
        try:
            # Format message
            message = self.notification_templates['telegram'].format(
                severity=alert['severity'].upper(),
                name=alert['name'],
                message=alert['message'],
                timestamp=alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC'),
                alert_id=alert['id']
            )
            
            # Send via Telegram API
            url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
            payload = {
                'chat_id': settings.TELEGRAM_CHAT_ID,
                'text': message,
                'parse_mode': 'HTML'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        logger.info("Telegram alert sent successfully")
                        return True
                    else:
                        logger.error(f"Telegram API error: {response.status}")
                        return False
                        
        except Exception as e:
            logger.error(f"Telegram sending failed: {str(e)}")
            return False
    
    async def _send_webhook(self, alert: Dict[str, Any]) -> bool:
        """Send webhook alert"""
        webhook_url = getattr(settings, 'WEBHOOK_URL', None)
        if not webhook_url:
            logger.warning("Webhook URL not configured")
            return False
        
        try:
            payload = {
                'alert_id': alert['id'],
                'timestamp': alert['timestamp'].isoformat(),
                'severity': alert['severity'],
                'name': alert['name'],
                'message': alert['message'],
                'source': 'IntelliGuard Enterprise'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload, timeout=10) as response:
                    if response.status < 400:
                        logger.info("Webhook alert sent successfully")
                        return True
                    else:
                        logger.error(f"Webhook error: {response.status}")
                        return False
                        
        except Exception as e:
            logger.error(f"Webhook sending failed: {str(e)}")
            return False
    
    async def _send_slack(self, alert: Dict[str, Any]) -> bool:
        """Send Slack alert"""
        slack_webhook = getattr(settings, 'SLACK_WEBHOOK_URL', None)
        if not slack_webhook:
            logger.warning("Slack webhook URL not configured")
            return False
        
        try:
            # Slack color coding
            color_map = {
                'low': '#36a64f',      # Green
                'medium': '#ff9500',   # Orange
                'high': '#ff0000',     # Red
                'critical': '#8B0000'  # Dark Red
            }
            
            payload = {
                'attachments': [{
                    'color': color_map.get(alert['severity'], '#ff0000'),
                    'title': f"IntelliGuard Alert: {alert['name']}",
                    'text': alert['message'],
                    'fields': [
                        {'title': 'Severity', 'value': alert['severity'].upper(), 'short': True},
                        {'title': 'Time', 'value': alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC'), 'short': True},
                        {'title': 'Alert ID', 'value': alert['id'], 'short': True}
                    ],
                    'footer': 'IntelliGuard Enterprise',
                    'ts': int(alert['timestamp'].timestamp())
                }]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(slack_webhook, json=payload, timeout=10) as response:
                    if response.status == 200:
                        logger.info("Slack alert sent successfully")
                        return True
                    else:
                        logger.error(f"Slack webhook error: {response.status}")
                        return False
                        
        except Exception as e:
            logger.error(f"Slack sending failed: {str(e)}")
            return False
    
    async def _schedule_escalation(self, alert: Dict[str, Any]):
        """Schedule alert escalation for critical alerts"""
        escalation_time = self.alert_configs[AlertSeverity.CRITICAL].escalation_time
        
        await asyncio.sleep(escalation_time)
        
        # Check if alert is still active
        if alert['id'] in self.active_alerts:
            escalation_alert = {
                'name': f"ESCALATION: {alert['name']}",
                'severity': 'critical',
                'message': f"Critical alert has not been acknowledged: {alert['message']}",
                'timestamp': datetime.utcnow()
            }
            
            await self.send_alert(escalation_alert)
    
    async def _test_email_connection(self):
        """Test email configuration"""
        if not all([settings.SMTP_HOST, settings.SMTP_USER, settings.SMTP_PASSWORD]):
            logger.warning("Email configuration incomplete - email alerts disabled")
            return False
        
        try:
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                server.starttls()
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            logger.info("✅ Email connection test successful")
            return True
        except Exception as e:
            logger.error(f"Email connection test failed: {str(e)}")
            return False
    
    async def _test_telegram_connection(self):
        """Test Telegram configuration"""
        if not settings.TELEGRAM_BOT_TOKEN:
            logger.warning("Telegram configuration incomplete - Telegram alerts disabled")
            return False
        
        try:
            url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/getMe"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as response:
                    if response.status == 200:
                        logger.info("✅ Telegram connection test successful")
                        return True
                    else:
                        logger.error(f"Telegram connection test failed: {response.status}")
                        return False
        except Exception as e:
            logger.error(f"Telegram connection test failed: {str(e)}")
            return False
    
    def _load_templates(self) -> Dict[str, str]:
        """Load notification templates"""
        return {
            'email_html': '''
            <html>
            <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5;">
                <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                    <div style="background-color: #dc3545; color: white; padding: 20px; text-align: center;">
                        <h1 style="margin: 0; font-size: 24px;">🚨 IntelliGuard Alert</h1>
                        <p style="margin: 5px 0 0 0; font-size: 16px;">Severity: {severity}</p>
                    </div>
                    <div style="padding: 30px;">
                        <h2 style="color: #33viceseAlertSer EnterpriService =ertnstance
Alservice ilert Global a
# 
rvice")
rt Se down Aleuttinginfo("🛑 Sher.       logg"""
 ert servicehutdown al"S        ""(self):
wndoync def shut
    as    }
    
    else 100cent_alerts f res) * 100 int_alertrece']) / len(sentatus'] == 'ts if a['st_aler recentinn([a for a ate': leuccess_r      'snts,
      ty_cou severibution':erity_distri        'sev,
    _alerts)activeself.rts': len(tive_ale'ac            alerts),
ly_eklen(we': s_7dtotal_alert       '   lerts),
  _arecents_24h': len(_alertotal          'teturn {
        r   
  ])
     erity.valueev sy'] ==f a['severitalerts irecent_a for a in  = len([rity.value]severity_counts[seve  
          Severity:erty in Alor severit        funts = {}
 severity_co           
   t_7d]
 > las'] estamp'timif a[rt_history lf.aler a in sefoerts = [a    weekly_al24h]
     st_mp'] > laestaimy if a['t_histor self.alert in ats = [a forcent_aler        re    
7)
    days=medelta(ow - tiast_7d = n)
        lta(hours=24medel tiow -t_24h = n  lasw()
      me.utcnow = dateti       no
 stics"""statit alert Ge      """]:
  , Anytr-> Dict[stics(self) alert_statisc def get_   asyn    
 }

         '''           ise</i>
rd EnterprntelliGua<i>I       
                ert_id}
 > {al:</b    <b>ID    mp}
    ta> {times</bime:   <b>T  
       > {message}essage:</b   <b>M}
         t:</b> {name     <b>Aler}
       b> {severityrity:</b>Seve      <   
              
  Alert</b>rdIntelliGua<b>     🚨    '''
     telegram':        '
                 ''',
    
        Platform.se Securityd EnterpriarGuIntelliated by rt was gener  This ale      
              rt_id}
  : {ale Alert ID
           {timestamp}me:          Ti  message}
  {essage:   M         {name}
 t:        Aler     
         everity}
   - {sGUARD ALERT INTELLI  🚨          '''
: t''email_tex                
 ',
              ''l>
     /htm  <       body>
      </   
      v>/di           <
          </div>          /p>
      <                       form.
ity Platrise Securnterpuard EliGy Intelenerated b alert was g       This                  ;">
   n-bottom: 0rgima 14px; e:iz; font-s#666e="color:     <p styl                      </div>
                 p>
     ert_id}</al {/strong>rt ID:<><strong>Ale66;"color: #6x 0 0 0; n: 5pgiar style="m      <p               
       p}</p>> {timestamime:</strong"><strong>T #666;r:ologin: 0; cle="mar      <p sty                   ;">
   rgin: 20px 0s: 5px; mar-radiu5px; borde; padding: 19faf8fnd-color: #"backgrouv style=       <di        
         message}</p>: 1.5;">{ightine-he: 16px; lsize666; font-"color: # style=     <p              
     h2>me}</0;">{nap: 3; margin-to
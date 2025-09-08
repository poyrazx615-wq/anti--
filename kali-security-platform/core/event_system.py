# Event-Driven Architecture for Reactive System
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import asyncio
import json
from collections import defaultdict
import uuid

class EventType(Enum):
    """System event types"""
    # Scan events
    SCAN_STARTED = "scan.started"
    SCAN_PROGRESS = "scan.progress"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_CANCELLED = "scan.cancelled"
    
    # Vulnerability events
    VULN_DISCOVERED = "vulnerability.discovered"
    VULN_CONFIRMED = "vulnerability.confirmed"
    VULN_EXPLOITED = "vulnerability.exploited"
    
    # System events
    SYSTEM_START = "system.start"
    SYSTEM_STOP = "system.stop"
    SYSTEM_ERROR = "system.error"
    SYSTEM_WARNING = "system.warning"
    
    # User events
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    USER_ACTION = "user.action"
    
    # Tool events
    TOOL_STARTED = "tool.started"
    TOOL_COMPLETED = "tool.completed"
    TOOL_ERROR = "tool.error"
    
    # Workflow events
    WORKFLOW_STARTED = "workflow.started"
    WORKFLOW_STEP_COMPLETED = "workflow.step.completed"
    WORKFLOW_COMPLETED = "workflow.completed"
    WORKFLOW_FAILED = "workflow.failed"
    
    # Alert events
    ALERT_CRITICAL = "alert.critical"
    ALERT_HIGH = "alert.high"
    ALERT_MEDIUM = "alert.medium"
    ALERT_LOW = "alert.low"

@dataclass
class Event:
    """System event"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: EventType = EventType.SYSTEM_START
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source: str = "system"
    data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[str] = None
    user_id: Optional[str] = None
    severity: str = "info"

class EventBus:
    """Central event bus for pub/sub communication"""
    
    def __init__(self):
        self.subscribers: Dict[EventType, List[Callable]] = defaultdict(list)
        self.async_subscribers: Dict[EventType, List[Callable]] = defaultdict(list)
        self.event_history: List[Event] = []
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self.running = False
    
    def subscribe(self, event_type: EventType, handler: Callable, async_handler: bool = False):
        """Subscribe to an event type"""
        if async_handler:
            self.async_subscribers[event_type].append(handler)
        else:
            self.subscribers[event_type].append(handler)
    
    def unsubscribe(self, event_type: EventType, handler: Callable):
        """Unsubscribe from an event type"""
        if handler in self.subscribers[event_type]:
            self.subscribers[event_type].remove(handler)
        if handler in self.async_subscribers[event_type]:
            self.async_subscribers[event_type].remove(handler)
    
    async def emit(self, event: Event):
        """Emit an event to all subscribers"""
        # Add to history
        self.event_history.append(event)
        
        # Limit history size
        if len(self.event_history) > 10000:
            self.event_history = self.event_history[-5000:]
        
        # Queue for async processing
        await self.event_queue.put(event)
        
        # Notify sync subscribers immediately
        for handler in self.subscribers[event.type]:
            try:
                handler(event)
            except Exception as e:
                print(f"Event handler error: {e}")
    
    async def process_events(self):
        """Process events from queue"""
        self.running = True
        
        while self.running:
            try:
                # Get event from queue with timeout
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                
                # Process async subscribers
                tasks = []
                for handler in self.async_subscribers[event.type]:
                    tasks.append(handler(event))
                
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                    
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                print(f"Event processing error: {e}")
    
    def stop(self):
        """Stop event processing"""
        self.running = False
    
    def get_event_history(self, event_type: EventType = None, limit: int = 100) -> List[Event]:
        """Get event history"""
        if event_type:
            filtered = [e for e in self.event_history if e.type == event_type]
        else:
            filtered = self.event_history
        
        return filtered[-limit:]

class EventHandlers:
    """Common event handlers"""
    
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self.register_handlers()
    
    def register_handlers(self):
        """Register default event handlers"""
        
        # Scan events
        self.event_bus.subscribe(EventType.SCAN_STARTED, self.on_scan_started)
        self.event_bus.subscribe(EventType.SCAN_COMPLETED, self.on_scan_completed)
        self.event_bus.subscribe(EventType.SCAN_FAILED, self.on_scan_failed)
        
        # Vulnerability events
        self.event_bus.subscribe(EventType.VULN_DISCOVERED, self.on_vulnerability_discovered)
        self.event_bus.subscribe(EventType.VULN_EXPLOITED, self.on_vulnerability_exploited)
        
        # Alert events
        self.event_bus.subscribe(EventType.ALERT_CRITICAL, self.on_critical_alert)
        self.event_bus.subscribe(EventType.ALERT_HIGH, self.on_high_alert)
        
        # System events
        self.event_bus.subscribe(EventType.SYSTEM_ERROR, self.on_system_error)
    
    def on_scan_started(self, event: Event):
        """Handle scan started event"""
        scan_id = event.data.get("scan_id")
        target = event.data.get("target")
        print(f"[SCAN] Started scan {scan_id} on target {target}")
        
        # Log to database
        self._log_event(event)
        
        # Send notification
        self._send_notification(f"Scan started: {target}", "info")
    
    def on_scan_completed(self, event: Event):
        """Handle scan completed event"""
        scan_id = event.data.get("scan_id")
        results = event.data.get("results", {})
        
        print(f"[SCAN] Completed scan {scan_id}")
        
        # Process results
        if results.get("vulnerabilities"):
            # Emit vulnerability events
            for vuln in results["vulnerabilities"]:
                vuln_event = Event(
                    type=EventType.VULN_DISCOVERED,
                    source=f"scan_{scan_id}",
                    data=vuln,
                    correlation_id=scan_id
                )
                asyncio.create_task(self.event_bus.emit(vuln_event))
        
        # Generate report
        self._generate_scan_report(scan_id, results)
    
    def on_scan_failed(self, event: Event):
        """Handle scan failed event"""
        scan_id = event.data.get("scan_id")
        error = event.data.get("error")
        
        print(f"[SCAN] Failed scan {scan_id}: {error}")
        
        # Alert administrators
        alert_event = Event(
            type=EventType.ALERT_MEDIUM,
            source="scan_manager",
            data={
                "title": f"Scan {scan_id} failed",
                "message": error,
                "scan_id": scan_id
            }
        )
        asyncio.create_task(self.event_bus.emit(alert_event))
    
    def on_vulnerability_discovered(self, event: Event):
        """Handle vulnerability discovered event"""
        vuln = event.data
        severity = vuln.get("severity", "unknown")
        
        print(f"[VULN] Discovered {severity} vulnerability: {vuln.get('type')}")
        
        # Auto-trigger exploit if critical
        if severity == "critical":
            # Check if auto-exploit is enabled
            if self._is_auto_exploit_enabled():
                exploit_event = Event(
                    type=EventType.TOOL_STARTED,
                    source="auto_exploit",
                    data={
                        "tool": "metasploit",
                        "vulnerability": vuln,
                        "auto": True
                    },
                    correlation_id=event.correlation_id
                )
                asyncio.create_task(self.event_bus.emit(exploit_event))
        
        # Send alert based on severity
        alert_type = {
            "critical": EventType.ALERT_CRITICAL,
            "high": EventType.ALERT_HIGH,
            "medium": EventType.ALERT_MEDIUM,
            "low": EventType.ALERT_LOW
        }.get(severity, EventType.ALERT_LOW)
        
        alert_event = Event(
            type=alert_type,
            source="vulnerability_scanner",
            data={
                "title": f"{severity.upper()} vulnerability discovered",
                "vulnerability": vuln
            },
            correlation_id=event.correlation_id
        )
        asyncio.create_task(self.event_bus.emit(alert_event))
    
    def on_vulnerability_exploited(self, event: Event):
        """Handle vulnerability exploited event"""
        exploit_data = event.data
        success = exploit_data.get("success", False)
        
        if success:
            print(f"[EXPLOIT] Successfully exploited vulnerability")
            
            # Generate detailed report
            self._generate_exploit_report(exploit_data)
            
            # Alert high priority
            alert_event = Event(
                type=EventType.ALERT_CRITICAL,
                source="exploit_handler",
                data={
                    "title": "Vulnerability successfully exploited",
                    "details": exploit_data
                }
            )
            asyncio.create_task(self.event_bus.emit(alert_event))
    
    def on_critical_alert(self, event: Event):
        """Handle critical alert"""
        alert_data = event.data
        
        print(f"[CRITICAL] {alert_data.get('title')}")
        
        # Send immediate notifications
        self._send_immediate_notification(alert_data)
        
        # Log to security incident database
        self._log_security_incident(alert_data)
        
        # Trigger automated response if configured
        self._trigger_automated_response(alert_data)
    
    def on_high_alert(self, event: Event):
        """Handle high priority alert"""
        alert_data = event.data
        
        print(f"[HIGH] {alert_data.get('title')}")
        
        # Send notifications
        self._send_notification(alert_data.get('title'), "high")
        
        # Log to database
        self._log_alert(alert_data)
    
    def on_system_error(self, event: Event):
        """Handle system error"""
        error_data = event.data
        
        print(f"[ERROR] System error: {error_data.get('message')}")
        
        # Log error
        self._log_error(error_data)
        
        # Check if critical system component
        if error_data.get("critical"):
            # Trigger system recovery
            self._trigger_system_recovery(error_data)
    
    def _log_event(self, event: Event):
        """Log event to database"""
        # Implement database logging
        pass
    
    def _send_notification(self, message: str, priority: str):
        """Send notification"""
        # Implement notification system
        pass
    
    def _send_immediate_notification(self, alert_data: Dict):
        """Send immediate high-priority notification"""
        # Implement urgent notification (SMS, phone call, etc.)
        pass
    
    def _generate_scan_report(self, scan_id: str, results: Dict):
        """Generate scan report"""
        # Implement report generation
        pass
    
    def _generate_exploit_report(self, exploit_data: Dict):
        """Generate exploit report"""
        # Implement exploit report generation
        pass
    
    def _log_security_incident(self, incident_data: Dict):
        """Log security incident"""
        # Implement security incident logging
        pass
    
    def _log_alert(self, alert_data: Dict):
        """Log alert"""
        # Implement alert logging
        pass
    
    def _log_error(self, error_data: Dict):
        """Log error"""
        # Implement error logging
        pass
    
    def _trigger_automated_response(self, alert_data: Dict):
        """Trigger automated response to critical alert"""
        # Implement automated response (isolate system, block IP, etc.)
        pass
    
    def _trigger_system_recovery(self, error_data: Dict):
        """Trigger system recovery procedures"""
        # Implement system recovery
        pass
    
    def _is_auto_exploit_enabled(self) -> bool:
        """Check if auto-exploitation is enabled"""
        # Check configuration
        return False  # Default to disabled for safety

# Global event bus instance
event_bus = EventBus()
event_handlers = EventHandlers(event_bus)

# Helper function to emit events
async def emit_event(event_type: EventType, data: Dict = None, **kwargs):
    """Helper function to emit events"""
    event = Event(
        type=event_type,
        data=data or {},
        **kwargs
    )
    await event_bus.emit(event)

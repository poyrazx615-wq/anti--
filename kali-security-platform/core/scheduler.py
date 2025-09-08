# Advanced Scheduling System for Automated Security Testing
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from croniter import croniter
import asyncio
import uuid
from enum import Enum
import pytz

class ScheduleType(Enum):
    """Schedule types"""
    ONCE = "once"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CRON = "cron"
    INTERVAL = "interval"

class ScheduleStatus(Enum):
    """Schedule status"""
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class ScheduledTask:
    """Scheduled task definition"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    task_type: str = "scan"  # scan, workflow, report, maintenance
    schedule_type: ScheduleType = ScheduleType.ONCE
    schedule_expression: str = ""  # Cron expression or interval
    target: Dict[str, Any] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)
    timezone: str = "UTC"
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    max_runs: Optional[int] = None
    run_count: int = 0
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    status: ScheduleStatus = ScheduleStatus.ACTIVE
    created_at: datetime = field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    notifications: Dict[str, Any] = field(default_factory=dict)
    retry_policy: Dict[str, Any] = field(default_factory=dict)
    execution_history: List[Dict] = field(default_factory=list)

class Scheduler:
    """Advanced task scheduler with cron support"""
    
    def __init__(self):
        self.tasks: Dict[str, ScheduledTask] = {}
        self.running_tasks: Dict[str, asyncio.Task] = {}
        self.scheduler_running = False
        self.check_interval = 60  # Check every minute
        self._load_persisted_tasks()
    
    def _load_persisted_tasks(self):
        """Load persisted scheduled tasks from database"""
        # TODO: Implement database loading
        pass
    
    def create_schedule(
        self,
        name: str,
        task_type: str,
        schedule_type: ScheduleType,
        target: Dict,
        config: Dict = None,
        **kwargs
    ) -> str:
        """Create a new scheduled task"""
        
        task = ScheduledTask(
            name=name,
            task_type=task_type,
            schedule_type=schedule_type,
            target=target,
            config=config or {},
            **kwargs
        )
        
        # Calculate next run time
        task.next_run = self._calculate_next_run(task)
        
        # Save task
        self.tasks[task.id] = task
        self._persist_task(task)
        
        return task.id
    
    def create_cron_schedule(
        self,
        name: str,
        cron_expression: str,
        task_type: str,
        target: Dict,
        **kwargs
    ) -> str:
        """Create a cron-based schedule"""
        
        # Validate cron expression
        if not self._validate_cron_expression(cron_expression):
            raise ValueError(f"Invalid cron expression: {cron_expression}")
        
        return self.create_schedule(
            name=name,
            task_type=task_type,
            schedule_type=ScheduleType.CRON,
            schedule_expression=cron_expression,
            target=target,
            **kwargs
        )
    
    def create_interval_schedule(
        self,
        name: str,
        interval_seconds: int,
        task_type: str,
        target: Dict,
        **kwargs
    ) -> str:
        """Create an interval-based schedule"""
        
        return self.create_schedule(
            name=name,
            task_type=task_type,
            schedule_type=ScheduleType.INTERVAL,
            schedule_expression=str(interval_seconds),
            target=target,
            **kwargs
        )
    
    async def start(self):
        """Start the scheduler"""
        self.scheduler_running = True
        
        while self.scheduler_running:
            try:
                # Check all tasks
                await self._check_scheduled_tasks()
                
                # Wait before next check
                await asyncio.sleep(self.check_interval)
                
            except Exception as e:
                print(f"Scheduler error: {e}")
                await asyncio.sleep(5)
    
    def stop(self):
        """Stop the scheduler"""
        self.scheduler_running = False
        
        # Cancel all running tasks
        for task_id, async_task in self.running_tasks.items():
            async_task.cancel()
    
    async def _check_scheduled_tasks(self):
        """Check and execute due tasks"""
        
        current_time = datetime.utcnow()
        
        for task_id, task in self.tasks.items():
            # Skip if not active
            if task.status != ScheduleStatus.ACTIVE:
                continue
            
            # Check if task is due
            if task.next_run and task.next_run <= current_time:
                # Check max runs
                if task.max_runs and task.run_count >= task.max_runs:
                    task.status = ScheduleStatus.COMPLETED
                    continue
                
                # Check end date
                if task.end_date and current_time > task.end_date:
                    task.status = ScheduleStatus.COMPLETED
                    continue
                
                # Execute task
                asyncio.create_task(self._execute_task(task))
    
    async def _execute_task(self, task: ScheduledTask):
        """Execute a scheduled task"""
        
        try:
            # Update task status
            task.last_run = datetime.utcnow()
            task.run_count += 1
            
            # Create execution record
            execution = {
                "run_number": task.run_count,
                "started_at": task.last_run.isoformat(),
                "status": "running"
            }
            
            # Execute based on task type
            result = await self._run_task_by_type(task)
            
            # Update execution record
            execution["completed_at"] = datetime.utcnow().isoformat()
            execution["status"] = "success"
            execution["result"] = result
            
            # Add to history
            task.execution_history.append(execution)
            
            # Limit history size
            if len(task.execution_history) > 100:
                task.execution_history = task.execution_history[-50:]
            
            # Send notifications
            await self._send_task_notifications(task, "success", result)
            
            # Calculate next run
            task.next_run = self._calculate_next_run(task)
            
            # Persist changes
            self._persist_task(task)
            
        except Exception as e:
            print(f"Task execution error: {e}")
            
            # Update execution record
            execution["completed_at"] = datetime.utcnow().isoformat()
            execution["status"] = "failed"
            execution["error"] = str(e)
            
            # Add to history
            task.execution_history.append(execution)
            
            # Handle retry
            if await self._should_retry(task):
                await self._schedule_retry(task)
            else:
                # Send failure notification
                await self._send_task_notifications(task, "failed", str(e))
    
    async def _run_task_by_type(self, task: ScheduledTask) -> Dict:
        """Run task based on its type"""
        
        if task.task_type == "scan":
            return await self._run_scan_task(task)
        elif task.task_type == "workflow":
            return await self._run_workflow_task(task)
        elif task.task_type == "report":
            return await self._run_report_task(task)
        elif task.task_type == "maintenance":
            return await self._run_maintenance_task(task)
        else:
            raise ValueError(f"Unknown task type: {task.task_type}")
    
    async def _run_scan_task(self, task: ScheduledTask) -> Dict:
        """Run a scan task"""
        from core.task_queue import task_manager
        
        tool = task.target.get("tool", "nmap")
        targets = task.target.get("targets", [])
        options = task.config.get("scan_options", {})
        
        results = {}
        for target in targets:
            command = f"{tool} {target}"
            task_id = task_manager.submit_scan_task(tool, command, options)
            results[target] = task_id
        
        return results
    
    async def _run_workflow_task(self, task: ScheduledTask) -> Dict:
        """Run a workflow task"""
        from core.workflow_engine import workflow_engine
        
        workflow_template = task.target.get("template")
        variables = task.target.get("variables", {})
        
        workflow_id = workflow_engine.create_workflow(workflow_template, variables)
        result = await workflow_engine.execute_workflow(workflow_id)
        
        return result
    
    async def _run_report_task(self, task: ScheduledTask) -> Dict:
        """Run a report generation task"""
        # TODO: Implement report generation
        return {"report": "generated"}
    
    async def _run_maintenance_task(self, task: ScheduledTask) -> Dict:
        """Run a maintenance task"""
        maintenance_type = task.target.get("type", "cleanup")
        
        if maintenance_type == "cleanup":
            # Clean old data
            return await self._cleanup_old_data(task.config)
        elif maintenance_type == "backup":
            # Backup database
            return await self._backup_database(task.config)
        elif maintenance_type == "update":
            # Update tools/signatures
            return await self._update_tools(task.config)
        
        return {"maintenance": "completed"}
    
    async def _cleanup_old_data(self, config: Dict) -> Dict:
        """Clean old scan data"""
        days_to_keep = config.get("days_to_keep", 30)
        
        # TODO: Implement cleanup logic
        return {"cleaned": "old_data"}
    
    async def _backup_database(self, config: Dict) -> Dict:
        """Backup database"""
        # TODO: Implement backup logic
        return {"backup": "completed"}
    
    async def _update_tools(self, config: Dict) -> Dict:
        """Update security tools"""
        # TODO: Implement update logic
        return {"update": "completed"}
    
    def _calculate_next_run(self, task: ScheduledTask) -> Optional[datetime]:
        """Calculate next run time for a task"""
        
        if task.schedule_type == ScheduleType.ONCE:
            # One-time task
            if task.run_count > 0:
                return None
            return task.start_date or datetime.utcnow()
            
        elif task.schedule_type == ScheduleType.CRON:
            # Cron expression
            tz = pytz.timezone(task.timezone)
            base_time = task.last_run or datetime.utcnow()
            cron = croniter(task.schedule_expression, base_time)
            return cron.get_next(datetime)
            
        elif task.schedule_type == ScheduleType.INTERVAL:
            # Fixed interval
            interval_seconds = int(task.schedule_expression)
            base_time = task.last_run or datetime.utcnow()
            return base_time + timedelta(seconds=interval_seconds)
            
        elif task.schedule_type == ScheduleType.HOURLY:
            base_time = task.last_run or datetime.utcnow()
            return base_time + timedelta(hours=1)
            
        elif task.schedule_type == ScheduleType.DAILY:
            base_time = task.last_run or datetime.utcnow()
            return base_time + timedelta(days=1)
            
        elif task.schedule_type == ScheduleType.WEEKLY:
            base_time = task.last_run or datetime.utcnow()
            return base_time + timedelta(weeks=1)
            
        elif task.schedule_type == ScheduleType.MONTHLY:
            base_time = task.last_run or datetime.utcnow()
            # Approximate month as 30 days
            return base_time + timedelta(days=30)
        
        return None
    
    def _validate_cron_expression(self, expression: str) -> bool:
        """Validate cron expression"""
        try:
            croniter(expression)
            return True
        except:
            return False
    
    async def _should_retry(self, task: ScheduledTask) -> bool:
        """Check if task should be retried"""
        retry_policy = task.retry_policy
        
        if not retry_policy.get("enabled", False):
            return False
        
        max_retries = retry_policy.get("max_retries", 3)
        retry_count = retry_policy.get("current_retry", 0)
        
        return retry_count < max_retries
    
    async def _schedule_retry(self, task: ScheduledTask):
        """Schedule task retry"""
        retry_policy = task.retry_policy
        retry_delay = retry_policy.get("retry_delay", 300)  # 5 minutes default
        
        # Update retry count
        retry_policy["current_retry"] = retry_policy.get("current_retry", 0) + 1
        
        # Schedule retry
        task.next_run = datetime.utcnow() + timedelta(seconds=retry_delay)
    
    async def _send_task_notifications(self, task: ScheduledTask, status: str, data: Any):
        """Send task notifications"""
        notifications = task.notifications
        
        if not notifications.get("enabled", False):
            return
        
        # Email notification
        if notifications.get("email"):
            await self._send_email_notification(
                notifications["email"],
                f"Scheduled task {task.name} - {status}",
                data
            )
        
        # Webhook notification
        if notifications.get("webhook"):
            await self._send_webhook_notification(
                notifications["webhook"],
                {
                    "task": task.name,
                    "status": status,
                    "data": data
                }
            )
    
    async def _send_email_notification(self, email: str, subject: str, body: Any):
        """Send email notification"""
        # TODO: Implement email sending
        pass
    
    async def _send_webhook_notification(self, webhook_url: str, data: Dict):
        """Send webhook notification"""
        import aiohttp
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=data) as response:
                    return response.status == 200
        except:
            return False
    
    def _persist_task(self, task: ScheduledTask):
        """Persist task to database"""
        # TODO: Implement database persistence
        pass
    
    def pause_task(self, task_id: str) -> bool:
        """Pause a scheduled task"""
        if task_id in self.tasks:
            self.tasks[task_id].status = ScheduleStatus.PAUSED
            return True
        return False
    
    def resume_task(self, task_id: str) -> bool:
        """Resume a paused task"""
        if task_id in self.tasks:
            task = self.tasks[task_id]
            if task.status == ScheduleStatus.PAUSED:
                task.status = ScheduleStatus.ACTIVE
                task.next_run = self._calculate_next_run(task)
                return True
        return False
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a scheduled task"""
        if task_id in self.tasks:
            self.tasks[task_id].status = ScheduleStatus.CANCELLED
            
            # Cancel if running
            if task_id in self.running_tasks:
                self.running_tasks[task_id].cancel()
                del self.running_tasks[task_id]
            
            return True
        return False
    
    def get_task(self, task_id: str) -> Optional[ScheduledTask]:
        """Get task by ID"""
        return self.tasks.get(task_id)
    
    def get_all_tasks(self, status: ScheduleStatus = None) -> List[ScheduledTask]:
        """Get all tasks, optionally filtered by status"""
        if status:
            return [t for t in self.tasks.values() if t.status == status]
        return list(self.tasks.values())
    
    def get_upcoming_tasks(self, hours: int = 24) -> List[ScheduledTask]:
        """Get tasks scheduled in the next N hours"""
        cutoff = datetime.utcnow() + timedelta(hours=hours)
        upcoming = []
        
        for task in self.tasks.values():
            if task.next_run and task.next_run <= cutoff:
                upcoming.append(task)
        
        return sorted(upcoming, key=lambda t: t.next_run)

# Predefined schedule templates
SCHEDULE_TEMPLATES = {
    "daily_vulnerability_scan": {
        "name": "Daily Vulnerability Scan",
        "task_type": "scan",
        "schedule_type": ScheduleType.DAILY,
        "config": {
            "scan_options": {
                "intensity": "normal",
                "ports": "common"
            }
        }
    },
    "weekly_full_scan": {
        "name": "Weekly Full Scan",
        "task_type": "scan",
        "schedule_type": ScheduleType.WEEKLY,
        "config": {
            "scan_options": {
                "intensity": "aggressive",
                "ports": "all"
            }
        }
    },
    "hourly_uptime_check": {
        "name": "Hourly Uptime Check",
        "task_type": "scan",
        "schedule_type": ScheduleType.HOURLY,
        "config": {
            "scan_options": {
                "type": "ping",
                "timeout": 30
            }
        }
    },
    "monthly_compliance_report": {
        "name": "Monthly Compliance Report",
        "task_type": "report",
        "schedule_type": ScheduleType.MONTHLY,
        "config": {
            "report_type": "compliance",
            "format": "pdf"
        }
    },
    "nightly_backup": {
        "name": "Nightly Database Backup",
        "task_type": "maintenance",
        "schedule_type": ScheduleType.CRON,
        "schedule_expression": "0 2 * * *",  # 2 AM every day
        "target": {
            "type": "backup"
        }
    }
}

# Global scheduler instance
scheduler = Scheduler()

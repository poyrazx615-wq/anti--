# Asynchronous Task Queue System
from celery import Celery
from celery.result import AsyncResult
from typing import Dict, Any, Optional
import json
import subprocess
import asyncio
from datetime import datetime
import redis

# Celery configuration
celery_app = Celery(
    'kali_security_platform',
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/1',
    include=['core.tasks']
)

# Celery settings
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max per task
    task_soft_time_limit=3000,  # 50 minutes soft limit
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=100,
)

class TaskManager:
    """Manage asynchronous scanning tasks"""
    
    def __init__(self):
        self.redis_client = redis.Redis(host='localhost', port=6379, db=2, decode_responses=True)
        self.active_tasks = {}
    
    def submit_scan_task(self, tool: str, command: str, options: Dict = None) -> str:
        """Submit a new scan task to queue"""
        from core.tasks import execute_scan_task
        
        task = execute_scan_task.delay(tool, command, options or {})
        task_id = task.id
        
        # Store task metadata
        self.redis_client.hset(f"task:{task_id}", mapping={
            "tool": tool,
            "command": command,
            "status": "pending",
            "submitted_at": datetime.utcnow().isoformat(),
            "progress": 0
        })
        
        self.active_tasks[task_id] = task
        return task_id
    
    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Get current status of a task"""
        task = AsyncResult(task_id, app=celery_app)
        metadata = self.redis_client.hgetall(f"task:{task_id}")
        
        status = {
            "task_id": task_id,
            "state": task.state,
            "progress": int(metadata.get("progress", 0)),
            "tool": metadata.get("tool"),
            "command": metadata.get("command"),
            "submitted_at": metadata.get("submitted_at"),
            "completed_at": metadata.get("completed_at"),
            "result": None,
            "error": None
        }
        
        if task.state == 'PENDING':
            status["info"] = "Task is waiting in queue"
        elif task.state == 'STARTED':
            status["info"] = "Task is running"
        elif task.state == 'SUCCESS':
            status["result"] = task.result
            status["info"] = "Task completed successfully"
        elif task.state == 'FAILURE':
            status["error"] = str(task.info)
            status["info"] = "Task failed"
        
        return status
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a running task"""
        task = AsyncResult(task_id, app=celery_app)
        task.revoke(terminate=True)
        
        # Update metadata
        self.redis_client.hset(f"task:{task_id}", "status", "cancelled")
        
        if task_id in self.active_tasks:
            del self.active_tasks[task_id]
        
        return True
    
    def get_all_tasks(self, limit: int = 100) -> list:
        """Get all tasks with their status"""
        tasks = []
        
        # Get all task keys
        task_keys = self.redis_client.keys("task:*")[:limit]
        
        for key in task_keys:
            task_id = key.split(":")[1]
            status = self.get_task_status(task_id)
            tasks.append(status)
        
        return sorted(tasks, key=lambda x: x.get("submitted_at", ""), reverse=True)
    
    def cleanup_old_tasks(self, days: int = 7):
        """Clean up tasks older than specified days"""
        from datetime import timedelta
        
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        task_keys = self.redis_client.keys("task:*")
        
        for key in task_keys:
            metadata = self.redis_client.hgetall(key)
            submitted_at = metadata.get("submitted_at")
            
            if submitted_at:
                task_date = datetime.fromisoformat(submitted_at)
                if task_date < cutoff_date:
                    self.redis_client.delete(key)

# Celery Tasks
@celery_app.task(bind=True, name='core.tasks.execute_scan_task')
def execute_scan_task(self, tool: str, command: str, options: Dict) -> Dict:
    """Execute a scan task asynchronously"""
    import shlex
    import time
    
    task_id = self.request.id
    redis_client = redis.Redis(host='localhost', port=6379, db=2, decode_responses=True)
    
    try:
        # Update task status
        redis_client.hset(f"task:{task_id}", mapping={
            "status": "running",
            "started_at": datetime.utcnow().isoformat()
        })
        
        # Parse command safely
        cmd_args = shlex.split(command)
        
        # Execute command
        process = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        output_lines = []
        line_count = 0
        
        # Read output line by line
        for line in iter(process.stdout.readline, ''):
            if line:
                output_lines.append(line.strip())
                line_count += 1
                
                # Update progress
                if line_count % 10 == 0:
                    progress = min(90, line_count)  # Cap at 90%
                    redis_client.hset(f"task:{task_id}", "progress", progress)
                    
                    # Update Celery task state
                    self.update_state(
                        state='PROGRESS',
                        meta={'current': progress, 'total': 100}
                    )
        
        # Wait for process to complete
        process.wait()
        
        # Get any remaining stderr
        stderr = process.stderr.read()
        
        # Final update
        redis_client.hset(f"task:{task_id}", mapping={
            "status": "completed",
            "completed_at": datetime.utcnow().isoformat(),
            "progress": 100
        })
        
        return {
            "tool": tool,
            "command": command,
            "output": output_lines,
            "stderr": stderr,
            "return_code": process.returncode,
            "line_count": line_count
        }
        
    except Exception as e:
        # Update on error
        redis_client.hset(f"task:{task_id}", mapping={
            "status": "failed",
            "error": str(e),
            "completed_at": datetime.utcnow().isoformat()
        })
        raise

@celery_app.task(name='core.tasks.batch_scan_task')
def batch_scan_task(targets: list, tool: str, options: Dict) -> Dict:
    """Execute batch scans on multiple targets"""
    results = {}
    
    for target in targets:
        command = f"{tool} {target}"
        result = execute_scan_task.delay(tool, command, options)
        results[target] = result.id
    
    return results

@celery_app.task(name='core.tasks.scheduled_scan_task')
def scheduled_scan_task(scan_config: Dict) -> Dict:
    """Execute scheduled scans"""
    tool = scan_config.get("tool")
    targets = scan_config.get("targets", [])
    schedule = scan_config.get("schedule")  # cron expression
    
    results = batch_scan_task(targets, tool, {})
    
    return {
        "schedule": schedule,
        "executed_at": datetime.utcnow().isoformat(),
        "results": results
    }

# Create global task manager instance
task_manager = TaskManager()

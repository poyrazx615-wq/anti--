# Workflow Engine for Complex Security Testing Scenarios
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import json
import asyncio
from datetime import datetime
import uuid

class WorkflowStatus(Enum):
    """Workflow execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"

class StepStatus(Enum):
    """Workflow step status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

@dataclass
class WorkflowStep:
    """Single step in a workflow"""
    id: str
    name: str
    tool: str
    command: str
    depends_on: List[str] = field(default_factory=list)
    condition: Optional[str] = None  # JavaScript expression
    timeout: int = 300  # seconds
    retry_count: int = 3
    on_success: Optional[str] = None  # Next step ID
    on_failure: Optional[str] = None  # Error handling step ID
    variables: Dict[str, Any] = field(default_factory=dict)
    status: StepStatus = StepStatus.PENDING
    result: Optional[Dict] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

@dataclass
class Workflow:
    """Complete workflow definition"""
    id: str
    name: str
    description: str
    steps: List[WorkflowStep]
    variables: Dict[str, Any] = field(default_factory=dict)
    status: WorkflowStatus = WorkflowStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    current_step: Optional[str] = None
    results: Dict[str, Any] = field(default_factory=dict)

class WorkflowEngine:
    """Execute and manage complex security testing workflows"""
    
    def __init__(self):
        self.workflows: Dict[str, Workflow] = {}
        self.templates: Dict[str, Dict] = {}
        self._load_templates()
    
    def _load_templates(self):
        """Load predefined workflow templates"""
        
        self.templates = {
            "web_pentest": {
                "name": "Web Application Penetration Test",
                "description": "Complete web application security assessment",
                "steps": [
                    {
                        "id": "recon",
                        "name": "Reconnaissance",
                        "tool": "nmap",
                        "command": "nmap -sV -p- {{target}}",
                        "timeout": 600
                    },
                    {
                        "id": "web_scan",
                        "name": "Web Vulnerability Scan",
                        "tool": "nikto",
                        "command": "nikto -h {{target}}",
                        "depends_on": ["recon"],
                        "timeout": 900
                    },
                    {
                        "id": "dir_discovery",
                        "name": "Directory Discovery",
                        "tool": "gobuster",
                        "command": "gobuster dir -u {{target}} -w /usr/share/wordlists/dirb/common.txt",
                        "depends_on": ["recon"],
                        "timeout": 600
                    },
                    {
                        "id": "sql_test",
                        "name": "SQL Injection Test",
                        "tool": "sqlmap",
                        "command": "sqlmap -u {{target}} --batch --forms",
                        "depends_on": ["web_scan"],
                        "condition": "results.web_scan.has_forms == true",
                        "timeout": 1200
                    },
                    {
                        "id": "xss_test",
                        "name": "XSS Testing",
                        "tool": "xsstrike",
                        "command": "xsstrike -u {{target}}",
                        "depends_on": ["web_scan"],
                        "timeout": 600
                    },
                    {
                        "id": "report",
                        "name": "Generate Report",
                        "tool": "custom",
                        "command": "generate_report",
                        "depends_on": ["sql_test", "xss_test", "dir_discovery"],
                        "timeout": 60
                    }
                ]
            },
            
            "network_pentest": {
                "name": "Network Penetration Test",
                "description": "Internal network security assessment",
                "steps": [
                    {
                        "id": "discovery",
                        "name": "Network Discovery",
                        "tool": "nmap",
                        "command": "nmap -sn {{network_range}}",
                        "timeout": 300
                    },
                    {
                        "id": "port_scan",
                        "name": "Port Scanning",
                        "tool": "masscan",
                        "command": "masscan -p1-65535 {{targets}} --rate=1000",
                        "depends_on": ["discovery"],
                        "timeout": 600
                    },
                    {
                        "id": "service_enum",
                        "name": "Service Enumeration",
                        "tool": "nmap",
                        "command": "nmap -sV -sC -p {{open_ports}} {{targets}}",
                        "depends_on": ["port_scan"],
                        "timeout": 900
                    },
                    {
                        "id": "vuln_scan",
                        "name": "Vulnerability Scanning",
                        "tool": "nmap",
                        "command": "nmap --script vuln {{targets}}",
                        "depends_on": ["service_enum"],
                        "timeout": 1200
                    },
                    {
                        "id": "exploit",
                        "name": "Exploitation Attempt",
                        "tool": "metasploit",
                        "command": "msfconsole -x 'use {{exploit_module}}; set RHOSTS {{target}}; run'",
                        "depends_on": ["vuln_scan"],
                        "condition": "results.vuln_scan.has_exploitable == true",
                        "timeout": 1800
                    }
                ]
            },
            
            "osint_workflow": {
                "name": "OSINT Investigation",
                "description": "Open source intelligence gathering",
                "steps": [
                    {
                        "id": "dns_enum",
                        "name": "DNS Enumeration",
                        "tool": "dnsrecon",
                        "command": "dnsrecon -d {{domain}}",
                        "timeout": 300
                    },
                    {
                        "id": "subdomain_enum",
                        "name": "Subdomain Enumeration",
                        "tool": "amass",
                        "command": "amass enum -d {{domain}}",
                        "timeout": 600
                    },
                    {
                        "id": "email_harvest",
                        "name": "Email Harvesting",
                        "tool": "theharvester",
                        "command": "theHarvester -d {{domain}} -b all",
                        "depends_on": ["dns_enum"],
                        "timeout": 600
                    },
                    {
                        "id": "shodan_search",
                        "name": "Shodan Search",
                        "tool": "shodan",
                        "command": "shodan search hostname:{{domain}}",
                        "depends_on": ["subdomain_enum"],
                        "timeout": 60
                    },
                    {
                        "id": "metadata_extract",
                        "name": "Metadata Extraction",
                        "tool": "metagoofil",
                        "command": "metagoofil -d {{domain}} -t pdf,doc,xls",
                        "depends_on": ["dns_enum"],
                        "timeout": 900
                    }
                ]
            }
        }
    
    def create_workflow(self, template_name: str, variables: Dict[str, Any]) -> str:
        """Create a new workflow from template"""
        
        if template_name not in self.templates:
            raise ValueError(f"Template {template_name} not found")
        
        template = self.templates[template_name]
        workflow_id = str(uuid.uuid4())
        
        # Create workflow steps from template
        steps = []
        for step_def in template["steps"]:
            # Replace variables in command
            command = step_def["command"]
            for var_name, var_value in variables.items():
                command = command.replace(f"{{{{{var_name}}}}}", str(var_value))
            
            step = WorkflowStep(
                id=step_def["id"],
                name=step_def["name"],
                tool=step_def["tool"],
                command=command,
                depends_on=step_def.get("depends_on", []),
                condition=step_def.get("condition"),
                timeout=step_def.get("timeout", 300),
                retry_count=step_def.get("retry_count", 3),
                on_success=step_def.get("on_success"),
                on_failure=step_def.get("on_failure"),
                variables=step_def.get("variables", {})
            )
            steps.append(step)
        
        # Create workflow
        workflow = Workflow(
            id=workflow_id,
            name=template["name"],
            description=template["description"],
            steps=steps,
            variables=variables
        )
        
        self.workflows[workflow_id] = workflow
        return workflow_id
    
    async def execute_workflow(self, workflow_id: str) -> Dict[str, Any]:
        """Execute a workflow"""
        
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            raise ValueError(f"Workflow {workflow_id} not found")
        
        workflow.status = WorkflowStatus.RUNNING
        workflow.started_at = datetime.utcnow()
        
        try:
            # Execute steps in dependency order
            executed_steps = set()
            
            while len(executed_steps) < len(workflow.steps):
                # Find next executable steps
                executable_steps = []
                
                for step in workflow.steps:
                    if step.id in executed_steps:
                        continue
                    
                    # Check dependencies
                    if all(dep in executed_steps for dep in step.depends_on):
                        # Check condition if present
                        if step.condition:
                            if not self._evaluate_condition(step.condition, workflow):
                                step.status = StepStatus.SKIPPED
                                executed_steps.add(step.id)
                                continue
                        
                        executable_steps.append(step)
                
                if not executable_steps:
                    break
                
                # Execute steps in parallel
                tasks = []
                for step in executable_steps:
                    tasks.append(self._execute_step(step, workflow))
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results
                for step, result in zip(executable_steps, results):
                    if isinstance(result, Exception):
                        step.status = StepStatus.FAILED
                        step.error = str(result)
                        
                        # Handle failure
                        if step.on_failure:
                            # Execute failure handling step
                            pass
                    else:
                        step.status = StepStatus.COMPLETED
                        step.result = result
                        workflow.results[step.id] = result
                        
                        # Handle success
                        if step.on_success:
                            # Execute next step
                            pass
                    
                    executed_steps.add(step.id)
                    step.completed_at = datetime.utcnow()
            
            workflow.status = WorkflowStatus.COMPLETED
            workflow.completed_at = datetime.utcnow()
            
            return {
                "workflow_id": workflow_id,
                "status": workflow.status.value,
                "results": workflow.results,
                "duration": (workflow.completed_at - workflow.started_at).total_seconds()
            }
            
        except Exception as e:
            workflow.status = WorkflowStatus.FAILED
            workflow.completed_at = datetime.utcnow()
            raise
    
    async def _execute_step(self, step: WorkflowStep, workflow: Workflow) -> Dict[str, Any]:
        """Execute a single workflow step"""
        
        step.status = StepStatus.RUNNING
        step.started_at = datetime.utcnow()
        workflow.current_step = step.id
        
        # Execute command with timeout
        try:
            result = await asyncio.wait_for(
                self._run_command(step.tool, step.command),
                timeout=step.timeout
            )
            
            return result
            
        except asyncio.TimeoutError:
            if step.retry_count > 0:
                step.retry_count -= 1
                return await self._execute_step(step, workflow)
            else:
                raise Exception(f"Step {step.name} timed out after {step.timeout} seconds")
    
    async def _run_command(self, tool: str, command: str) -> Dict[str, Any]:
        """Run a command and return results"""
        import subprocess
        
        # This is a simplified version - integrate with task_queue for real execution
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        return {
            "stdout": stdout.decode() if stdout else "",
            "stderr": stderr.decode() if stderr else "",
            "return_code": process.returncode
        }
    
    def _evaluate_condition(self, condition: str, workflow: Workflow) -> bool:
        """Evaluate a condition expression"""
        # Simple evaluation - in production use a safe expression evaluator
        try:
            # Build context
            context = {
                "results": workflow.results,
                "variables": workflow.variables
            }
            
            # This is unsafe - use a proper expression evaluator in production
            return eval(condition, {"__builtins__": {}}, context)
        except:
            return False
    
    def get_workflow_status(self, workflow_id: str) -> Dict[str, Any]:
        """Get current workflow status"""
        
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return None
        
        return {
            "id": workflow.id,
            "name": workflow.name,
            "status": workflow.status.value,
            "current_step": workflow.current_step,
            "steps": [
                {
                    "id": step.id,
                    "name": step.name,
                    "status": step.status.value,
                    "error": step.error
                }
                for step in workflow.steps
            ],
            "started_at": workflow.started_at.isoformat() if workflow.started_at else None,
            "completed_at": workflow.completed_at.isoformat() if workflow.completed_at else None
        }
    
    def cancel_workflow(self, workflow_id: str) -> bool:
        """Cancel a running workflow"""
        
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return False
        
        if workflow.status == WorkflowStatus.RUNNING:
            workflow.status = WorkflowStatus.CANCELLED
            workflow.completed_at = datetime.utcnow()
            return True
        
        return False
    
    def pause_workflow(self, workflow_id: str) -> bool:
        """Pause a running workflow"""
        
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return False
        
        if workflow.status == WorkflowStatus.RUNNING:
            workflow.status = WorkflowStatus.PAUSED
            return True
        
        return False
    
    def resume_workflow(self, workflow_id: str) -> bool:
        """Resume a paused workflow"""
        
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return False
        
        if workflow.status == WorkflowStatus.PAUSED:
            workflow.status = WorkflowStatus.RUNNING
            return True
        
        return False

# Global workflow engine instance
workflow_engine = WorkflowEngine()

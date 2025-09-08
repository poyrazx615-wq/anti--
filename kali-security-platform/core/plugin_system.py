# Plugin System for Extensibility
import importlib
import inspect
from typing import Dict, List, Any, Optional, Callable
from pathlib import Path
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
import yaml

@dataclass
class PluginMetadata:
    """Plugin metadata"""
    name: str
    version: str
    author: str
    description: str
    category: str
    dependencies: List[str]
    config_schema: Dict[str, Any]

class BasePlugin(ABC):
    """Base class for all plugins"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.metadata = self.get_metadata()
    
    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        pass
    
    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the plugin"""
        pass
    
    @abstractmethod
    def execute(self, *args, **kwargs) -> Any:
        """Execute plugin functionality"""
        pass
    
    def validate_config(self) -> bool:
        """Validate plugin configuration"""
        # Implement config validation based on schema
        return True
    
    def cleanup(self):
        """Cleanup plugin resources"""
        pass

class PluginManager:
    """Manage and execute plugins"""
    
    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = Path(plugin_dir)
        self.plugins: Dict[str, BasePlugin] = {}
        self.hooks: Dict[str, List[Callable]] = {}
        self._ensure_plugin_directory()
    
    def _ensure_plugin_directory(self):
        """Ensure plugin directory exists with proper structure"""
        self.plugin_dir.mkdir(exist_ok=True)
        
        # Create category directories
        categories = ["scanners", "exploits", "parsers", "reporters", "integrations"]
        for category in categories:
            (self.plugin_dir / category).mkdir(exist_ok=True)
    
    def discover_plugins(self) -> List[str]:
        """Discover all available plugins"""
        discovered = []
        
        for category_dir in self.plugin_dir.iterdir():
            if category_dir.is_dir() and not category_dir.name.startswith("__"):
                for plugin_file in category_dir.glob("*.py"):
                    if not plugin_file.name.startswith("__"):
                        plugin_name = f"{category_dir.name}.{plugin_file.stem}"
                        discovered.append(plugin_name)
        
        return discovered
    
    def load_plugin(self, plugin_name: str, config: Dict = None) -> bool:
        """Load a plugin"""
        try:
            # Import plugin module
            module_path = f"plugins.{plugin_name.replace('.', '.')}"
            module = importlib.import_module(module_path)
            
            # Find plugin class (must inherit from BasePlugin)
            plugin_class = None
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and issubclass(obj, BasePlugin) and obj != BasePlugin:
                    plugin_class = obj
                    break
            
            if not plugin_class:
                return False
            
            # Instantiate plugin
            plugin_instance = plugin_class(config)
            
            # Validate configuration
            if not plugin_instance.validate_config():
                return False
            
            # Initialize plugin
            if not plugin_instance.initialize():
                return False
            
            # Register plugin
            self.plugins[plugin_name] = plugin_instance
            
            return True
            
        except Exception as e:
            print(f"Failed to load plugin {plugin_name}: {e}")
            return False
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin"""
        if plugin_name in self.plugins:
            plugin = self.plugins[plugin_name]
            plugin.cleanup()
            del self.plugins[plugin_name]
            return True
        return False
    
    def execute_plugin(self, plugin_name: str, *args, **kwargs) -> Any:
        """Execute a plugin"""
        if plugin_name not in self.plugins:
            raise ValueError(f"Plugin {plugin_name} not loaded")
        
        plugin = self.plugins[plugin_name]
        return plugin.execute(*args, **kwargs)
    
    def register_hook(self, hook_name: str, callback: Callable):
        """Register a hook callback"""
        if hook_name not in self.hooks:
            self.hooks[hook_name] = []
        
        self.hooks[hook_name].append(callback)
    
    def trigger_hook(self, hook_name: str, *args, **kwargs) -> List[Any]:
        """Trigger all callbacks for a hook"""
        results = []
        
        if hook_name in self.hooks:
            for callback in self.hooks[hook_name]:
                try:
                    result = callback(*args, **kwargs)
                    results.append(result)
                except Exception as e:
                    print(f"Hook callback error: {e}")
        
        return results
    
    def get_loaded_plugins(self) -> Dict[str, Dict]:
        """Get information about loaded plugins"""
        info = {}
        
        for name, plugin in self.plugins.items():
            metadata = plugin.metadata
            info[name] = {
                "name": metadata.name,
                "version": metadata.version,
                "author": metadata.author,
                "description": metadata.description,
                "category": metadata.category
            }
        
        return info

# Example Scanner Plugin
class NmapPlugin(BasePlugin):
    """Nmap scanner plugin"""
    
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Nmap Scanner",
            version="1.0.0",
            author="Security Team",
            description="Advanced Nmap scanning plugin",
            category="scanners",
            dependencies=["python-nmap"],
            config_schema={
                "timeout": {"type": "integer", "default": 300},
                "ports": {"type": "string", "default": "1-65535"},
                "scan_type": {"type": "string", "default": "-sV"}
            }
        )
    
    def initialize(self) -> bool:
        try:
            import nmap
            self.nm = nmap.PortScanner()
            return True
        except:
            return False
    
    def execute(self, target: str, **kwargs) -> Dict:
        """Execute Nmap scan"""
        scan_type = kwargs.get("scan_type", self.config.get("scan_type", "-sV"))
        ports = kwargs.get("ports", self.config.get("ports", "1-65535"))
        
        self.nm.scan(target, ports, scan_type)
        
        results = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "hosts": {}
        }
        
        for host in self.nm.all_hosts():
            results["hosts"][host] = {
                "state": self.nm[host].state(),
                "protocols": {}
            }
            
            for proto in self.nm[host].all_protocols():
                results["hosts"][host]["protocols"][proto] = {}
                
                for port in self.nm[host][proto].keys():
                    results["hosts"][host]["protocols"][proto][port] = {
                        "state": self.nm[host][proto][port]["state"],
                        "name": self.nm[host][proto][port]["name"],
                        "product": self.nm[host][proto][port].get("product", ""),
                        "version": self.nm[host][proto][port].get("version", "")
                    }
        
        return results

# Example Parser Plugin
class JsonParserPlugin(BasePlugin):
    """JSON output parser plugin"""
    
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="JSON Parser",
            version="1.0.0",
            author="Security Team",
            description="Parse JSON scan outputs",
            category="parsers",
            dependencies=[],
            config_schema={
                "pretty": {"type": "boolean", "default": True}
            }
        )
    
    def initialize(self) -> bool:
        return True
    
    def execute(self, data: Any, **kwargs) -> str:
        """Convert data to JSON"""
        pretty = kwargs.get("pretty", self.config.get("pretty", True))
        
        if pretty:
            return json.dumps(data, indent=2, default=str)
        else:
            return json.dumps(data, default=str)

# Example Integration Plugin
class SlackIntegrationPlugin(BasePlugin):
    """Slack notification integration"""
    
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Slack Integration",
            version="1.0.0",
            author="Security Team",
            description="Send notifications to Slack",
            category="integrations",
            dependencies=["slack-sdk"],
            config_schema={
                "webhook_url": {"type": "string", "required": True},
                "channel": {"type": "string", "default": "#security"},
                "username": {"type": "string", "default": "Security Bot"}
            }
        )
    
    def initialize(self) -> bool:
        try:
            from slack_sdk.webhook import WebhookClient
            self.webhook_url = self.config.get("webhook_url")
            if not self.webhook_url:
                return False
            self.client = WebhookClient(self.webhook_url)
            return True
        except:
            return False
    
    def execute(self, message: str, **kwargs) -> bool:
        """Send message to Slack"""
        try:
            response = self.client.send(
                text=message,
                username=kwargs.get("username", self.config.get("username")),
                channel=kwargs.get("channel", self.config.get("channel"))
            )
            return response.status_code == 200
        except:
            return False

# Global plugin manager instance
plugin_manager = PluginManager()

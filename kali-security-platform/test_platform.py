#!/usr/bin/env python3
"""
Kali Security Platform - Test Script
Tests all components before deployment
"""

import sys
import importlib
from pathlib import Path
from colorama import init, Fore, Style

init(autoreset=True)

def print_header():
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║     KALI SECURITY PLATFORM - SYSTEM TEST                    ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")

def test_import(module_name, display_name=None):
    """Test if a module can be imported"""
    display = display_name or module_name
    try:
        importlib.import_module(module_name)
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} {display} module loaded successfully")
        return True
    except ImportError as e:
        print(f"{Fore.RED}✗{Style.RESET_ALL} {display} module failed: {e}")
        return False

def test_directory(path, name):
    """Test if directory exists"""
    if Path(path).exists():
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} {name} directory exists")
        return True
    else:
        print(f"{Fore.YELLOW}!{Style.RESET_ALL} {name} directory missing (will be created)")
        Path(path).mkdir(parents=True, exist_ok=True)
        return True

def test_file(path, name):
    """Test if file exists"""
    if Path(path).exists():
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} {name} file exists")
        return True
    else:
        print(f"{Fore.RED}✗{Style.RESET_ALL} {name} file missing")
        return False

def run_tests():
    """Run all system tests"""
    print_header()
    
    results = []
    
    print(f"\n{Fore.CYAN}[1/5] Testing Core Dependencies:{Style.RESET_ALL}")
    results.append(test_import("fastapi", "FastAPI"))
    results.append(test_import("uvicorn", "Uvicorn"))
    results.append(test_import("pydantic", "Pydantic"))
    results.append(test_import("sqlalchemy", "SQLAlchemy"))
    
    print(f"\n{Fore.CYAN}[2/5] Testing Application Modules:{Style.RESET_ALL}")
    results.append(test_import("api.app", "API Application"))
    results.append(test_import("core.config", "Configuration"))
    results.append(test_import("core.security", "Security Manager"))
    results.append(test_import("core.database", "Database Manager"))
    results.append(test_import("core.validator", "Input Validator"))
    
    print(f"\n{Fore.CYAN}[3/5] Testing Feature Modules:{Style.RESET_ALL}")
    results.append(test_import("modules.security_tools", "Security Tools"))
    results.append(test_import("modules.osint.osint_framework", "OSINT Framework"))
    results.append(test_import("modules.exploits.exploit_mapper", "Exploit Mapper"))
    
    print(f"\n{Fore.CYAN}[4/5] Testing Routes:{Style.RESET_ALL}")
    results.append(test_import("api.routes.security_tools", "Security Tools Route"))
    results.append(test_import("api.routes.osint", "OSINT Route"))
    results.append(test_import("api.routes.exploit_advisor", "Exploit Advisor Route"))
    
    print(f"\n{Fore.CYAN}[5/5] Testing File System:{Style.RESET_ALL}")
    results.append(test_directory("outputs", "Outputs"))
    results.append(test_directory("logs", "Logs"))
    results.append(test_file("main.py", "Main application"))
    results.append(test_file("requirements.txt", "Requirements"))
    
    # Summary
    total = len(results)
    passed = sum(results)
    failed = total - passed
    
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}TEST SUMMARY:{Style.RESET_ALL}")
    print(f"  Total Tests: {total}")
    print(f"  {Fore.GREEN}Passed: {passed}{Style.RESET_ALL}")
    print(f"  {Fore.RED}Failed: {failed}{Style.RESET_ALL}")
    
    if failed == 0:
        print(f"\n{Fore.GREEN}✓ ALL TESTS PASSED! Platform is ready to run.{Style.RESET_ALL}")
        print(f"\nTo start the platform:")
        print(f"  {Fore.YELLOW}python3 main.py{Style.RESET_ALL}")
        return 0
    else:
        print(f"\n{Fore.RED}✗ Some tests failed. Please check the errors above.{Style.RESET_ALL}")
        print(f"\nTo fix missing dependencies:")
        print(f"  {Fore.YELLOW}pip3 install -r requirements.txt{Style.RESET_ALL}")
        return 1

if __name__ == "__main__":
    sys.exit(run_tests())

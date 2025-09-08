#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Forensics, Reverse Engineering, and Advanced Analysis Tools
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from .web_security import SecurityTool

class ForensicsTools:
    """Digital Forensics and Incident Response Tools"""
    
    def __init__(self):
        self.tools = self._initialize_tools()
    
    def _initialize_tools(self) -> Dict[str, SecurityTool]:
        return {
            "VOLATILITY3": SecurityTool(
                name="Volatility3",
                category="Forensics",
                subcategory="Memory Forensics",
                description="Advanced memory forensics framework",
                installation={
                    "linux": "git clone https://github.com/volatilityfoundation/volatility3.git && cd volatility3 && pip3 install -r requirements.txt",
                    "windows": "git clone https://github.com/volatilityfoundation/volatility3.git && cd volatility3 && pip install -r requirements.txt"
                },
                usage=[
                    "python3 vol.py -f memory.dmp windows.info",
                    "python3 vol.py -f memory.dmp windows.pslist",
                    "python3 vol.py -f memory.dmp windows.netscan"
                ],
                examples=[
                    {
                        "description": "List processes",
                        "command": "python3 vol.py -f memory.dmp windows.pslist"
                    },
                    {
                        "description": "Network connections",
                        "command": "python3 vol.py -f memory.dmp windows.netscan"
                    },
                    {
                        "description": "Registry hives",
                        "command": "python3 vol.py -f memory.dmp windows.registry.hivelist"
                    },
                    {
                        "description": "Command line arguments",
                        "command": "python3 vol.py -f memory.dmp windows.cmdline"
                    },
                    {
                        "description": "Dump process",
                        "command": "python3 vol.py -f memory.dmp windows.memmap --pid 1234 --dump"
                    }
                ],
                options=[
                    {"flag": "-f", "description": "Memory dump file"},
                    {"flag": "-o", "description": "Output directory"},
                    {"flag": "--pid", "description": "Process ID"},
                    {"flag": "--dump", "description": "Dump to file"},
                    {"flag": "-r", "description": "Renderer (json, csv)"}
                ],
                output_format="txt/json/csv",
                requires_root=False,
                api_support=True,
                gui_available=False,
                platform=["linux", "windows", "macos"],
                dependencies=["python3", "yara-python"],
                documentation="https://volatility3.readthedocs.io/",
                github="https://github.com/volatilityfoundation/volatility3",
                alternatives=["Rekall", "Redline", "WinPMEM"]
            ),
            
            "WIRESHARK": SecurityTool(
                name="Wireshark",
                category="Forensics",
                subcategory="Network Analysis",
                description="Network protocol analyzer and packet capture tool",
                installation={
                    "linux": "apt-get install wireshark",
                    "windows": "Download from https://www.wireshark.org/download.html",
                    "macos": "brew install wireshark"
                },
                usage=[
                    "wireshark",
                    "tshark -i eth0 -w capture.pcap",
                    "tshark -r capture.pcap -Y 'http'"
                ],
                examples=[
                    {
                        "description": "GUI capture",
                        "command": "wireshark"
                    },
                    {
                        "description": "Command line capture",
                        "command": "tshark -i eth0 -w output.pcap"
                    },
                    {
                        "description": "Filter HTTP traffic",
                        "command": "tshark -r capture.pcap -Y 'http' -T fields -e http.host"
                    },
                    {
                        "description": "Extract files",
                        "command": "tshark -r capture.pcap --export-objects http,exported_files"
                    },
                    {
                        "description": "Statistics",
                        "command": "tshark -r capture.pcap -q -z io,stat,1"
                    }
                ],
                options=[
                    {"flag": "-i", "description": "Interface"},
                    {"flag": "-w", "description": "Write to file"},
                    {"flag": "-r", "description": "Read from file"},
                    {"flag": "-Y", "description": "Display filter"},
                    {"flag": "-T", "description": "Output format"}
                ],
                output_format="pcap/pcapng",
                requires_root=True,
                api_support=False,
                gui_available=True,
                platform=["linux", "windows", "macos"],
                dependencies=["libpcap"],
                documentation="https://www.wireshark.org/docs/",
                github="https://github.com/wireshark/wireshark",
                alternatives=["tcpdump", "NetworkMiner", "tshark"]
            )
        }

class ReverseEngineeringTools:
    """Reverse Engineering and Binary Analysis Tools"""
    
    def __init__(self):
        self.tools = self._initialize_tools()
    
    def _initialize_tools(self) -> Dict[str, SecurityTool]:
        return {
            "GHIDRA": SecurityTool(
                name="Ghidra",
                category="Reverse Engineering",
                subcategory="Binary Analysis",
                description="NSA's software reverse engineering framework",
                installation={
                    "linux": "wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20230928.zip && unzip ghidra*.zip",
                    "windows": "Download from https://ghidra-sre.org/",
                    "macos": "Download from https://ghidra-sre.org/"
                },
                usage=[
                    "./ghidraRun",
                    "./analyzeHeadless project_path project_name -import binary",
                    "./ghidraRun -import binary -scriptPath scripts"
                ],
                examples=[
                    {
                        "description": "Start GUI",
                        "command": "./ghidraRun"
                    },
                    {
                        "description": "Headless analysis",
                        "command": "./analyzeHeadless ~/ghidra_projects TestProject -import /path/to/binary -postScript ListFunctions.java"
                    },
                    {
                        "description": "Export decompiled code",
                        "command": "./analyzeHeadless ~/ghidra_projects TestProject -process binary -scriptPath ~/scripts -postScript ExportDecompiled.java"
                    },
                    {
                        "description": "Batch analysis",
                        "command": "./analyzeHeadless ~/ghidra_projects TestProject -import /path/to/binaries/*.exe -analysisTimeoutPerFile 3600"
                    }
                ],
                options=[
                    {"flag": "-import", "description": "Import file"},
                    {"flag": "-process", "description": "Process existing"},
                    {"flag": "-postScript", "description": "Run script after"},
                    {"flag": "-scriptPath", "description": "Script directory"},
                    {"flag": "-analysisTimeoutPerFile", "description": "Timeout per file"}
                ],
                output_format="project/text/asm",
                requires_root=False,
                api_support=True,
                gui_available=True,
                platform=["linux", "windows", "macos"],
                dependencies=["java"],
                documentation="https://ghidra-sre.org/CheatSheet.html",
                github="https://github.com/NationalSecurityAgency/ghidra",
                alternatives=["IDA Pro", "Radare2", "Binary Ninja"]
            ),
            
            "RADARE2": SecurityTool(
                name="Radare2",
                category="Reverse Engineering",
                subcategory="Binary Analysis",
                description="Advanced command-line reverse engineering framework",
                installation={
                    "linux": "git clone https://github.com/radareorg/radare2 && cd radare2 && sys/install.sh",
                    "apt": "apt-get install radare2",
                    "windows": "Download from https://rada.re/n/radare2.html"
                },
                usage=[
                    "r2 binary",
                    "r2 -A binary",
                    "r2 -d binary"
                ],
                examples=[
                    {
                        "description": "Analyze binary",
                        "command": "r2 -A binary"
                    },
                    {
                        "description": "Debug mode",
                        "command": "r2 -d binary"
                    },
                    {
                        "description": "Disassemble function",
                        "command": "r2 binary -c 'aaa; afl; pdf @main'"
                    },
                    {
                        "description": "String search",
                        "command": "r2 binary -c 'iz~password'"
                    },
                    {
                        "description": "Export graph",
                        "command": "r2 binary -c 'agf main > graph.dot'"
                    },
                    {
                        "description": "Web UI",
                        "command": "r2 -c=H binary"
                    }
                ],
                options=[
                    {"flag": "-A", "description": "Analyze all"},
                    {"flag": "-d", "description": "Debug mode"},
                    {"flag": "-c", "description": "Run command"},
                    {"flag": "-w", "description": "Write mode"},
                    {"flag": "-i", "description": "Run script"}
                ],
                output_format="text/json/dot",
                requires_root=False,
                api_support=True,
                gui_available=True,
                platform=["linux", "windows", "macos"],
                dependencies=["none"],
                documentation="https://book.rada.re/",
                github="https://github.com/radareorg/radare2",
                alternatives=["IDA Pro", "Ghidra", "x64dbg"]
            ),
            
            "GDB": SecurityTool(
                name="GDB",
                category="Reverse Engineering",
                subcategory="Debugger",
                description="GNU Debugger for debugging programs",
                installation={
                    "linux": "apt-get install gdb",
                    "macos": "brew install gdb",
                    "windows": "MinGW or Cygwin installation"
                },
                usage=[
                    "gdb binary",
                    "gdb -p PID",
                    "gdb binary core"
                ],
                examples=[
                    {
                        "description": "Start debugging",
                        "command": "gdb ./binary"
                    },
                    {
                        "description": "Attach to process",
                        "command": "gdb -p 1234"
                    },
                    {
                        "description": "Set breakpoint",
                        "command": "(gdb) break main"
                    },
                    {
                        "description": "Run with arguments",
                        "command": "(gdb) run arg1 arg2"
                    },
                    {
                        "description": "Examine memory",
                        "command": "(gdb) x/10x $rsp"
                    },
                    {
                        "description": "Disassemble",
                        "command": "(gdb) disas main"
                    }
                ],
                options=[
                    {"flag": "-p", "description": "Attach to PID"},
                    {"flag": "-x", "description": "Execute commands from file"},
                    {"flag": "-q", "description": "Quiet mode"},
                    {"flag": "-batch", "description": "Batch mode"},
                    {"flag": "-tui", "description": "Text UI mode"}
                ],
                output_format="text",
                requires_root=False,
                api_support=False,
                gui_available=False,
                platform=["linux", "macos"],
                dependencies=["none"],
                documentation="https://www.gnu.org/software/gdb/documentation/",
                github="https://sourceware.org/git/binutils-gdb.git",
                alternatives=["lldb", "x64dbg", "OllyDbg"]
            ),
            
            "OBJDUMP": SecurityTool(
                name="objdump",
                category="Reverse Engineering",
                subcategory="Binary Analysis",
                description="Display information from object files",
                installation={
                    "linux": "apt-get install binutils",
                    "macos": "brew install binutils",
                    "windows": "MinGW installation"
                },
                usage=[
                    "objdump -d binary",
                    "objdump -s binary",
                    "objdump -t binary"
                ],
                examples=[
                    {
                        "description": "Disassemble",
                        "command": "objdump -d binary"
                    },
                    {
                        "description": "Display headers",
                        "command": "objdump -x binary"
                    },
                    {
                        "description": "Show sections",
                        "command": "objdump -h binary"
                    },
                    {
                        "description": "Display symbols",
                        "command": "objdump -t binary"
                    },
                    {
                        "description": "Intel syntax",
                        "command": "objdump -M intel -d binary"
                    }
                ],
                options=[
                    {"flag": "-d", "description": "Disassemble"},
                    {"flag": "-s", "description": "Display full contents"},
                    {"flag": "-t", "description": "Display symbols"},
                    {"flag": "-x", "description": "Display all headers"},
                    {"flag": "-M", "description": "Disassembler options"}
                ],
                output_format="text",
                requires_root=False,
                api_support=False,
                gui_available=False,
                platform=["linux", "macos"],
                dependencies=["binutils"],
                documentation="https://sourceware.org/binutils/docs/binutils/objdump.html",
                github="https://sourceware.org/git/binutils-gdb.git",
                alternatives=["readelf", "nm", "strings"]
            )
        }

class SteganographyTools:
    """Steganography and Hidden Data Analysis Tools"""
    
    def __init__(self):
        self.tools = self._initialize_tools()
    
    def _initialize_tools(self) -> Dict[str, SecurityTool]:
        return {
            "STEGHIDE": SecurityTool(
                name="Steghide",
                category="Steganography",
                subcategory="Data Hiding",
                description="Steganography tool to hide data in images and audio files",
                installation={
                    "linux": "apt-get install steghide",
                    "macos": "brew install steghide"
                },
                usage=[
                    "steghide embed -cf image.jpg -ef secret.txt",
                    "steghide extract -sf image.jpg",
                    "steghide info image.jpg"
                ],
                examples=[
                    {
                        "description": "Embed file",
                        "command": "steghide embed -cf cover.jpg -ef secret.txt -p password"
                    },
                    {
                        "description": "Extract file",
                        "command": "steghide extract -sf stego.jpg -p password"
                    },
                    {
                        "description": "Get info",
                        "command": "steghide info stego.jpg"
                    },
                    {
                        "description": "Without password",
                        "command": "steghide embed -cf cover.jpg -ef secret.txt -N"
                    },
                    {
                        "description": "Force overwrite",
                        "command": "steghide embed -cf cover.jpg -ef secret.txt -f"
                    }
                ],
                options=[
                    {"flag": "embed", "description": "Embed data"},
                    {"flag": "extract", "description": "Extract data"},
                    {"flag": "-cf", "description": "Cover file"},
                    {"flag": "-ef", "description": "Embed file"},
                    {"flag": "-sf", "description": "Stego file"},
                    {"flag": "-p", "description": "Passphrase"}
                ],
                output_format="file",
                requires_root=False,
                api_support=False,
                gui_available=False,
                platform=["linux", "macos"],
                dependencies=["libjpeg", "libmcrypt"],
                documentation="http://steghide.sourceforge.net/documentation.php",
                github="https://github.com/StefanoDeVuono/steghide",
                alternatives=["StegSolve", "zsteg", "OpenStego"]
            ),
            
            "STEGSOLVE": SecurityTool(
                name="StegSolve",
                category="Steganography",
                subcategory="Image Analysis",
                description="Image steganography solver",
                installation={
                    "linux": "wget http://www.caesum.com/handbook/Stegsolve.jar",
                    "windows": "Download Stegsolve.jar"
                },
                usage=[
                    "java -jar Stegsolve.jar",
                    "java -jar Stegsolve.jar image.png"
                ],
                examples=[
                    {
                        "description": "Open GUI",
                        "command": "java -jar Stegsolve.jar"
                    },
                    {
                        "description": "Open image",
                        "command": "java -jar Stegsolve.jar image.png"
                    },
                    {
                        "description": "Analyze mode",
                        "command": "Use GUI: Analyze -> Data Extract"
                    }
                ],
                options=[
                    {"flag": "File", "description": "Open file"},
                    {"flag": "Analyze", "description": "Analysis tools"},
                    {"flag": "Image Combiner", "description": "XOR images"}
                ],
                output_format="image/text",
                requires_root=False,
                api_support=False,
                gui_available=True,
                platform=["linux", "windows", "macos"],
                dependencies=["java"],
                documentation="https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve",
                github="https://github.com/eugenekolo/sec-tools",
                alternatives=["steghide", "zsteg", "binwalk"]
            ),
            
            "ZSTEG": SecurityTool(
                name="zsteg",
                category="Steganography",
                subcategory="PNG/BMP Analysis",
                description="PNG/BMP steganography detection",
                installation={
                    "linux": "gem install zsteg",
                    "macos": "gem install zsteg"
                },
                usage=[
                    "zsteg image.png",
                    "zsteg -a image.png",
                    "zsteg -E image.png"
                ],
                examples=[
                    {
                        "description": "Basic scan",
                        "command": "zsteg image.png"
                    },
                    {
                        "description": "All methods",
                        "command": "zsteg -a image.png"
                    },
                    {
                        "description": "Extract data",
                        "command": "zsteg -E b1,rgb,lsb image.png"
                    },
                    {
                        "description": "Verbose output",
                        "command": "zsteg -v image.png"
                    },
                    {
                        "description": "Check specific",
                        "command": "zsteg image.png -b 1,8,lsb,xy"
                    }
                ],
                options=[
                    {"flag": "-a", "description": "Try all methods"},
                    {"flag": "-E", "description": "Extract data"},
                    {"flag": "-v", "description": "Verbose"},
                    {"flag": "-b", "description": "Bits to check"},
                    {"flag": "-l", "description": "Limit bytes"}
                ],
                output_format="text/binary",
                requires_root=False,
                api_support=False,
                gui_available=False,
                platform=["linux", "macos"],
                dependencies=["ruby"],
                documentation="https://github.com/zed-0xff/zsteg",
                github="https://github.com/zed-0xff/zsteg",
                alternatives=["stegsolve", "steghide", "stegdetect"]
            )
        }
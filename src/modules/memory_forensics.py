# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""
Module 2: Memory Forensics & Live Triage
Production-grade memory analysis with Volatility 3 integration
"""
import os, sys, subprocess, json, logging, struct, mmap, re
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
import psutil

logger = logging.getLogger('blueteam-memory')

class MemoryForensicsModule:
    """Production-grade memory forensics with real threat detection"""
    
    def __init__(self):
        self.volatility_available = self._check_volatility()
        self.yara_available = self._check_yara()
        self.shellcode_signatures = self._load_shellcode_signatures()
        self.pe_header_sig = b'MZ'
    
    def _check_volatility(self) -> bool:
        """Check if Volatility 3 is available"""
        try:
            result = subprocess.run(
                ['python3', '-m', 'volatility3', '--version'],
                capture_output=True, timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def _check_yara(self) -> bool:
        """Check if YARA is available"""
        try:
            import yara
            return True
        except:
            return False
    
    def _load_shellcode_signatures(self) -> Dict[str, bytes]:
        """Load shellcode detection patterns"""
        return {
            "x86_jmp_rip": b'\xff\x25',  # jmp [rip+offset]
            "x86_call_rip": b'\xff\x15',  # call [rip+offset]
            "x86_push_ret": b'\x68.*\xc3',  # push addr; ret
            "x86_xor_eax": b'\x31\xc0',  # xor eax, eax
            "x86_int_80": b'\xcd\x80',  # int 0x80
            "x64_syscall": b'\x0f\x05',  # syscall
            "pe_header": b'MZ',  # PE executable
        }
    
    def detect_process_injection(self) -> List[Dict[str, Any]]:
        """Detect process injection via memory analysis"""
        injections = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    pid = proc.pid
                    maps_file = f'/proc/{pid}/maps'
                    
                    if not os.path.exists(maps_file):
                        continue
                    
                    with open(maps_file, 'r') as f:
                        for line in f:
                            parts = line.split()
                            if len(parts) < 2:
                                continue
                            
                            perms = parts[1]
                            addr_range = parts[0]
                            
                            # Detect suspicious: writable + executable + anonymous
                            if 'w' in perms and 'x' in perms and '[anon]' in line:
                                try:
                                    # Read memory region
                                    start_addr = int(addr_range.split('-')[0], 16)
                                    mem_data = self._read_process_memory(pid, start_addr, 4096)
                                    
                                    if mem_data and self._contains_shellcode(mem_data):
                                        injections.append({
                                            "pid": pid,
                                            "name": proc.name(),
                                            "type": "process_injection",
                                            "address": addr_range,
                                            "permissions": perms,
                                            "severity": "critical",
                                            "description": "Writable executable region with shellcode detected",
                                            "timestamp": datetime.now().isoformat()
                                        })
                                except:
                                    pass
                
                except (PermissionError, FileNotFoundError, psutil.NoSuchProcess):
                    pass
        
        except Exception as e:
            logger.error(f"Process injection detection error: {e}")
        
        return injections
    
    def _read_process_memory(self, pid: int, address: int, size: int) -> Optional[bytes]:
        """Read process memory at address"""
        try:
            mem_file = f'/proc/{pid}/mem'
            with open(mem_file, 'rb') as f:
                f.seek(address)
                return f.read(size)
        except (PermissionError, OSError):
            return None
    
    def _contains_shellcode(self, data: bytes) -> bool:
        """Detect shellcode patterns in data"""
        try:
            # Check for common shellcode patterns
            for pattern_name, pattern in self.shellcode_signatures.items():
                if isinstance(pattern, bytes):
                    if pattern in data:
                        return True
                else:
                    if re.search(pattern, data):
                        return True
            
            # Check for PE headers in unexpected locations
            if self.pe_header_sig in data:
                return True
        except:
            pass
        
        return False
    
    def detect_process_hollowing(self) -> List[Dict[str, Any]]:
        """Detect process hollowing attacks"""
        hollowing_indicators = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    pid = proc.pid
                    exe = proc.exe()
                    
                    # Check if process image doesn't match disk
                    try:
                        with open(exe, 'rb') as f:
                            disk_header = f.read(4)
                        
                        # Read process memory header
                        mem_header = self._read_process_memory(pid, 0x400000, 4)
                        
                        if mem_header and disk_header != mem_header:
                            hollowing_indicators.append({
                                "pid": pid,
                                "name": proc.name(),
                                "type": "process_hollowing",
                                "severity": "critical",
                                "description": "Process image in memory differs from disk (hollowing indicator)",
                                "timestamp": datetime.now().isoformat()
                            })
                    except (PermissionError, FileNotFoundError):
                        pass
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        
        except Exception as e:
            logger.error(f"Process hollowing detection error: {e}")
        
        return hollowing_indicators
    
    def dump_process_memory(self, pid: int, output_dir: str = '/tmp') -> Dict[str, Any]:
        """Dump process memory for forensic analysis"""
        try:
            proc = psutil.Process(pid)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            dump_file = f'{output_dir}/memdump_{pid}_{timestamp}.bin'
            
            # Dump first 100MB or available
            with open(f'/proc/{pid}/mem', 'rb') as src:
                with open(dump_file, 'wb') as dst:
                    dst.write(src.read(100 * 1024 * 1024))
            
            return {
                "pid": pid,
                "name": proc.name(),
                "dump_file": dump_file,
                "size_bytes": os.path.getsize(dump_file),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Memory dump error: {e}")
            return {"error": str(e)}
    
    def analyze_memory_anomalies(self) -> List[Dict[str, Any]]:
        """Analyze memory allocation anomalies"""
        anomalies = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                try:
                    mem_info = proc.memory_info()
                    rss_mb = mem_info.rss / 1024 / 1024
                    vms_mb = mem_info.vms / 1024 / 1024
                    
                    # Flag processes with unusual memory patterns
                    if rss_mb > 1000:  # >1GB
                        anomalies.append({
                            "pid": proc.pid,
                            "name": proc.name(),
                            "rss_mb": round(rss_mb, 2),
                            "vms_mb": round(vms_mb, 2),
                            "type": "high_memory_usage",
                            "severity": "medium",
                            "timestamp": datetime.now().isoformat()
                        })
                    
                    # Flag processes with high VMS to RSS ratio (potential memory leak)
                    if vms_mb > 0 and (vms_mb / rss_mb) > 10:
                        anomalies.append({
                            "pid": proc.pid,
                            "name": proc.name(),
                            "vms_to_rss_ratio": round(vms_mb / rss_mb, 2),
                            "type": "memory_leak_indicator",
                            "severity": "low",
                            "timestamp": datetime.now().isoformat()
                        })
                
                except (PermissionError, psutil.NoSuchProcess):
                    pass
        
        except Exception as e:
            logger.error(f"Memory anomaly analysis error: {e}")
        
        return anomalies
    
    def detect_lsass_access(self) -> List[Dict[str, Any]]:
        """Detect unauthorized LSASS access attempts (Linux equivalent)"""
        findings = []
        
        try:
            # Check for processes accessing /etc/shadow or /etc/passwd
            result = subprocess.run(
                ['lsof', '+D', '/etc'],
                capture_output=True, text=True, timeout=10
            )
            
            sensitive_files = ['/etc/shadow', '/etc/passwd', '/etc/gshadow']
            for line in result.stdout.split('\n'):
                for sensitive in sensitive_files:
                    if sensitive in line:
                        parts = line.split()
                        if len(parts) > 1:
                            findings.append({
                                "type": "sensitive_file_access",
                                "file": sensitive,
                                "process": parts[0],
                                "severity": "high",
                                "description": f"Unauthorized access to {sensitive}",
                                "timestamp": datetime.now().isoformat()
                            })
        
        except Exception as e:
            logger.warning(f"LSASS access detection error: {e}")
        
        return findings
    
    def volatility_analyze(self, dump_file: str) -> Dict[str, Any]:
        """Analyze memory dump with Volatility 3"""
        if not self.volatility_available:
            return {"error": "Volatility 3 not available"}
        
        try:
            result = subprocess.run(
                ['python3', '-m', 'volatility3', '-f', dump_file, 'windows.pslist.PsList'],
                capture_output=True, text=True, timeout=30
            )
            
            return {
                "dump_file": dump_file,
                "analysis": result.stdout,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Volatility analysis error: {e}")
            return {"error": str(e)}
    
    def get_summary(self) -> Dict[str, Any]:
        """Get module summary"""
        return {
            "module": "Memory Forensics & Live Triage",
            "volatility_available": self.volatility_available,
            "yara_available": self.yara_available,
            "injections_detected": len(self.detect_process_injection()),
            "hollowing_detected": len(self.detect_process_hollowing()),
            "anomalies_detected": len(self.analyze_memory_anomalies()),
            "timestamp": datetime.now().isoformat()
        }

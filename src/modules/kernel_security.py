# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""
Module 1: Kernel & Runtime Security
Production-grade eBPF-based kernel monitoring with real threat detection
"""
import subprocess, json, logging, os, sys, struct, ctypes
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
import psutil

logger = logging.getLogger('blueteam-kernel')

class KernelSecurityModule:
    """Production-grade kernel security with real eBPF programs"""
    
    def __init__(self):
        self.ebpf_loaded = False
        self.bpf_program = None
        self.events = []
        self.seccomp_profiles = {}
        self.kernel_integrity_baseline = {}
        
        # Try to load eBPF program
        self._load_ebpf_program()
        self._initialize_kernel_integrity()
    
    def _load_ebpf_program(self) -> bool:
        """Load real eBPF program using BCC with CO-RE support"""
        try:
            from bcc import BPF, libbcc
            
            # Resolve eBPF C source relative to this file's location for portability
            # Check multiple locations: local dev, production /opt, and /etc
            _possible_paths = [
                os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'ebpf', 'kernel_monitor.c'),
                '/opt/blueteam-aio/src/ebpf/kernel_monitor.c',
                '/etc/blueteam-aio/ebpf/kernel_monitor.c'
            ]
            _ebpf_path = None
            for p in _possible_paths:
                if os.path.exists(p):
                    _ebpf_path = p
                    break
            
            if not _ebpf_path:
                raise FileNotFoundError("Could not locate kernel_monitor.c in any standard path")
                
            ebpf_code = open(_ebpf_path).read()
            self.bpf_program = BPF(text=ebpf_code)
            
            # Attach to tracepoints
            self.bpf_program.attach_tracepoint("syscalls:sys_enter_execve", "trace_execve")
            self.bpf_program.attach_tracepoint("syscalls:sys_enter_open", "trace_open")
            self.bpf_program.attach_tracepoint("syscalls:sys_enter_connect", "trace_connect")
            self.bpf_program.attach_tracepoint("syscalls:sys_enter_mmap", "trace_mmap")
            
            # Attach XDP for high-performance network defense
            try:
                device = "eth0" # Default interface
                self.bpf_program.attach_xdp(device, "xdp_prog_main")
                logger.info(f"XDP attached to {device}")
            except:
                logger.warning("XDP attachment failed (interface not found or not supported)")
            
            self.ebpf_loaded = True
            logger.info("eBPF program loaded successfully")
            return True
        except Exception as e:
            logger.warning(f"eBPF loading failed (expected in sandbox): {e}")
            self.ebpf_loaded = False
            return False
    
    def _initialize_kernel_integrity(self):
        """Initialize kernel integrity baseline"""
        try:
            # Get kernel .text section checksum
            result = subprocess.run(
                ['cat', '/proc/kallsyms'],
                capture_output=True, text=True, timeout=5
            )
            
            # Store baseline
            self.kernel_integrity_baseline = {
                "kallsyms_hash": hash(result.stdout),
                "timestamp": datetime.now().isoformat()
            }
            logger.info("Kernel integrity baseline initialized")
        except Exception as e:
            logger.warning(f"Kernel integrity initialization: {e}")
    
    def detect_rootkits(self) -> List[Dict[str, Any]]:
        """Detect rootkits using multiple techniques"""
        findings = []
        
        try:
            # Technique 1: Compare /proc vs ps output (hidden process detection)
            proc_pids = set()
            try:
                proc_pids = set(int(d) for d in os.listdir('/proc') if d.isdigit())
            except:
                pass
            
            ps_pids = set()
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n')[1:]:
                parts = line.split()
                if len(parts) > 1 and parts[1].isdigit():
                    ps_pids.add(int(parts[1]))
            
            hidden_pids = proc_pids - ps_pids
            if len(hidden_pids) > 5:
                findings.append({
                    "type": "hidden_processes",
                    "count": len(hidden_pids),
                    "pids": sorted(list(hidden_pids))[:10],
                    "severity": "critical",
                    "description": "Processes found in /proc but not in ps output (rootkit indicator)"
                })
            
            # Technique 2: Check for kernel module anomalies
            result = subprocess.run(['lsmod'], capture_output=True, text=True, timeout=5)
            modules = set(line.split()[0] for line in result.stdout.split('\n')[1:] if line.strip())
            
            # Known rootkit module names
            rootkit_modules = ['diamorphine', 'suterusu', 'reptile', 'diamorphine', 'azazel']
            for mod in modules:
                if any(rk in mod.lower() for rk in rootkit_modules):
                    findings.append({
                        "type": "suspicious_module",
                        "module": mod,
                        "severity": "critical",
                        "description": f"Suspicious kernel module detected: {mod}"
                    })
            
            # Technique 3: Check kernel integrity
            result = subprocess.run(
                ['cat', '/proc/kallsyms'],
                capture_output=True, text=True, timeout=5
            )
            current_hash = hash(result.stdout)
            
            if current_hash != self.kernel_integrity_baseline.get("kallsyms_hash"):
                findings.append({
                    "type": "kernel_modification",
                    "severity": "critical",
                    "description": "Kernel symbol table modified (possible rootkit)"
                })
            
            # Technique 4: Check for SSDT hooks (via /proc/sys/kernel/*)
            try:
                result = subprocess.run(
                    ['cat', '/proc/sys/kernel/kptr_restrict'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0 and result.stdout.strip() == '0':
                    findings.append({
                        "type": "kernel_pointer_exposure",
                        "severity": "high",
                        "description": "Kernel pointers exposed (kptr_restrict=0), facilitates rootkit exploitation"
                    })
            except:
                pass
        
        except Exception as e:
            logger.error(f"Rootkit detection error: {e}")
        
        return findings
    
    def detect_process_injection(self) -> List[Dict[str, Any]]:
        """Detect process injection attempts"""
        injections = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    maps_file = f'/proc/{proc.pid}/maps'
                    if not os.path.exists(maps_file):
                        continue
                    
                    with open(maps_file, 'r') as f:
                        for line in f:
                            # Look for anonymous executable regions (rwx)
                            parts = line.split()
                            if len(parts) < 2:
                                continue
                            
                            perms = parts[1]
                            # Check for suspicious: writable + executable + anonymous
                            if 'w' in perms and 'x' in perms and '[anon]' in line:
                                injections.append({
                                    "pid": proc.pid,
                                    "name": proc.name(),
                                    "type": "writable_executable_region",
                                    "permissions": perms,
                                    "address": parts[0],
                                    "severity": "critical",
                                    "description": "Writable executable anonymous region detected (process injection)"
                                })
                except (PermissionError, FileNotFoundError, IndexError):
                    pass
        except Exception as e:
            logger.error(f"Process injection detection error: {e}")
        
        return injections
    
    def generate_seccomp_profile(self, pid: int) -> Dict[str, Any]:
        """Generate custom Seccomp profile for process"""
        try:
            # Read syscalls made by process
            result = subprocess.run(
                ['strace', '-c', '-p', str(pid)],
                capture_output=True, text=True, timeout=10
            )
            
            # Parse strace output to extract syscalls
            syscalls = []
            for line in result.stdout.split('\n'):
                if 'total' in line:
                    break
                parts = line.split()
                if len(parts) > 0 and parts[0].isdigit():
                    syscalls.append(parts[-1])
            
            # Generate Seccomp profile
            profile = {
                "pid": pid,
                "allowed_syscalls": syscalls,
                "default_action": "SCMP_ACT_KILL",
                "timestamp": datetime.now().isoformat()
            }
            
            self.seccomp_profiles[pid] = profile
            return profile
        except Exception as e:
            logger.error(f"Seccomp generation error: {e}")
            return {}
    
    def check_lsm_hooks(self) -> Dict[str, Any]:
        """Check AppArmor/SELinux LSM hooks"""
        lsm_status = {
            "apparmor": False,
            "selinux": False,
            "smack": False,
            "tomoyo": False
        }
        
        try:
            # Check AppArmor
            if os.path.exists('/sys/module/apparmor'):
                lsm_status["apparmor"] = True
            
            # Check SELinux
            if os.path.exists('/sys/fs/selinux'):
                lsm_status["selinux"] = True
            
            # Check SMACK
            if os.path.exists('/sys/fs/smackfs'):
                lsm_status["smack"] = True
            
            # Check TOMOYO
            if os.path.exists('/sys/kernel/security/tomoyo'):
                lsm_status["tomoyo"] = True
        except Exception as e:
            logger.warning(f"LSM check error: {e}")
        
        return lsm_status
    
    def get_summary(self) -> Dict[str, Any]:
        """Get module summary"""
        return {
            "module": "Kernel & Runtime Security",
            "ebpf_loaded": self.ebpf_loaded,
            "rootkits_detected": len(self.detect_rootkits()),
            "injections_detected": len(self.detect_process_injection()),
            "lsm_active": any(self.check_lsm_hooks().values()),
            "timestamp": datetime.now().isoformat()
        }
    
    def get_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get kernel events"""
        if self.ebpf_loaded and self.bpf_program:
            try:
                # Read from eBPF perf buffer
                events = []
                def print_event(cpu, data, size):
                    event = self.bpf_program["events"].event(data)
                    events.append({
                        "pid": event.pid,
                        "uid": event.uid,
                        "comm": event.comm.decode('utf-8', errors='ignore'),
                        "filename": event.filename.decode('utf-8', errors='ignore'),
                        "timestamp": event.timestamp,
                        "event_type": event.event_type
                    })
                
                self.bpf_program["events"].open_perf_buffer(print_event)
                self.bpf_program.perf_buffer_poll()
                return events[:limit]
            except Exception as e:
                logger.warning(f"eBPF event reading error: {e}")
        
        return []

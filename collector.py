import os
import sys
import psutil
import json
import socket
import datetime
import subprocess
import shutil
import ctypes
import sqlite3
import hashlib
import winreg
import base64
import time
import glob
import struct
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple

from Crypto.Cipher import AES
import win32crypt
import win32security
import win32api
import win32con
import win32process

# ==========================================
# COLLECTOR VERSION & CONFIG
# ==========================================

COLLECTOR_VERSION = "2.0.0"

@dataclass
class CollectorConfig:
    """Configurable collection options."""
    collect_ram: bool = True
    collect_mft: bool = True
    collect_srum: bool = True
    process_signature_check: bool = True
    max_file_hash_size_mb: int = 10
    recent_files_days: int = 30
    max_browser_history: int = 500
    max_event_logs: int = 3000


# ==========================================
# UTILITIES
# ==========================================

def utc_now() -> datetime.datetime:
    """Get current UTC time (timezone-aware)."""
    return datetime.datetime.now(datetime.timezone.utc)


def to_utc_str(dt: datetime.datetime = None, fmt: str = "%Y-%m-%d %H:%M:%S UTC") -> str:
    """Convert datetime to UTC string format."""
    if dt is None:
        dt = utc_now()
    # Remove timezone info for formatting if present
    if dt.tzinfo is not None:
        dt = dt.replace(tzinfo=None)
    return dt.strftime(fmt)


def timestamp_from_epoch(epoch_seconds: float) -> str:
    """Convert epoch seconds to UTC timestamp string."""
    try:
        dt = datetime.datetime.fromtimestamp(epoch_seconds, datetime.timezone.utc)
        return to_utc_str(dt)
    except (ValueError, OSError):
        return "Unknown"


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def get_base_path():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def impersonate_logged_on_user():
    """Find logged-on user and impersonate for DPAPI decryption."""
    try:
        current_session_id = win32api.WTSGetActiveConsoleSessionId()
        processes = win32process.EnumProcesses()
        target_pid = None
        for pid in processes:
            try:
                handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
                if win32process.ProcessIdToSessionId(pid) == current_session_id:
                    if "explorer.exe" in win32process.GetModuleFileNameEx(handle, 0).lower():
                        target_pid = pid
                        win32api.CloseHandle(handle)
                        break
                win32api.CloseHandle(handle)
            except Exception:
                continue
        if not target_pid:
            return False
        h_process = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, target_pid)
        h_token = win32security.OpenProcessToken(h_process, win32con.TOKEN_DUPLICATE | win32con.TOKEN_QUERY)
        duplicate_token = win32security.DuplicateTokenEx(
            h_token, win32security.SecurityImpersonation,
            win32con.TOKEN_ALL_ACCESS, win32security.TokenImpersonation
        )
        win32security.ImpersonateLoggedOnUser(duplicate_token)
        win32api.CloseHandle(h_token)
        win32api.CloseHandle(duplicate_token)
        win32api.CloseHandle(h_process)
        return True
    except Exception:
        return False


def stop_impersonation():
    try:
        win32security.RevertToSelf()
    except Exception:
        pass


# ==========================================
# FORENSIC COLLECTOR CLASS
# ==========================================

class ForensicCollector:
    def __init__(self, config: CollectorConfig = None):
        self.config = config or CollectorConfig()
        self.base_path = get_base_path()
        self.hostname = socket.gethostname()
        self.start_time = utc_now()  # Use UTC for all timestamps
        timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
        self.output_dir = os.path.join(self.base_path, f"Evidence_{self.hostname}_{timestamp}")

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        self.log_file = os.path.join(self.output_dir, "collection.log")
        self.error_file = os.path.join(self.output_dir, "errors.log")
        self.hash_list = []
        self.phase_timings = []
        self.current_phase = 0
        self.total_phases = 12

        # Signature cache for batch verification
        self._signature_cache: Dict[str, Tuple[str, str]] = {}

        self._print_banner()

    def _print_banner(self):
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║       FORENSIC EVIDENCE COLLECTOR v{COLLECTOR_VERSION}                    ║
║       Production-Ready IR Triage Tool                        ║
╠══════════════════════════════════════════════════════════════╣
║  Host: {self.hostname:<52} ║
║  Output: {self.output_dir:<50} ║
╚══════════════════════════════════════════════════════════════╝
        """)

    def log(self, msg: str):
        ts = utc_now().strftime("%H:%M:%S")
        print(f"[{ts} UTC] {msg}")
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(f"[{ts} UTC] {msg}\n")
        except Exception:
            pass

    def log_phase(self, phase_name: str):
        """Log phase with progress indicator."""
        self.current_phase += 1
        phase_start = utc_now()
        progress = f"[{self.current_phase}/{self.total_phases}]"
        self.log(f"{progress} {phase_name}")
        return phase_start

    def log_phase_complete(self, phase_name: str, phase_start: datetime.datetime):
        """Log phase completion with timing."""
        elapsed = (utc_now() - phase_start).total_seconds()
        self.phase_timings.append({"phase": phase_name, "duration_sec": round(elapsed, 2)})
        self.log(f"    ✓ Completed in {elapsed:.1f}s")

    def log_error(self, func_name: str, error_msg: str):
        ts = utc_now().strftime("%H:%M:%S")
        full_msg = f"[{ts} UTC] [ERROR] in {func_name}: {error_msg}"
        print(full_msg)
        try:
            with open(self.error_file, "a", encoding="utf-8") as f:
                f.write(full_msg + "\n")
        except Exception:
            pass

    def calculate_hash(self, file_path: str, add_to_evidence_list: bool = True) -> str:
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
            file_hash = sha256.hexdigest()

            if add_to_evidence_list:
                # Deduplicate - check if this path was already hashed
                existing_paths = {h.get("Path") for h in self.hash_list}
                if file_path not in existing_paths:
                    self.hash_list.append({
                        "Filename": os.path.basename(file_path),
                        "Path": file_path,
                        "SHA256": file_hash
                    })
            return file_hash
        except Exception as e:
            return f"Error hashing: {str(e)}"

    def forensic_copy(self, src: str, dst: str) -> bool:
        """Copy file with fallback to esentutl for locked files."""
        if not os.path.exists(src):
            return False
        try:
            shutil.copy2(src, dst)
            return True
        except Exception:
            try:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                subprocess.run(f'esentutl /y "{src}" /d "{dst}" /o', shell=True,
                              capture_output=True, startupinfo=si)
                return os.path.exists(dst)
            except Exception:
                return False

    def save_json(self, filename: str, data):
        try:
            full_path = os.path.join(self.output_dir, filename)
            with open(full_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str, ensure_ascii=False)
            self.calculate_hash(full_path)
        except Exception as e:
            self.log_error(f"save_json({filename})", str(e))

    def run_powershell(self, script_block: str, timeout: int = 60) -> list:
        wrapper = f"""
        $Output = & {{ {script_block} }}
        if ($Output) {{ $Output | ConvertTo-Json -Depth 3 -Compress }} else {{ Write-Output '[]' }}
        """
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", wrapper],
                capture_output=True, text=True, encoding='utf-8',
                errors='replace', startupinfo=si, timeout=timeout
            )
            if res.stdout.strip():
                try:
                    data = json.loads(res.stdout)
                    if isinstance(data, dict):
                        return [data]
                    return data
                except json.JSONDecodeError:
                    return []
            return []
        except subprocess.TimeoutExpired:
            self.log_error("run_powershell", "Timeout expired")
            return []
        except Exception as e:
            self.log_error("run_powershell", str(e))
            return []

    # ==========================================
    # BATCH SIGNATURE VERIFICATION (PERFORMANCE)
    # ==========================================

    def batch_signature_check(self, exe_paths: List[str]) -> Dict[str, Tuple[str, str]]:
        """Check signatures for multiple files in ONE PowerShell call."""
        if not exe_paths:
            return {}

        # Filter valid paths and deduplicate
        valid_paths = list(set(p for p in exe_paths if p and os.path.exists(p)))
        if not valid_paths:
            return {}

        # Build PowerShell array
        paths_array = ",".join([f'"{p}"' for p in valid_paths[:200]])  # Limit to 200

        script = f"""
        $paths = @({paths_array})
        $results = @()
        foreach ($p in $paths) {{
            try {{
                $sig = Get-AuthenticodeSignature $p -ErrorAction SilentlyContinue
                $status = if ($sig) {{ $sig.Status.ToString() }} else {{ "Unknown" }}
                $signer = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Subject }} else {{ "N/A" }}
                if ($signer -match 'CN=([^,]+)') {{ $signer = $Matches[1] }}
                $results += [PSCustomObject]@{{ Path=$p; Status=$status; Signer=$signer }}
            }} catch {{
                $results += [PSCustomObject]@{{ Path=$p; Status="Error"; Signer="N/A" }}
            }}
        }}
        $results
        """

        results = self.run_powershell(script, timeout=120)

        sig_dict = {}
        for r in results:
            if isinstance(r, dict) and 'Path' in r:
                sig_dict[r['Path']] = (r.get('Status', 'Unknown'), r.get('Signer', 'N/A'))

        # Cache results
        self._signature_cache.update(sig_dict)
        return sig_dict

    def get_signature_cached(self, file_path: str) -> Tuple[str, str]:
        """Get signature from cache or return unknown."""
        return self._signature_cache.get(file_path, ("Unknown", "N/A"))

    # ==========================================
    # PHASE 1: VOLATILE DATA (RAM, Network, Processes)
    # ==========================================

    def collect_ram_dump(self):
        phase_start = self.log_phase("RAM Dump (Magnet DumpIt)...")
        tool = os.path.join(self.base_path, "tools", "DumpIt.exe")
        dump_path = os.path.join(self.output_dir, "memdump.raw")

        if not self.config.collect_ram:
            self.log("    ⊘ Skipped (disabled in config)")
            return

        if os.path.exists(tool):
            try:
                cmd = [tool, "/O", dump_path, "/Q"]
                subprocess.run(cmd, input=b'y', check=True, timeout=300)
                if os.path.exists(dump_path):
                    self.log("    Hashing RAM Dump...")
                    self.calculate_hash(dump_path)
            except Exception as e:
                self.log_error("collect_ram_dump", str(e))
        else:
            self.log("    ⊘ DumpIt.exe not found in tools/")

        self.log_phase_complete("RAM Dump", phase_start)

    def collect_live_data(self):
        phase_start = self.log_phase("Live Data (Processes, Network, ARP, Hosts)...")

        # Collect process list first
        procs = []
        exe_paths = []
        pid_to_name = {}

        try:
            for p in psutil.process_iter(['pid', 'name']):
                pid_to_name[p.info['pid']] = p.info['name']
        except Exception:
            pass

        try:
            for p in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'cmdline', 'create_time', 'exe']):
                try:
                    i = p.info

                    if i['create_time']:
                        i['create_time'] = timestamp_from_epoch(i['create_time'])

                    cmd = i.get('cmdline')
                    i['cmdline'] = " ".join(cmd) if isinstance(cmd, list) else (str(cmd) if cmd else "")
                    i['parent_pid'] = i['ppid']
                    i['parent_name'] = pid_to_name.get(i['ppid'], "Unknown/Exited")

                    exe_path = i.get('exe')
                    if exe_path and os.path.exists(exe_path):
                        i['sha256'] = self.calculate_hash(exe_path, add_to_evidence_list=False)
                        exe_paths.append(exe_path)

                    # Collect loaded modules (limit to non-system for performance)
                    try:
                        i['loaded_modules'] = [m.path for m in p.memory_maps()][:50]
                    except Exception:
                        i['loaded_modules'] = []

                    procs.append(i)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            # Batch signature verification
            if self.config.process_signature_check and exe_paths:
                self.log("    Verifying signatures (batch)...")
                self.batch_signature_check(exe_paths)

                # Apply signatures to processes
                for proc in procs:
                    exe = proc.get('exe')
                    if exe:
                        status, publisher = self.get_signature_cached(exe)
                        proc['SignatureStatus'] = status
                        proc['Publisher'] = publisher

            self.save_json("processes.json", procs)
        except Exception as e:
            self.log_error("collect_live_data_procs", str(e))

        # Network connections
        net = []
        try:
            for c in psutil.net_connections(kind='inet'):
                net.append({
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                    "status": c.status,
                    "pid": c.pid
                })
            self.save_json("network_connections.json", net)
        except Exception as e:
            self.log_error("collect_live_data_net", str(e))

        # ARP table
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            arp_out = subprocess.check_output("arp -a", shell=True, startupinfo=si).decode('cp1252', errors='ignore')
            self.save_json("arp_table.json", [{"raw_content": arp_out}])
        except Exception as e:
            self.log_error("collect_arp", str(e))

        # Hosts file
        try:
            hosts_src = r"C:\Windows\System32\drivers\etc\hosts"
            if os.path.exists(hosts_src):
                hosts_dst = os.path.join(self.output_dir, "hosts_file_backup")
                shutil.copy2(hosts_src, hosts_dst)
                self.calculate_hash(hosts_dst)
        except Exception as e:
            self.log_error("collect_hosts", str(e))

        self.log_phase_complete("Live Data", phase_start)

    # ==========================================
    # PHASE 2: PERSISTENCE MECHANISMS
    # ==========================================

    def _read_registry_key(self, hive, path: str, category: str) -> list:
        results = []
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        results.append({
                            "Category": category,
                            "Hive": "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU",
                            "Path": path,
                            "Name": name,
                            "Value": str(value)[:500]
                        })
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        except Exception as e:
            self.log_error(f"RegRead({path})", str(e))
        return results

    def collect_persistence(self):
        phase_start = self.log_phase("Persistence (Registry, Tasks, Services, WMI, Startup)...")

        # Scheduled Tasks
        self.save_json("scheduled_tasks.json", self.run_powershell(
            "Get-ScheduledTask | Select TaskName, TaskPath, State, @{N='Action';E={$_.Actions.Execute}}, @{N='Author';E={$_.Principal.UserId}}"
        ))

        # Registry autoruns
        reg_data = []
        run_paths = [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunServices",
            r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        ]

        for p in run_paths:
            reg_data += self._read_registry_key(winreg.HKEY_LOCAL_MACHINE, p, "Autorun")
            reg_data += self._read_registry_key(winreg.HKEY_CURRENT_USER, p, "Autorun")

        # Winlogon
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                               0, winreg.KEY_READ) as key:
                for val in ["Userinit", "Shell", "Taskman"]:
                    try:
                        v, _ = winreg.QueryValueEx(key, val)
                        reg_data.append({"Category": "Winlogon", "Name": val, "Value": str(v)})
                    except Exception:
                        pass
        except Exception:
            pass

        # IFEO (Image File Execution Options)
        ifeo_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ifeo_path, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            try:
                                dbg, _ = winreg.QueryValueEx(subkey, "Debugger")
                                reg_data.append({"Category": "IFEO Debugger", "Name": subkey_name, "Value": str(dbg)})
                            except Exception:
                                pass
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass

        self.save_json("registry_autoruns.json", reg_data)

        # Services
        self.collect_services()

        # WMI Persistence
        self.collect_wmi_persistence()

        # Startup Folders
        self.collect_startup_folders()

        self.log_phase_complete("Persistence", phase_start)

    def collect_services(self):
        services = []
        try:
            for s in psutil.win_service_iter():
                try:
                    s_info = s.as_dict()
                    service_data = {
                        "Name": s_info.get('name'),
                        "DisplayName": s_info.get('display_name'),
                        "Status": s_info.get('status'),
                        "StartType": s_info.get('start_type'),
                        "BinPath": s_info.get('binpath'),
                        "Username": s_info.get('username'),
                        "Description": s_info.get('description')
                    }

                    bin_path = s_info.get('binpath')
                    if bin_path:
                        clean_path = bin_path.split('.exe')[0] + '.exe' if '.exe' in bin_path.lower() else bin_path
                        clean_path = clean_path.strip('"').strip()
                        if os.path.exists(clean_path):
                            service_data["SHA256"] = self.calculate_hash(clean_path, add_to_evidence_list=False)

                    services.append(service_data)
                except Exception:
                    continue

            self.save_json("services_list.json", services)
        except Exception as e:
            self.log_error("collect_services", str(e))

    def collect_wmi_persistence(self):
        """Collect WMI Event Subscriptions (common malware persistence)."""
        wmi_script = """
        $results = @()
        try {
            $filters = Get-WmiObject -Namespace root\\subscription -Class __EventFilter -ErrorAction SilentlyContinue
            $consumers = Get-WmiObject -Namespace root\\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
            $bindings = Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue

            foreach ($f in $filters) {
                $results += [PSCustomObject]@{Type="EventFilter"; Name=$f.Name; Query=$f.Query}
            }
            foreach ($c in $consumers) {
                $cmd = if ($c.CommandLineTemplate) { $c.CommandLineTemplate } else { $c.ScriptText }
                $results += [PSCustomObject]@{Type="EventConsumer"; Name=$c.Name; Command=$cmd}
            }
            foreach ($b in $bindings) {
                $results += [PSCustomObject]@{Type="Binding"; Filter=$b.Filter; Consumer=$b.Consumer}
            }
        } catch {}
        $results
        """
        self.save_json("wmi_persistence.json", self.run_powershell(wmi_script))

    def collect_startup_folders(self):
        """Enumerate startup folder contents."""
        startup_files = []
        startup_paths = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        ]

        for startup_path in startup_paths:
            if os.path.exists(startup_path):
                for f in os.listdir(startup_path):
                    fp = os.path.join(startup_path, f)
                    try:
                        stat = os.stat(fp)
                        startup_files.append({
                            "Path": fp,
                            "Filename": f,
                            "Size": stat.st_size,
                            "Modified": timestamp_from_epoch(stat.st_mtime),
                            "SHA256": self.calculate_hash(fp, add_to_evidence_list=False) if stat.st_size < 10*1024*1024 else "Too Large"
                        })
                    except Exception:
                        continue

        self.save_json("startup_files.json", startup_files)

    # ==========================================
    # PHASE 3: EXECUTION ARTIFACTS
    # ==========================================

    def collect_execution_artifacts(self):
        phase_start = self.log_phase("Execution Artifacts (Shimcache, Amcache, UserAssist, Prefetch)...")

        # Shimcache
        self.collect_shimcache()

        # Amcache
        self.collect_amcache()

        # UserAssist
        ua_script = """
        $Results = @()
        $UAPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
        if (Test-Path $UAPath) {
            Get-ChildItem $UAPath | ForEach-Object {
                $CountKey = Join-Path $_.PSPath "Count"
                if (Test-Path $CountKey) {
                    Get-ItemProperty $CountKey | ForEach-Object {
                        $_.PSObject.Properties | Where-Object { $_.Name -ne "PSPath" -and $_.Name -ne "PSParentPath" -and $_.Name -ne "PSChildName" -and $_.Name -ne "PSDrive" -and $_.Name -ne "PSProvider" } | ForEach-Object {
                            $n=$_.Name.ToCharArray()
                            for($i=0;$i -lt $n.Length;$i++){
                                $c=[int]$n[$i]
                                if(($c-ge97-and$c-le109)-or($c-ge65-and$c-le77)){$n[$i]=[char]($c+13)}
                                elseif(($c-ge110-and$c-le122)-or($c-ge78-and$c-le90)){$n[$i]=[char]($c-13)}
                            }
                            $dec=-join $n
                            $b=$_.Value; $d="Unknown"; $cnt=0
                            if ($b -is [byte[]] -and $b.Length -ge 68) {
                                try { $d=[DateTime]::FromFileTime([BitConverter]::ToInt64($b, 60)).ToString("yyyy-MM-dd HH:mm:ss") } catch {}
                                try { $cnt=[BitConverter]::ToInt32($b, 4) } catch {}
                            }
                            if ($dec -match '\\\\|:') { $Results += [PSCustomObject]@{ Program=$dec; LastRun=$d; RunCount=$cnt } }
                        }
                    }
                }
            }
        }
        $Results
        """
        self.save_json("user_assist.json", self.run_powershell(ua_script))

        # Prefetch
        pf_script = """
        Get-ChildItem "C:\\Windows\\Prefetch\\*.pf" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 200 |
        Select-Object Name, @{N='LastRun';E={$_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")}},
        @{N='Created';E={$_.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")}}, Length
        """
        self.save_json("prefetch_list.json", self.run_powershell(pf_script))

        # LNK files
        lnk_script = """
        $Shell = New-Object -ComObject WScript.Shell
        Get-ChildItem "$env:APPDATA\\Microsoft\\Windows\\Recent\\*.lnk" -ErrorAction SilentlyContinue |
        Select-Object -First 100 | ForEach-Object {
            try {
                $Target = $Shell.CreateShortcut($_.FullName).TargetPath
                [PSCustomObject]@{ Name=$_.Name; Target=$Target; LastAccess=$_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") }
            } catch {}
        }
        """
        self.save_json("lnk_files.json", self.run_powershell(lnk_script))

        # PowerShell History
        self.collect_powershell_history()

        self.log_phase_complete("Execution Artifacts", phase_start)

    def collect_shimcache(self):
        """Extract Shimcache (AppCompatCache) from registry using PowerShell."""
        shimcache_entries = []

        try:
            # Use PowerShell to parse AppCompatCache - more reliable across Windows versions
            ps_script = r'''
$ErrorActionPreference = 'SilentlyContinue'

# Get AppCompatCache binary data from registry
$regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
$data = (Get-ItemProperty -Path $regPath -Name AppCompatCache).AppCompatCache

if (-not $data) { exit }

$results = @()
$signature = [BitConverter]::ToUInt32($data, 0)

# Windows 10/11 format with signature 0x30, 0x34, or 0x80
if ($signature -eq 0x30 -or $signature -eq 0x34 -or $signature -eq 0x80) {
    # For Win10 with signature 0x34, entries start at offset 0x34
    # Each entry has: "10ts" signature (4) + unknown (4) + data_size (4) + path_len (2) + path

    $offset = $signature  # Header size equals signature value
    $position = 0
    $entrySig = 0x73743031  # "10ts" in little-endian

    while ($offset -lt ($data.Length - 20) -and $position -lt 1024) {
        try {
            $currentSig = [BitConverter]::ToUInt32($data, $offset)

            if ($currentSig -eq $entrySig) {
                # Valid entry found
                $dataSize = [BitConverter]::ToUInt32($data, $offset + 8)
                $pathLen = [BitConverter]::ToUInt16($data, $offset + 12)

                if ($pathLen -gt 0 -and $pathLen -lt 1024 -and ($offset + 14 + $pathLen) -le $data.Length) {
                    $pathBytes = New-Object byte[] $pathLen
                    [Array]::Copy($data, $offset + 14, $pathBytes, 0, $pathLen)
                    $path = [System.Text.Encoding]::Unicode.GetString($pathBytes).TrimEnd([char]0)

                    if ($path -and $path.Length -gt 3 -and $path -match '^[A-Za-z]:\\') {
                        $results += [PSCustomObject]@{
                            path = $path
                            position = $position
                        }
                        $position++
                    }
                }

                # Move to next entry using data size
                if ($dataSize -gt 0 -and $dataSize -lt 10000) {
                    $offset += $dataSize
                } else {
                    $offset += 4
                }
            } else {
                $offset += 4
            }
        } catch {
            $offset += 4
        }
    }
}

# Fallback: regex-based path extraction if structured parsing failed
if ($results.Count -eq 0) {
    $text = [System.Text.Encoding]::Unicode.GetString($data)

    # Match valid Windows paths, stopping at control characters
    $pattern = '([A-Za-z]:\\(?:[^\\/:*?"<>|\x00-\x1F]+\\)*[^\\/:*?"<>|\x00-\x1F]+\.[a-zA-Z0-9]{1,10})'
    $matches = [regex]::Matches($text, $pattern)

    $seen = @{}
    $position = 0

    foreach ($match in $matches) {
        $path = $match.Value
        $pathLower = $path.ToLower()

        if (-not $seen.ContainsKey($pathLower) -and $path.Length -gt 5 -and $path.Length -lt 500) {
            $seen[$pathLower] = $true
            $results += [PSCustomObject]@{
                path = $path
                position = $position
            }
            $position++
        }

        if ($position -ge 1024) { break }
    }
}

$results | ConvertTo-Json -Depth 3
'''

            result = subprocess.run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
                capture_output=True, text=True, timeout=60
            )

            if result.stdout.strip():
                try:
                    parsed = json.loads(result.stdout)
                    if isinstance(parsed, dict):
                        parsed = [parsed]
                    shimcache_entries = parsed
                except json.JSONDecodeError:
                    pass

            # If PowerShell approach failed, try Python binary parsing as fallback
            if not shimcache_entries:
                shimcache_entries = self._parse_shimcache_binary()

        except Exception as e:
            self.log_error("collect_shimcache", str(e))
            # Try Python fallback
            try:
                shimcache_entries = self._parse_shimcache_binary()
            except Exception as e2:
                self.log_error("collect_shimcache_fallback", str(e2))

        self.save_json("shimcache.json", shimcache_entries)

    def _parse_shimcache_binary(self):
        """Fallback Python parser for AppCompatCache."""
        entries = []

        try:
            reg_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_READ) as key:
                data, _ = winreg.QueryValueEx(key, "AppCompatCache")

                if len(data) < 128:
                    return entries

                # Extract paths using regex pattern matching on Unicode strings
                # This is more reliable than trying to parse the exact binary format
                text = data.decode('utf-16-le', errors='ignore')

                import re
                # Match Windows file paths
                pattern = r'([A-Za-z]:\\(?:[^<>:"/\\|?*\x00-\x1F]+\\)*[^<>:"/\\|?*\x00-\x1F]+)'
                matches = re.findall(pattern, text)

                seen = set()
                position = 0

                for path in matches:
                    path = path.strip()
                    # Filter valid looking paths
                    if (len(path) > 5 and
                        len(path) < 500 and
                        path.lower() not in seen and
                        not any(c in path for c in '<>"|?*')):

                        seen.add(path.lower())
                        entries.append({
                            "path": path,
                            "position": position
                        })
                        position += 1

                        if position >= 1024:
                            break

        except Exception as e:
            self.log_error("_parse_shimcache_binary", str(e))

        return entries

    def collect_amcache(self):
        """Copy Amcache.hve for offline analysis."""
        amcache_path = r"C:\Windows\AppCompat\Programs\Amcache.hve"
        dst = os.path.join(self.output_dir, "Amcache.hve")

        if self.forensic_copy(amcache_path, dst):
            self.calculate_hash(dst)
        else:
            # Try via reg.exe
            try:
                subprocess.run(
                    ['reg', 'save', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppCompatCache', dst],
                    capture_output=True, timeout=30
                )
            except Exception as e:
                self.log_error("collect_amcache", str(e))

    def collect_powershell_history(self):
        base_users = r"C:\Users"
        dest_dir = os.path.join(self.output_dir, "PowerShell_History")
        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir)

        if os.path.exists(base_users):
            for user in os.listdir(base_users):
                ps_history_path = os.path.join(
                    base_users, user,
                    r"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
                )
                if os.path.exists(ps_history_path):
                    try:
                        dest_file = os.path.join(dest_dir, f"{user}_ConsoleHost_history.txt")
                        shutil.copy2(ps_history_path, dest_file)
                        self.calculate_hash(dest_file)
                    except Exception as e:
                        self.log_error(f"PSHistory({user})", str(e))

    # ==========================================
    # PHASE 4: USB & EXTERNAL DEVICES
    # ==========================================

    def collect_usb_artifacts(self):
        phase_start = self.log_phase("USB & External Devices...")

        # SetupAPI log
        try:
            setupapi_path = r"C:\Windows\inf\setupapi.dev.log"
            if os.path.exists(setupapi_path):
                dest = os.path.join(self.output_dir, "setupapi.dev.log")
                shutil.copy2(setupapi_path, dest)
                self.calculate_hash(dest)
        except Exception as e:
            self.log_error("collect_setupapi", str(e))

        # USB Registry
        usb_reg_script = """
        $results = @()
        try {
            Get-ChildItem "HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR" -Recurse -ErrorAction SilentlyContinue |
            ForEach-Object {
                $friendly = $_.GetValue("FriendlyName")
                if ($friendly) {
                    $results += [PSCustomObject]@{
                        DeviceName = $friendly
                        Serial = $_.PSChildName
                        RegistryPath = $_.Name
                    }
                }
            }
        } catch {}
        $results
        """
        self.save_json("usb_history_reg.json", self.run_powershell(usb_reg_script))

        # USB Events
        usb_evt_script = """
        $Events = @()
        $TargetLog = "Microsoft-Windows-DriverFrameworks-UserMode/Operational"
        try {
            if (Get-WinEvent -ListLog $TargetLog -ErrorAction SilentlyContinue) {
                $Events = Get-WinEvent -LogName $TargetLog -MaxEvents 100 -ErrorAction SilentlyContinue |
                Where-Object { $_.Id -in @(2003, 2004, 2005, 2100, 2101, 2102) } |
                Select-Object @{N='Time';E={$_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")}},
                Id, @{N='Message';E={$_.Message.Substring(0, [Math]::Min(200, $_.Message.Length))}}
            }
        } catch {}
        $Events | Sort-Object Time -Descending
        """
        self.save_json("usb_events.json", self.run_powershell(usb_evt_script))

        self.log_phase_complete("USB Artifacts", phase_start)

    # ==========================================
    # PHASE 5: FILE SYSTEM ARTIFACTS
    # ==========================================

    def collect_filesystem_artifacts(self):
        phase_start = self.log_phase("File System Artifacts (MFT, SRUM, Jump Lists, Recent Files)...")

        # $MFT
        if self.config.collect_mft:
            self.collect_mft()

        # SRUM
        if self.config.collect_srum:
            self.collect_srum()

        # Jump Lists
        self.collect_jump_lists()

        # Recent Files
        self.collect_recent_files()

        # Shellbags
        self.collect_shellbags()

        self.log_phase_complete("File System Artifacts", phase_start)

    def collect_mft(self):
        """Extract $MFT using multiple methods."""
        mft_dst = os.path.join(self.output_dir, "$MFT")

        # Method 1: esentutl (works on some systems)
        try:
            result = subprocess.run(
                f'esentutl /y C:\\$MFT /d "{mft_dst}" /o',
                shell=True, capture_output=True, timeout=300
            )
            if os.path.exists(mft_dst) and os.path.getsize(mft_dst) > 0:
                self.log("    ✓ $MFT extracted via esentutl")
                self.calculate_hash(mft_dst)
                return
        except Exception:
            pass

        # Method 2: Raw disk read via PowerShell (requires admin)
        try:
            ps_script = f'''
            $drive = "\\\\.\\C:"
            $mftOffset = 0
            $clusterSize = 4096
            $mftRecordSize = 1024
            $maxRecords = 100000  # Limit to first 100K records (~100MB)

            try {{
                # Get MFT location from boot sector
                $handle = [System.IO.File]::Open($drive, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                $reader = New-Object System.IO.BinaryReader($handle)

                # Read boot sector
                $bootSector = $reader.ReadBytes(512)

                # Parse NTFS boot sector
                $bytesPerSector = [BitConverter]::ToUInt16($bootSector, 0x0B)
                $sectorsPerCluster = $bootSector[0x0D]
                $mftCluster = [BitConverter]::ToInt64($bootSector, 0x30)

                $clusterSize = $bytesPerSector * $sectorsPerCluster
                $mftOffset = $mftCluster * $clusterSize

                # Seek to MFT
                $handle.Seek($mftOffset, [System.IO.SeekOrigin]::Begin) | Out-Null

                # Read MFT records
                $outputFile = [System.IO.File]::Create("{mft_dst}")
                $buffer = New-Object byte[] (1024 * 1024)  # 1MB buffer
                $totalRead = 0
                $maxBytes = $maxRecords * $mftRecordSize

                while ($totalRead -lt $maxBytes) {{
                    $bytesRead = $handle.Read($buffer, 0, $buffer.Length)
                    if ($bytesRead -eq 0) {{ break }}
                    $outputFile.Write($buffer, 0, $bytesRead)
                    $totalRead += $bytesRead
                }}

                $outputFile.Close()
                $handle.Close()
                Write-Output "SUCCESS"
            }} catch {{
                Write-Output "FAILED: $_"
            }}
            '''

            result = subprocess.run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
                capture_output=True, text=True, timeout=300
            )

            if os.path.exists(mft_dst) and os.path.getsize(mft_dst) > 0:
                self.log("    ✓ $MFT extracted via raw disk read")
                self.calculate_hash(mft_dst)
                return
        except Exception:
            pass

        # Method 3: Volume Shadow Copy (if available)
        try:
            # List shadow copies
            result = subprocess.run(
                'vssadmin list shadows /for=C:',
                shell=True, capture_output=True, text=True, timeout=30
            )

            if 'Shadow Copy Volume' in result.stdout:
                # Extract shadow copy path
                import re
                match = re.search(r'Shadow Copy Volume: (\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+)', result.stdout)
                if match:
                    shadow_path = match.group(1)
                    mft_shadow = f"{shadow_path}\\$MFT"

                    copy_result = subprocess.run(
                        f'copy "{mft_shadow}" "{mft_dst}"',
                        shell=True, capture_output=True, timeout=300
                    )

                    if os.path.exists(mft_dst) and os.path.getsize(mft_dst) > 0:
                        self.log("    ✓ $MFT extracted via Shadow Copy")
                        self.calculate_hash(mft_dst)
                        return
        except Exception:
            pass

        # All methods failed
        self.log("    ⊘ $MFT extraction failed - requires admin privileges or raw disk tools")
        self.log("    💡 Tip: Run collector as Administrator, or use external tools like RawCopy or FTK Imager")

    def collect_srum(self):
        """Copy SRUM database."""
        srum_path = r"C:\Windows\System32\sru\SRUDB.dat"
        srum_dst = os.path.join(self.output_dir, "SRUDB.dat")

        if self.forensic_copy(srum_path, srum_dst):
            self.calculate_hash(srum_dst)

    def collect_jump_lists(self):
        """Collect Jump Lists - both raw files and parsed JSON."""
        # Copy raw jump list files for offline analysis
        jump_list_dir = os.path.join(self.output_dir, "JumpLists")
        os.makedirs(jump_list_dir, exist_ok=True)

        base_users = r"C:\Users"
        patterns = [
            r"AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms",
            r"AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*.customDestinations-ms"
        ]

        for user in os.listdir(base_users):
            user_path = os.path.join(base_users, user)
            if not os.path.isdir(user_path) or user.lower() in ['public', 'all users', 'default', 'default user']:
                continue

            for pattern in patterns:
                full_pattern = os.path.join(user_path, pattern)
                for jl_file in glob.glob(full_pattern):
                    try:
                        dst = os.path.join(jump_list_dir, f"{user}_{os.path.basename(jl_file)}")
                        shutil.copy2(jl_file, dst)
                    except Exception:
                        continue

        # Parse Jump Lists using PowerShell to extract LNK target information
        jump_list_entries = []

        # PowerShell script to parse LNK files from Recent folder (accessible jump list data)
        ps_script = r'''
        $shell = New-Object -ComObject WScript.Shell
        $results = @()

        # Known App IDs mapping (common applications)
        $appIds = @{
            "5d696d521de238c3" = "Google Chrome"
            "1b4dd67f29cb1962" = "Windows Explorer"
            "7e4dca80246863e3" = "Control Panel"
            "9b9cdc69c1c24e2b" = "Notepad"
            "f01b4d95cf55d32a" = "Windows Explorer"
            "adecfb853d77462a" = "VMware Workstation"
            "cfcdff1f1e0f6e39" = "Firefox"
            "86b804f7a28a3c18" = "Visual Studio Code"
            "ebd8c95c5d5e9a8c" = "Microsoft Edge"
            "9839aec31243a928" = "Microsoft Word"
            "d00655d2aa12ff6d" = "Microsoft Excel"
            "a7bd71699cd38d1c" = "Microsoft PowerPoint"
            "be71009ff8bb02a2" = "7-Zip"
            "e36bfc5e811a5a2a" = "WinRAR"
        }

        $baseUsers = "C:\Users"
        Get-ChildItem $baseUsers -Directory | Where-Object { $_.Name -notin @("Public", "All Users", "Default", "Default User") } | ForEach-Object {
            $user = $_.Name
            $recentFolder = Join-Path $_.FullName "AppData\Roaming\Microsoft\Windows\Recent"
            $autoDestFolder = Join-Path $recentFolder "AutomaticDestinations"

            # Parse Recent folder LNK files
            if (Test-Path $recentFolder) {
                Get-ChildItem "$recentFolder\*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
                    try {
                        $shortcut = $shell.CreateShortcut($_.FullName)
                        if ($shortcut.TargetPath) {
                            $results += [PSCustomObject]@{
                                User = $user
                                Source = "Recent"
                                AppId = ""
                                Application = "Recent Files"
                                TargetPath = $shortcut.TargetPath
                                Arguments = $shortcut.Arguments
                                WorkingDir = $shortcut.WorkingDirectory
                                LnkFile = $_.Name
                                AccessTime = $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                            }
                        }
                    } catch {}
                }
            }

            # Try to get info from AutomaticDestinations folder names (App IDs)
            if (Test-Path $autoDestFolder) {
                Get-ChildItem "$autoDestFolder\*.automaticDestinations-ms" -ErrorAction SilentlyContinue | ForEach-Object {
                    $appId = $_.BaseName
                    $appName = if ($appIds.ContainsKey($appId)) { $appIds[$appId] } else { "Unknown ($appId)" }
                    $results += [PSCustomObject]@{
                        User = $user
                        Source = "AutomaticDestinations"
                        AppId = $appId
                        Application = $appName
                        TargetPath = ""
                        Arguments = ""
                        WorkingDir = ""
                        LnkFile = $_.Name
                        AccessTime = $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                    }
                }
            }
        }

        $results | ConvertTo-Json -Depth 3
        '''

        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
                capture_output=True, text=True, timeout=60
            )
            if result.stdout.strip():
                parsed = json.loads(result.stdout)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                jump_list_entries = parsed
        except Exception:
            pass

        # Save parsed jump list data as JSON
        output_path = os.path.join(self.output_dir, "jump_lists.json")
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(jump_list_entries, f, indent=2, default=str)

    def collect_recent_files(self):
        files = []
        suspicious_exts = ['.exe', '.msi', '.bat', '.ps1', '.vbs', '.js', '.scr', '.zip', '.rar', '.7z', '.iso', '.dll', '.sys']
        limit = utc_now() - datetime.timedelta(days=self.config.recent_files_days)
        base_users = r"C:\Users"

        if os.path.exists(base_users):
            for user_dir in os.listdir(base_users):
                u_path = os.path.join(base_users, user_dir)
                if not os.path.isdir(u_path) or user_dir.lower() in ['public', 'all users', 'default', 'default user']:
                    continue

                for folder in ["Desktop", "Downloads", r"AppData\Local\Temp"]:
                    target = os.path.join(u_path, folder)
                    if os.path.exists(target):
                        for r, _, fs in os.walk(target):
                            for f in fs:
                                try:
                                    fp = os.path.join(r, f)
                                    ext = os.path.splitext(f)[1].lower()
                                    stat = os.stat(fp)
                                    t_event = datetime.datetime.fromtimestamp(max(stat.st_ctime, stat.st_mtime), datetime.timezone.utc)

                                    if t_event > limit:
                                        file_info = {
                                            "path": fp,
                                            "filename": f,
                                            "created": to_utc_str(t_event),
                                            "size_mb": round(stat.st_size / (1024 * 1024), 2),
                                            "extension": ext
                                        }

                                        if ext in suspicious_exts and stat.st_size < self.config.max_file_hash_size_mb * 1024 * 1024:
                                            file_info["sha256"] = self.calculate_hash(fp, add_to_evidence_list=False)

                                        files.append(file_info)
                                except Exception:
                                    continue

        self.save_json("recent_files.json", files)

    def collect_shellbags(self):
        """Collect Shellbags - folder access history from registry."""
        shellbags = []

        # PowerShell script to extract shellbag-like folder access info from registry
        ps_script = r'''
        $results = @()

        # Get all user SIDs from HKU
        $userSIDs = Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21-' -and $_.Name -notmatch '_Classes' }

        foreach ($sid in $userSIDs) {
            $sidPath = $sid.Name

            # Try to get username from SID
            try {
                $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid.PSChildName)
                $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
                $username = $objUser.Value.Split('\')[-1]
            } catch {
                $username = $sid.PSChildName
            }

            # Explorer\Shell Folders - user folders
            $shellFoldersPath = "Registry::$sidPath\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
            if (Test-Path $shellFoldersPath) {
                $shellFolders = Get-ItemProperty -Path $shellFoldersPath -ErrorAction SilentlyContinue
                if ($shellFolders) {
                    $shellFolders.PSObject.Properties | Where-Object { $_.Value -is [string] -and $_.Value -match '^[A-Z]:\\' } | ForEach-Object {
                        $results += [PSCustomObject]@{
                            User = $username
                            FolderType = $_.Name
                            Path = $_.Value
                            Source = "Shell Folders"
                            AccessTime = ""
                        }
                    }
                }
            }

            # RecentDocs - recently accessed documents
            $recentDocsPath = "Registry::$sidPath\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
            if (Test-Path $recentDocsPath) {
                Get-ChildItem -Path $recentDocsPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $results += [PSCustomObject]@{
                        User = $username
                        FolderType = "RecentDocs"
                        Path = $_.PSChildName
                        Source = "RecentDocs Registry"
                        AccessTime = ""
                    }
                }
            }

            # ComDlg32\OpenSavePidlMRU - Open/Save dialog history
            $openSavePath = "Registry::$sidPath\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"
            if (Test-Path $openSavePath) {
                Get-ChildItem -Path $openSavePath -ErrorAction SilentlyContinue | ForEach-Object {
                    $extType = $_.PSChildName
                    $results += [PSCustomObject]@{
                        User = $username
                        FolderType = "OpenSave Dialog"
                        Path = "Extension: $extType"
                        Source = "ComDlg32 MRU"
                        AccessTime = ""
                    }
                }
            }

            # TypedPaths - paths typed in Explorer address bar
            $typedPathsPath = "Registry::$sidPath\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
            if (Test-Path $typedPathsPath) {
                $typedPaths = Get-ItemProperty -Path $typedPathsPath -ErrorAction SilentlyContinue
                if ($typedPaths) {
                    $typedPaths.PSObject.Properties | Where-Object { $_.Name -like 'url*' } | ForEach-Object {
                        $results += [PSCustomObject]@{
                            User = $username
                            FolderType = "Typed Path"
                            Path = $_.Value
                            Source = "TypedPaths"
                            AccessTime = ""
                        }
                    }
                }
            }

            # RunMRU - Run dialog history
            $runMRUPath = "Registry::$sidPath\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
            if (Test-Path $runMRUPath) {
                $runMRU = Get-ItemProperty -Path $runMRUPath -ErrorAction SilentlyContinue
                if ($runMRU) {
                    $runMRU.PSObject.Properties | Where-Object { $_.Name -match '^[a-z]$' } | ForEach-Object {
                        $results += [PSCustomObject]@{
                            User = $username
                            FolderType = "Run Command"
                            Path = $_.Value -replace '\\1$', ''
                            Source = "RunMRU"
                            AccessTime = ""
                        }
                    }
                }
            }
        }

        # MountPoints2 - mounted drives/network shares
        foreach ($sid in $userSIDs) {
            $sidPath = $sid.Name
            $mountPath = "Registry::$sidPath\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
            if (Test-Path $mountPath) {
                try {
                    $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid.PSChildName)
                    $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
                    $username = $objUser.Value.Split('\')[-1]
                } catch {
                    $username = $sid.PSChildName
                }

                Get-ChildItem -Path $mountPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $mountName = $_.PSChildName -replace '#', '\'
                    $results += [PSCustomObject]@{
                        User = $username
                        FolderType = "Mount Point"
                        Path = $mountName
                        Source = "MountPoints2"
                        AccessTime = ""
                    }
                }
            }
        }

        $results | ConvertTo-Json -Depth 3
        '''

        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
                capture_output=True, text=True, timeout=60
            )
            if result.stdout.strip():
                parsed = json.loads(result.stdout)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                shellbags = parsed
        except Exception as e:
            self.log_error("collect_shellbags", str(e))

        self.save_json("shellbags.json", shellbags)

    # ==========================================
    # PHASE 6: EVENT LOGS
    # ==========================================

    def collect_logs(self):
        phase_start = self.log_phase("Event Logs (EVTX backup + parsed)...")

        # Backup EVTX files - comprehensive forensic log collection
        backup_dir = os.path.join(self.output_dir, "EVTX_Backup")
        os.makedirs(backup_dir, exist_ok=True)

        # Organized by forensic value
        logs_to_copy = [
            # Core Windows Logs
            "Security",
            "System",
            "Application",
            "Setup",

            # PowerShell (T1059.001)
            "Microsoft-Windows-PowerShell%4Operational",
            "Windows PowerShell",

            # Remote Access / Lateral Movement
            "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational",
            "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational",
            "Microsoft-Windows-SMBClient%4Security",
            "Microsoft-Windows-SMBServer%4Security",
            "Microsoft-Windows-WinRM%4Operational",

            # Persistence Mechanisms
            "Microsoft-Windows-TaskScheduler%4Operational",
            "Microsoft-Windows-WMI-Activity%4Operational",

            # Network & DNS
            "Microsoft-Windows-DNS-Client%4Operational",
            "Microsoft-Windows-Bits-Client%4Operational",
            "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall",
            "Microsoft-Windows-WLAN-AutoConfig%4Operational",
            "Microsoft-Windows-NetworkProfile%4Operational",

            # Security Tools & Defenses
            "Microsoft-Windows-Sysmon%4Operational",
            "Microsoft-Windows-Windows Defender%4Operational",
            "Microsoft-Windows-Windows Defender%4WHC",
            "Microsoft-Windows-AppLocker%4EXE and DLL",
            "Microsoft-Windows-AppLocker%4MSI and Script",
            "Microsoft-Windows-DeviceGuard%4Operational",
            "Microsoft-Windows-CodeIntegrity%4Operational",

            # Authentication
            "Microsoft-Windows-NTLM%4Operational",
            "Microsoft-Windows-Kerberos%4Operational",
            "Microsoft-Windows-Authentication%4Operational",

            # Process & Service
            "Microsoft-Windows-Services%4Operational",
            "Microsoft-Windows-DriverFrameworks-UserMode%4Operational",

            # Exploit / Vulnerability
            "Microsoft-Windows-PrintService%4Operational",
            "Microsoft-Windows-Security-Mitigations%4KernelMode",
            "Microsoft-Windows-Security-Mitigations%4UserMode",

            # USB / Removable Media
            "Microsoft-Windows-Partition%4Diagnostic",
            "Microsoft-Windows-StorageSpaces-Driver%4Operational",
        ]

        copied_count = 0
        for log in logs_to_copy:
            try:
                src = fr"C:\Windows\System32\winevt\Logs\{log}.evtx"
                dst = os.path.join(backup_dir, f"{log.replace('%4', '-')}.evtx")
                if os.path.exists(src):
                    self.forensic_copy(src, dst)
                    if os.path.exists(dst):
                        self.calculate_hash(dst)
                        copied_count += 1
            except Exception:
                continue

        self.log(f"    ✓ Backed up {copied_count} EVTX files")

        # Parse important events from key channels
        channels_to_parse = [
            "Security",
            "System",
            "Application",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-TaskScheduler/Operational",
            "Microsoft-Windows-WMI-Activity/Operational",
            "Microsoft-Windows-Bits-Client/Operational",
            "Microsoft-Windows-Windows Defender/Operational",
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "Microsoft-Windows-Sysmon/Operational"
        ]

        script = f"""
        $Channels = @({', '.join([f'"{c}"' for c in channels_to_parse])})
        $Out = @()
        foreach ($C in $Channels) {{
            Try {{
                $Out += Get-WinEvent -LogName $C -MaxEvents {self.config.max_event_logs} -ErrorAction SilentlyContinue |
                Select-Object @{{N='Time';E={{$_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")}}}},
                Id, LevelDisplayName,
                @{{N='Message';E={{if ($_.Message.Length -gt 500) {{ $_.Message.Substring(0, 500) + "..." }} else {{ $_.Message }}}}}},
                @{{N='LogName';E={{$C}}}}
            }} Catch {{}}
        }}
        $Out | Sort-Object Time -Descending
        """
        self.save_json("all_events.json", self.run_powershell(script, timeout=180))

        # Collect high-value security events separately for easier analysis
        self.collect_security_events()

        self.log_phase_complete("Event Logs", phase_start)

    def collect_security_events(self):
        """Collect specific high-value security events for forensic analysis."""

        # High-value Event IDs organized by category
        script = """
        $HighValueEvents = @{
            # Logon Events
            "Logon" = @(4624, 4625, 4634, 4647, 4648, 4672, 4778, 4779)
            # Account Management
            "Account" = @(4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4756, 4738, 4740, 4767)
            # Process & Service
            "Process" = @(4688, 4689, 7045, 7040)
            # Object Access & Policy
            "Access" = @(4663, 4656, 4658, 4660, 4670, 4719, 4739, 4946, 4947, 4950)
            # Credential Access
            "Credential" = @(4768, 4769, 4771, 4776, 5136, 5137)
            # Defense Evasion
            "Evasion" = @(1102, 4697, 4698, 4699, 4700, 4701, 4702)
        }

        $Results = @()

        foreach ($Category in $HighValueEvents.Keys) {
            $EventIds = $HighValueEvents[$Category]
            try {
                $Events = Get-WinEvent -FilterHashtable @{
                    LogName = 'Security'
                    Id = $EventIds
                } -MaxEvents 500 -ErrorAction SilentlyContinue

                foreach ($E in $Events) {
                    $Results += [PSCustomObject]@{
                        Time = $E.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                        Category = $Category
                        EventId = $E.Id
                        Level = $E.LevelDisplayName
                        Message = if ($E.Message.Length -gt 300) { $E.Message.Substring(0, 300) + "..." } else { $E.Message }
                    }
                }
            } catch {}
        }

        # Also get Sysmon events if available
        try {
            $SysmonEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1000 -ErrorAction SilentlyContinue
            foreach ($E in $SysmonEvents) {
                $Results += [PSCustomObject]@{
                    Time = $E.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    Category = "Sysmon"
                    EventId = $E.Id
                    Level = $E.LevelDisplayName
                    Message = if ($E.Message.Length -gt 300) { $E.Message.Substring(0, 300) + "..." } else { $E.Message }
                }
            }
        } catch {}

        $Results | Sort-Object Time -Descending | ConvertTo-Json -Depth 3
        """

        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script],
                capture_output=True, text=True, timeout=120
            )
            if result.stdout.strip():
                events = json.loads(result.stdout)
                if isinstance(events, dict):
                    events = [events]
                self.save_json("security_events.json", events)
                self.log(f"    ✓ Collected {len(events)} high-value security events")
        except Exception as e:
            self.log_error("collect_security_events", str(e))

    # ==========================================
    # PHASE 7: BROWSER DATA
    # ==========================================

    def collect_browser_data(self):
        phase_start = self.log_phase("Browser Data (History, Cookies, Downloads - Chrome/Edge/Firefox)...")

        # Kill browsers for cookie access
        subprocess.run("taskkill /F /IM chrome.exe /T 2>nul", shell=True, capture_output=True)
        subprocess.run("taskkill /F /IM msedge.exe /T 2>nul", shell=True, capture_output=True)
        subprocess.run("taskkill /F /IM firefox.exe /T 2>nul", shell=True, capture_output=True)
        time.sleep(1)

        # Collect Chrome/Edge history
        self.collect_chromium_history()

        # Collect Firefox
        self.collect_firefox_data()

        # Collect browser downloads
        self.collect_browser_downloads()

        # Collect cookies
        self.collect_cookies_full()

        # Collect browser cache metadata
        self.collect_browser_cache_metadata()

        self.log_phase_complete("Browser Data", phase_start)

    def collect_chromium_history(self):
        history_data = []
        base_users = r"C:\Users"
        browser_paths = [
            {"name": "Chrome", "path": r"AppData\Local\Google\Chrome\User Data\Default\History"},
            {"name": "Edge", "path": r"AppData\Local\Microsoft\Edge\User Data\Default\History"}
        ]

        if os.path.exists(base_users):
            for user in os.listdir(base_users):
                for b in browser_paths:
                    full_db_path = os.path.join(base_users, user, b["path"])
                    if os.path.exists(full_db_path):
                        try:
                            temp_db = os.path.join(self.output_dir, f"History_tmp_{user}_{b['name']}")
                            if self.forensic_copy(full_db_path, temp_db):
                                conn = sqlite3.connect(temp_db)
                                cursor = conn.cursor()
                                query = f"""
                                    SELECT datetime(last_visit_time/1000000-11644473600, 'unixepoch', 'utc') as visit_time,
                                           url, title, visit_count
                                    FROM urls
                                    ORDER BY last_visit_time DESC
                                    LIMIT {self.config.max_browser_history}
                                """
                                cursor.execute(query)
                                for row in cursor.fetchall():
                                    history_data.append({
                                        "User": user, "Browser": b["name"],
                                        "Time": row[0], "URL": row[1],
                                        "Title": row[2], "Visits": row[3]
                                    })
                                conn.close()
                                os.remove(temp_db)
                        except Exception as e:
                            self.log_error(f"ChromiumHistory({user})", str(e))

        self.save_json("browser_history.json", history_data)

    def collect_firefox_data(self):
        """Collect Firefox history."""
        firefox_history = []
        base_users = r"C:\Users"

        if os.path.exists(base_users):
            for user in os.listdir(base_users):
                ff_profile_path = os.path.join(base_users, user, r"AppData\Roaming\Mozilla\Firefox\Profiles")
                if os.path.exists(ff_profile_path):
                    for profile in os.listdir(ff_profile_path):
                        places_db = os.path.join(ff_profile_path, profile, "places.sqlite")
                        if os.path.exists(places_db):
                            try:
                                temp_db = os.path.join(self.output_dir, f"ff_places_{user}_{profile}.db")
                                if self.forensic_copy(places_db, temp_db):
                                    conn = sqlite3.connect(temp_db)
                                    cursor = conn.cursor()
                                    query = f"""
                                        SELECT datetime(last_visit_date/1000000, 'unixepoch', 'utc'),
                                               url, title, visit_count
                                        FROM moz_places
                                        WHERE last_visit_date IS NOT NULL
                                        ORDER BY last_visit_date DESC
                                        LIMIT {self.config.max_browser_history}
                                    """
                                    cursor.execute(query)
                                    for row in cursor.fetchall():
                                        firefox_history.append({
                                            "User": user, "Browser": "Firefox", "Profile": profile,
                                            "Time": row[0], "URL": row[1],
                                            "Title": row[2], "Visits": row[3]
                                        })
                                    conn.close()
                                    os.remove(temp_db)
                            except Exception as e:
                                self.log_error(f"FirefoxHistory({user})", str(e))

        self.save_json("firefox_history.json", firefox_history)

    def collect_browser_downloads(self):
        """Collect download history from all browsers."""
        downloads = []
        base_users = r"C:\Users"

        if os.path.exists(base_users):
            for user in os.listdir(base_users):
                # Chrome/Edge downloads
                for browser, path in [
                    ("Chrome", r"AppData\Local\Google\Chrome\User Data\Default\History"),
                    ("Edge", r"AppData\Local\Microsoft\Edge\User Data\Default\History")
                ]:
                    db_path = os.path.join(base_users, user, path)
                    if os.path.exists(db_path):
                        try:
                            temp_db = os.path.join(self.output_dir, f"dl_{user}_{browser}.db")
                            if self.forensic_copy(db_path, temp_db):
                                conn = sqlite3.connect(temp_db)
                                cursor = conn.cursor()
                                # Get ALL downloads - no limit for forensic completeness
                                query = """
                                    SELECT target_path, tab_url, referrer,
                                           datetime(start_time/1000000-11644473600, 'unixepoch', 'utc') as start_dt,
                                           datetime(end_time/1000000-11644473600, 'unixepoch', 'utc') as end_dt,
                                           received_bytes, total_bytes, state, danger_type, mime_type
                                    FROM downloads
                                    ORDER BY start_time DESC
                                """
                                cursor.execute(query)
                                for row in cursor.fetchall():
                                    # State: 0=in progress, 1=complete, 2=cancelled, 3=interrupted
                                    state_map = {0: 'In Progress', 1: 'Complete', 2: 'Cancelled', 3: 'Interrupted', 4: 'Interrupted'}
                                    # Danger type: 0=safe, 1=dangerous, 2=dangerous_url, etc.
                                    danger_map = {0: 'Safe', 1: 'Dangerous File', 2: 'Dangerous URL', 3: 'Dangerous Content',
                                                  4: 'Uncommon Content', 5: 'User Validated', 6: 'Dangerous Host', 7: 'Potentially Unwanted'}

                                    downloads.append({
                                        "User": user,
                                        "Browser": browser,
                                        "FilePath": row[0],
                                        "URL": row[1],
                                        "Referrer": row[2],
                                        "StartTime": row[3],
                                        "EndTime": row[4],
                                        "ReceivedBytes": row[5],
                                        "TotalBytes": row[6],
                                        "State": state_map.get(row[7], str(row[7])) if row[7] is not None else 'Unknown',
                                        "DangerType": danger_map.get(row[8], str(row[8])) if row[8] is not None else 'Safe',
                                        "MimeType": row[9]
                                    })
                                conn.close()
                                os.remove(temp_db)
                        except Exception:
                            pass

                # Firefox downloads
                ff_profile_path = os.path.join(base_users, user, r"AppData\Roaming\Mozilla\Firefox\Profiles")
                if os.path.exists(ff_profile_path):
                    for profile in os.listdir(ff_profile_path):
                        places_db = os.path.join(ff_profile_path, profile, "places.sqlite")
                        if os.path.exists(places_db):
                            try:
                                temp_db = os.path.join(self.output_dir, f"ff_dl_{user}.db")
                                if self.forensic_copy(places_db, temp_db):
                                    conn = sqlite3.connect(temp_db)
                                    cursor = conn.cursor()
                                    # Get all Firefox downloads - no limit
                                    query = """
                                        SELECT a.content, p.url,
                                               datetime(a.dateAdded/1000000, 'unixepoch', 'utc'),
                                               p.title
                                        FROM moz_annos a
                                        JOIN moz_places p ON a.place_id = p.id
                                        WHERE a.anno_attribute_id =
                                            (SELECT id FROM moz_anno_attributes WHERE name='downloads/destinationFileURI')
                                        ORDER BY a.dateAdded DESC
                                    """
                                    try:
                                        cursor.execute(query)
                                        for row in cursor.fetchall():
                                            filepath = str(row[0] or '').replace('file:///', '').replace('file://', '')
                                            downloads.append({
                                                "User": user,
                                                "Browser": "Firefox",
                                                "FilePath": filepath,
                                                "URL": row[1],
                                                "StartTime": row[2],
                                                "Title": row[3],
                                                "State": "Complete",
                                                "DangerType": "Unknown"
                                            })
                                    except Exception:
                                        pass
                                    conn.close()
                                    os.remove(temp_db)
                            except Exception:
                                pass

        self.log(f"    ✓ Collected {len(downloads)} browser downloads")
        self.save_json("browser_downloads.json", downloads)

    def _convert_chrome_time(self, chrome_time):
        if not chrome_time or chrome_time == 0:
            return "N/A (Session Only)"
        try:
            epoch_time = (chrome_time / 1000000) - 11644473600
            return timestamp_from_epoch(epoch_time)
        except Exception:
            return f"Raw: {chrome_time}"

    def get_master_key(self, user_path: str, browser_name: str):
        paths = {
            "Chrome": r"AppData\Local\Google\Chrome\User Data\Local State",
            "Edge": r"AppData\Local\Microsoft\Edge\User Data\Local State"
        }
        state_path = os.path.join(user_path, paths.get(browser_name, ""))
        if not os.path.exists(state_path):
            return None

        try:
            with open(state_path, "r", encoding="utf-8") as f:
                local_state = json.loads(f.read())

            encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            raw_key = encrypted_key[5:]  # Remove DPAPI prefix

            # Try multiple approaches for DPAPI decryption
            master_key = None

            # Method 1: Try with user impersonation
            impersonated = impersonate_logged_on_user()
            try:
                master_key = win32crypt.CryptUnprotectData(raw_key, None, None, None, 0)[1]
            except Exception:
                pass
            finally:
                if impersonated:
                    stop_impersonation()

            # Method 2: Try direct DPAPI (works if running as the same user)
            if not master_key:
                try:
                    master_key = win32crypt.CryptUnprotectData(raw_key, None, None, None, 0)[1]
                except Exception:
                    pass

            return master_key
        except Exception as e:
            self.log_error("get_master_key", f"Failed for {browser_name}: {str(e)}")
            return None

    def decrypt_cookie(self, value, key, return_encrypted=False):
        """
        Decrypt cookie value. If decryption fails and return_encrypted is True,
        return base64 encoded value for later offline decryption.
        """
        try:
            if not value or len(value) < 3:
                return "", False

            # Chrome v80+ AES-GCM encryption (starts with v10 or v11)
            if value.startswith(b'v10') or value.startswith(b'v11'):
                if not key:
                    if return_encrypted:
                        return base64.b64encode(value).decode('utf-8'), True
                    return "[Key Unavailable]", False

                try:
                    nonce = value[3:15]
                    ciphertext = value[15:-16]
                    tag = value[-16:]
                    cipher = AES.new(key, AES.MODE_GCM, nonce)
                    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                    return decrypted.decode('utf-8', errors='ignore'), False
                except Exception:
                    if return_encrypted:
                        return base64.b64encode(value).decode('utf-8'), True
                    return "[Decryption Failed]", False

            # Older DPAPI encryption
            else:
                try:
                    decrypted = win32crypt.CryptUnprotectData(value, None, None, None, 0)[1]
                    return decrypted.decode('utf-8', errors='ignore'), False
                except Exception:
                    if return_encrypted:
                        return base64.b64encode(value).decode('utf-8'), True
                    return "[DPAPI Failed]", False

        except Exception:
            if return_encrypted:
                return base64.b64encode(value).decode('utf-8') if value else "", True
            return "[Error]", False

    def collect_cookies_full(self):
        all_cookies = []
        base_users = r"C:\Users"
        browser_configs = [
            {"name": "Chrome", "root": r"AppData\Local\Google\Chrome\User Data"},
            {"name": "Edge", "root": r"AppData\Local\Microsoft\Edge\User Data"}
        ]

        for user in os.listdir(base_users):
            u_path = os.path.join(base_users, user)
            if not os.path.isdir(u_path) or user.lower() in ['public', 'all users', 'default user', 'default']:
                continue

            for config in browser_configs:
                browser_path = os.path.join(u_path, config["root"])
                if not os.path.exists(browser_path):
                    continue

                m_key = self.get_master_key(u_path, config["name"])

                possible_cookie_locations = ["**/Cookies", "**/Network/Cookies"]

                for pattern in possible_cookie_locations:
                    search_path = os.path.join(browser_path, pattern)
                    for cookie_file in glob.glob(search_path, recursive=True):
                        profile_name = os.path.basename(os.path.dirname(os.path.dirname(cookie_file)))
                        if profile_name in ["User Data", "Network"]:
                            profile_name = "Default"

                        tmp_path = os.path.join(self.output_dir, f"ck_{user}_{config['name']}_{profile_name}.db")

                        if self.forensic_copy(cookie_file, tmp_path):
                            try:
                                conn = sqlite3.connect(tmp_path)
                                cur = conn.cursor()
                                cur.execute("SELECT host_key, name, path, creation_utc, expires_utc, encrypted_value, is_secure, is_httponly FROM cookies")

                                for row in cur.fetchall():
                                    h_key, name, c_path, created, expires, enc_val = row[:6]
                                    is_secure = row[6] if len(row) > 6 else 0
                                    is_httponly = row[7] if len(row) > 7 else 0

                                    # Try to decrypt, get encrypted value as fallback
                                    value, is_encrypted = self.decrypt_cookie(enc_val, m_key, return_encrypted=True)

                                    cookie_entry = {
                                        "User": user,
                                        "Browser": config["name"],
                                        "Profile": profile_name,
                                        "Host": h_key,
                                        "CookieName": name,
                                        "Path": c_path,
                                        "Value": value,  # Shows decrypted value or base64 encrypted value
                                        "Created": self._convert_chrome_time(created),
                                        "Expires": self._convert_chrome_time(expires),
                                        "Secure": bool(is_secure),
                                        "HttpOnly": bool(is_httponly),
                                        "Decrypted": not is_encrypted
                                    }

                                    all_cookies.append(cookie_entry)

                                conn.close()
                                os.remove(tmp_path)
                            except Exception as e:
                                self.log_error("CookieRead", str(e))

        # Log decryption statistics
        decrypted_count = sum(1 for c in all_cookies if c.get("Decrypted", False))
        self.log(f"    ✓ Collected {len(all_cookies)} cookies ({decrypted_count} decrypted, {len(all_cookies) - decrypted_count} encrypted)")

        if len(all_cookies) > decrypted_count:
            self.log("    💡 Tip: Run collector as the same user who owns the browser, or use offline tools like Nirsoft ChromeCookiesView")

        self.save_json("browser_cookies.json", all_cookies)

    def collect_browser_cache_metadata(self):
        """Collect browser cache metadata without copying large cache files."""
        cache_metadata = []
        base_users = r"C:\Users"

        # Browser cache locations
        cache_locations = [
            {"browser": "Chrome", "path": r"AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data"},
            {"browser": "Chrome", "path": r"AppData\Local\Google\Chrome\User Data\Default\Code Cache"},
            {"browser": "Edge", "path": r"AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data"},
            {"browser": "Edge", "path": r"AppData\Local\Microsoft\Edge\User Data\Default\Code Cache"},
            {"browser": "Firefox", "path": r"AppData\Local\Mozilla\Firefox\Profiles"},
        ]

        for user in os.listdir(base_users):
            user_path = os.path.join(base_users, user)
            if not os.path.isdir(user_path) or user.lower() in ['public', 'all users', 'default', 'default user']:
                continue

            for config in cache_locations:
                cache_path = os.path.join(user_path, config["path"])

                # Handle Firefox profiles
                if config["browser"] == "Firefox" and os.path.exists(cache_path):
                    for profile in os.listdir(cache_path):
                        ff_cache = os.path.join(cache_path, profile, "cache2", "entries")
                        if os.path.exists(ff_cache):
                            self._collect_cache_dir_metadata(cache_metadata, ff_cache, user, "Firefox", profile)
                elif os.path.exists(cache_path):
                    self._collect_cache_dir_metadata(cache_metadata, cache_path, user, config["browser"], "Default")

        # Also collect cache statistics summary
        cache_summary = self._get_cache_summary(cache_metadata)

        self.log(f"    ✓ Collected metadata for {len(cache_metadata)} cache entries")
        self.save_json("browser_cache_metadata.json", {
            "summary": cache_summary,
            "entries": cache_metadata[:5000]  # Limit entries to avoid huge files
        })

    def _collect_cache_dir_metadata(self, cache_list, cache_path, user, browser, profile):
        """Collect metadata from a cache directory."""
        try:
            total_size = 0
            file_count = 0

            for root, dirs, files in os.walk(cache_path):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    try:
                        stat = os.stat(file_path)
                        file_size = stat.st_size
                        total_size += file_size
                        file_count += 1

                        # Only record metadata for files, not the actual content
                        # Get timestamps (UTC)
                        created = datetime.datetime.fromtimestamp(stat.st_ctime, datetime.timezone.utc)
                        modified = datetime.datetime.fromtimestamp(stat.st_mtime, datetime.timezone.utc)
                        accessed = datetime.datetime.fromtimestamp(stat.st_atime, datetime.timezone.utc)

                        # For recently accessed cache entries (last 7 days), record details
                        if (utc_now() - accessed).days <= 7:
                            # Get relative path, use "root" if file is in cache root directory
                            rel_path = os.path.relpath(root, cache_path)
                            if rel_path == ".":
                                rel_path = "(root)"

                            cache_list.append({
                                "User": user,
                                "Browser": browser,
                                "Profile": profile,
                                "FileName": filename,
                                "Size": file_size,
                                "Created": to_utc_str(created),
                                "Modified": to_utc_str(modified),
                                "Accessed": to_utc_str(accessed),
                                "CachePath": rel_path
                            })
                    except Exception:
                        continue

        except Exception:
            pass

    def _get_cache_summary(self, cache_entries):
        """Generate summary statistics for cache data."""
        summary = {
            "total_entries": len(cache_entries),
            "by_browser": {},
            "by_user": {},
            "recent_24h": 0,
            "recent_7d": 0,
            "total_size_bytes": 0
        }

        now = utc_now()

        for entry in cache_entries:
            browser = entry.get("Browser", "Unknown")
            user = entry.get("User", "Unknown")
            size = entry.get("Size", 0)

            # Count by browser
            summary["by_browser"][browser] = summary["by_browser"].get(browser, 0) + 1

            # Count by user
            summary["by_user"][user] = summary["by_user"].get(user, 0) + 1

            # Total size
            summary["total_size_bytes"] += size

            # Recent entries (handle both old and new UTC format)
            try:
                accessed_str = entry.get("Accessed", "").replace(" UTC", "")
                accessed = datetime.datetime.strptime(accessed_str, "%Y-%m-%d %H:%M:%S")
                if (now - accessed).days <= 1:
                    summary["recent_24h"] += 1
                if (now - accessed).days <= 7:
                    summary["recent_7d"] += 1
            except:
                pass

        # Format total size
        total_mb = summary["total_size_bytes"] / (1024 * 1024)
        summary["total_size_formatted"] = f"{total_mb:.1f} MB"

        return summary

    # ==========================================
    # PHASE 8: NETWORK ARTIFACTS
    # ==========================================

    def collect_network_artifacts(self):
        phase_start = self.log_phase("Network Artifacts (DNS, BITS, RDP Cache)...")

        # DNS Cache - convert Status codes to readable text
        dns_script = """
        # DNS Status code mapping
        $statusMap = @{
            0 = 'Success'
            9003 = 'NotExist (NXDOMAIN)'
            9501 = 'NoRecords'
            9701 = 'NoRecords'
            1460 = 'Timeout'
            9002 = 'ServerFailure'
            87 = 'InvalidParameter'
        }

        # DNS Type code mapping
        $typeMap = @{
            1 = 'A'
            2 = 'NS'
            5 = 'CNAME'
            6 = 'SOA'
            12 = 'PTR'
            15 = 'MX'
            16 = 'TXT'
            28 = 'AAAA'
            33 = 'SRV'
            255 = 'ANY'
        }

        try {
            Get-DnsClientCache -ErrorAction SilentlyContinue | ForEach-Object {
                $statusText = if ($statusMap.ContainsKey([int]$_.Status)) { $statusMap[[int]$_.Status] } else { $_.Status.ToString() }
                $typeText = if ($typeMap.ContainsKey([int]$_.Type)) { $typeMap[[int]$_.Type] } else { $_.Type.ToString() }

                [PSCustomObject]@{
                    Entry = $_.Entry
                    Name = $_.Name
                    Type = $typeText
                    Status = $statusText
                    TTL = $_.TimeToLive
                    Data = ($_.Data -join ', ')
                }
            }
        } catch { @() }
        """
        dns_data = self.run_powershell(dns_script)
        if dns_data:
            self.save_json("dns_cache.json", dns_data)
        else:
            try:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                raw = subprocess.run("ipconfig /displaydns", capture_output=True, text=True, startupinfo=si).stdout
                self.save_json("dns_cache_raw.json", [{"raw": raw}])
            except Exception:
                pass

        # BITS Jobs - convert enums to readable strings and resolve SID to username
        bits_script = """
        try {
            Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | ForEach-Object {
                # Resolve SID to username
                $ownerName = $_.OwnerAccount
                if ($ownerName -match '^S-1-') {
                    try {
                        $sid = New-Object System.Security.Principal.SecurityIdentifier($ownerName)
                        $account = $sid.Translate([System.Security.Principal.NTAccount])
                        $ownerName = $account.Value
                    } catch {
                        # Keep original SID if translation fails
                    }
                }

                [PSCustomObject]@{
                    DisplayName = $_.DisplayName
                    JobState = $_.JobState.ToString()
                    TransferType = $_.TransferType.ToString()
                    Files = ($_.FileList.RemoteName -join '; ')
                    LocalFiles = ($_.FileList.LocalName -join '; ')
                    BytesTotal = $_.BytesTotal
                    BytesTransferred = $_.BytesTransferred
                    CreationTime = if ($_.CreationTime) { $_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                    TransferCompletionTime = if ($_.TransferCompletionTime -and $_.TransferCompletionTime.Year -gt 1) { $_.TransferCompletionTime.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                    OwnerAccount = $ownerName
                    Priority = $_.Priority.ToString()
                }
            }
        } catch { @() }
        """
        self.save_json("bits_jobs.json", self.run_powershell(bits_script))

        # RDP Cache
        self.collect_rdp_cache()

        # Installed Software
        self.save_json("installed_software.json", self.run_powershell(
            "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Select DisplayName, Publisher, InstallDate, DisplayVersion"
        ))

        self.log_phase_complete("Network Artifacts", phase_start)

    def collect_rdp_cache(self):
        """Collect RDP bitmap cache files."""
        rdp_cache_dir = os.path.join(self.output_dir, "RDP_Cache")
        os.makedirs(rdp_cache_dir, exist_ok=True)

        base_users = r"C:\Users"
        for user in os.listdir(base_users):
            cache_path = os.path.join(base_users, user, r"AppData\Local\Microsoft\Terminal Server Client\Cache")
            if os.path.exists(cache_path):
                for f in os.listdir(cache_path):
                    if f.endswith('.bmc') or f.endswith('.bin'):
                        try:
                            src = os.path.join(cache_path, f)
                            dst = os.path.join(rdp_cache_dir, f"{user}_{f}")
                            shutil.copy2(src, dst)
                        except Exception:
                            continue

    # ==========================================
    # PHASE 9: REGISTRY HIVES BACKUP
    # ==========================================

    def collect_registry_hives(self):
        phase_start = self.log_phase("Registry Hives (SAM, SYSTEM, SECURITY, SOFTWARE)...")

        hive_dir = os.path.join(self.output_dir, "Registry_Hives")
        os.makedirs(hive_dir, exist_ok=True)

        hives = [
            ("HKLM\\SAM", "SAM"),
            ("HKLM\\SYSTEM", "SYSTEM"),
            ("HKLM\\SECURITY", "SECURITY"),
            ("HKLM\\SOFTWARE", "SOFTWARE")
        ]

        for hive_path, hive_name in hives:
            dst = os.path.join(hive_dir, f"{hive_name}.hiv")
            try:
                result = subprocess.run(
                    ['reg', 'save', hive_path, dst, '/y'],
                    capture_output=True, timeout=60
                )
                if os.path.exists(dst):
                    self.calculate_hash(dst)
            except Exception as e:
                self.log_error(f"reg_save({hive_name})", str(e))

        # NTUSER.DAT for each user
        base_users = r"C:\Users"
        for user in os.listdir(base_users):
            ntuser_path = os.path.join(base_users, user, "NTUSER.DAT")
            if os.path.exists(ntuser_path):
                try:
                    dst = os.path.join(hive_dir, f"NTUSER_{user}.DAT")
                    self.forensic_copy(ntuser_path, dst)
                    if os.path.exists(dst):
                        self.calculate_hash(dst)
                except Exception:
                    pass

        self.log_phase_complete("Registry Hives", phase_start)

    # ==========================================
    # FINALIZATION
    # ==========================================

    def create_audit_log(self):
        """Create audit log with collection metadata (all timestamps in UTC)."""
        end_time = utc_now()
        duration = (end_time - self.start_time).total_seconds()

        audit_data = {
            "collector_version": COLLECTOR_VERSION,
            "hostname": self.hostname,
            "os_version": platform.platform(),
            "current_user": os.environ.get('USERNAME', 'Unknown'),
            "collection_start": to_utc_str(self.start_time),
            "collection_end": to_utc_str(end_time),
            "duration_seconds": round(duration, 2),
            "output_directory": self.output_dir,
            "phase_timings": self.phase_timings,
            "total_evidence_files": len(self.hash_list),
            "timezone": "UTC",
            "config": asdict(self.config)
        }

        self.save_json("audit_log.json", audit_data)

    def finalize(self):
        phase_start = self.log_phase("Finalizing (Hashes, Index, Audit Log)...")

        # Save hash list
        self.save_json("file_hashes.json", self.hash_list)

        # Create audit log
        self.create_audit_log()

        # Create HTML index
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Forensic Report - {self.hostname}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1e1e2e; color: #ccc; padding: 20px; }}
        h1 {{ color: #4da6ff; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .file-list {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 10px; }}
        .file-item {{ background: #2d2d3d; padding: 10px; border-radius: 5px; }}
        .file-item a {{ color: #4da6ff; text-decoration: none; }}
        .file-item a:hover {{ color: #6db8ff; }}
        .meta {{ color: #888; font-size: 12px; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Forensic Evidence Collection</h1>
        <p><strong>Host:</strong> {self.hostname}</p>
        <p><strong>Collected:</strong> {to_utc_str(self.start_time)}</p>
        <p><strong>Collector Version:</strong> {COLLECTOR_VERSION}</p>
        <h2>Evidence Files</h2>
        <div class="file-list">
"""
        for f in sorted(os.listdir(self.output_dir)):
            if f != "index.html":
                html_content += f'            <div class="file-item"><a href="{f}" target="_blank">{f}</a></div>\n'

        html_content += """        </div>
    </div>
</body>
</html>"""

        try:
            with open(os.path.join(self.output_dir, "index.html"), "w", encoding='utf-8') as f:
                f.write(html_content)
        except Exception:
            pass

        self.log_phase_complete("Finalization", phase_start)

    def run_collection(self):
        """Run the full collection process."""
        try:
            self.collect_ram_dump()
            self.collect_live_data()
            self.collect_persistence()
            self.collect_execution_artifacts()
            self.collect_usb_artifacts()
            self.collect_filesystem_artifacts()
            self.collect_logs()
            self.collect_browser_data()
            self.collect_network_artifacts()
            self.collect_registry_hives()
            self.finalize()

            duration = (utc_now() - self.start_time).total_seconds()
            print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    COLLECTION COMPLETE                        ║
╠══════════════════════════════════════════════════════════════╣
║  Duration: {duration:>6.1f} seconds                                   ║
║  Evidence Files: {len(self.hash_list):>4}                                        ║
║  Output: {self.output_dir:<50} ║
╚══════════════════════════════════════════════════════════════╝
            """)
        except Exception as e:
            self.log_error("run_collection", str(e))
            raise


# ==========================================
# MAIN ENTRY POINT
# ==========================================

if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')

    if not is_admin():
        print("\n[!] ERROR: This collector requires Administrator privileges.")
        print("[!] Please right-click and 'Run as Administrator'.\n")
        input("Press Enter to exit...")
        sys.exit(1)

    config = CollectorConfig(
        collect_ram=True,
        collect_mft=True,
        collect_srum=True,
        process_signature_check=True,
        max_file_hash_size_mb=10,
        recent_files_days=30
    )

    collector = ForensicCollector(config)
    collector.run_collection()

    input("\nPress Enter to exit...")

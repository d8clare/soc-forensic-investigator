"""
Cross-artifact correlation for process-network-event analysis.
"""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

import pandas as pd


@dataclass
class ProcessContext:
    """Complete context for a process including network and events."""
    pid: int
    name: str
    cmdline: str
    parent_pid: int
    parent_name: str
    username: str
    exe_path: str
    signature_status: str
    sha256: str
    create_time: str
    network_connections: List[Dict[str, Any]] = field(default_factory=list)
    child_processes: List[Dict[str, Any]] = field(default_factory=list)
    related_events: List[Dict[str, Any]] = field(default_factory=list)


class ArtifactCorrelator:
    """
    Correlates artifacts across different data sources for enriched analysis.
    """

    def __init__(self):
        self.processes: Dict[int, Dict] = {}
        self.network_by_pid: Dict[int, List[Dict]] = {}
        self.process_tree: Dict[int, List[int]] = {}  # parent_pid -> [child_pids]
        self.events: List[Dict] = []

    def load_processes(self, processes: List[Dict]):
        """
        Load process data for correlation.

        Args:
            processes: List of process dictionaries
        """
        self.processes = {}
        self.process_tree = {}

        for proc in processes:
            pid = proc.get('pid')
            if pid:
                self.processes[pid] = proc

                # Build process tree
                parent_pid = proc.get('parent_pid')
                if parent_pid:
                    if parent_pid not in self.process_tree:
                        self.process_tree[parent_pid] = []
                    self.process_tree[parent_pid].append(pid)

    def load_network(self, connections: List[Dict]):
        """
        Load network connection data and index by PID.

        Args:
            connections: List of network connection dictionaries
        """
        self.network_by_pid = {}

        for conn in connections:
            pid = conn.get('pid')
            if pid:
                if pid not in self.network_by_pid:
                    self.network_by_pid[pid] = []
                self.network_by_pid[pid].append(conn)

    def load_events(self, events: List[Dict]):
        """
        Load event log data.

        Args:
            events: List of event dictionaries
        """
        self.events = events

    def get_process_context(self, pid: int) -> Optional[ProcessContext]:
        """
        Get complete context for a process including network and child info.

        Args:
            pid: Process ID to look up

        Returns:
            ProcessContext with all correlated data or None
        """
        if pid not in self.processes:
            return None

        proc = self.processes[pid]

        # Get network connections for this process
        network = self.network_by_pid.get(pid, [])

        # Get child processes
        child_pids = self.process_tree.get(pid, [])
        children = [self.processes[cpid] for cpid in child_pids if cpid in self.processes]

        return ProcessContext(
            pid=pid,
            name=proc.get('name', ''),
            cmdline=proc.get('cmdline', ''),
            parent_pid=proc.get('parent_pid', 0),
            parent_name=proc.get('parent_name', ''),
            username=proc.get('username', ''),
            exe_path=proc.get('exe', ''),
            signature_status=proc.get('SignatureStatus', 'Unknown'),
            sha256=proc.get('sha256', ''),
            create_time=proc.get('create_time', ''),
            network_connections=network,
            child_processes=children,
            related_events=[]
        )

    def get_process_tree(self, root_pid: int, max_depth: int = 5) -> Dict:
        """
        Build a process tree starting from a root process.

        Args:
            root_pid: Starting process ID
            max_depth: Maximum depth to traverse

        Returns:
            Nested dictionary representing the process tree
        """
        if max_depth <= 0 or root_pid not in self.processes:
            return {}

        proc = self.processes[root_pid]
        child_pids = self.process_tree.get(root_pid, [])

        return {
            'pid': root_pid,
            'name': proc.get('name', ''),
            'cmdline': proc.get('cmdline', ''),
            'children': [
                self.get_process_tree(cpid, max_depth - 1)
                for cpid in child_pids
            ]
        }

    def get_network_summary(self, pid: int) -> Dict[str, Any]:
        """
        Get network activity summary for a process.

        Args:
            pid: Process ID

        Returns:
            Summary dictionary with connection counts and IPs
        """
        connections = self.network_by_pid.get(pid, [])

        if not connections:
            return {"total": 0, "established": 0, "remote_ips": []}

        established = [c for c in connections if c.get('status') == 'ESTABLISHED']

        remote_ips = set()
        for conn in connections:
            raddr = conn.get('raddr', '')
            if raddr and ':' in str(raddr):
                ip = str(raddr).split(':')[0]
                if ip not in ['0.0.0.0', '127.0.0.1', '::', 'localhost']:
                    remote_ips.add(ip)

        return {
            "total": len(connections),
            "established": len(established),
            "remote_ips": list(remote_ips)
        }

    def get_suspicious_chains(self) -> List[Dict]:
        """
        Find suspicious parent-child process chains.

        Returns:
            List of suspicious process chains with details
        """
        suspicious = []

        # Office applications spawning shells
        office_apps = ['winword', 'excel', 'outlook', 'powerpnt', 'onenote']
        shell_apps = ['cmd', 'powershell', 'wscript', 'cscript', 'mshta']

        for pid, children in self.process_tree.items():
            if pid not in self.processes:
                continue

            parent = self.processes[pid]
            parent_name = parent.get('name', '').lower().replace('.exe', '')

            if parent_name in office_apps:
                for child_pid in children:
                    if child_pid not in self.processes:
                        continue

                    child = self.processes[child_pid]
                    child_name = child.get('name', '').lower().replace('.exe', '')

                    if child_name in shell_apps:
                        suspicious.append({
                            'type': 'Office Spawn Shell',
                            'severity': 'critical',
                            'parent': parent,
                            'child': child,
                            'description': f"{parent.get('name')} spawned {child.get('name')}"
                        })

        return suspicious

    def get_processes_with_network(self) -> List[Dict]:
        """
        Get all processes that have network activity.

        Returns:
            List of processes with their network connections
        """
        result = []

        for pid, connections in self.network_by_pid.items():
            if pid in self.processes and connections:
                proc = self.processes[pid].copy()
                proc['network_connections'] = connections
                proc['connection_count'] = len(connections)
                result.append(proc)

        return sorted(result, key=lambda x: x['connection_count'], reverse=True)

    def find_processes_by_remote_ip(self, ip: str) -> List[Dict]:
        """
        Find all processes connected to a specific remote IP.

        Args:
            ip: Remote IP address to search for

        Returns:
            List of processes with connections to that IP
        """
        result = []

        for pid, connections in self.network_by_pid.items():
            for conn in connections:
                raddr = str(conn.get('raddr', ''))
                if ip in raddr and pid in self.processes:
                    proc = self.processes[pid].copy()
                    proc['matching_connection'] = conn
                    result.append(proc)
                    break

        return result

    def create_pid_name_map(self) -> Dict[int, str]:
        """
        Create a mapping of PID to process name.

        Returns:
            Dictionary mapping PID to process name
        """
        return {pid: proc.get('name', 'Unknown') for pid, proc in self.processes.items()}

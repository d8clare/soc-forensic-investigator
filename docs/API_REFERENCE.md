# API Reference

## Core Modules

### RiskEngine

The main detection engine with MITRE ATT&CK integration.

```python
from core.risk_engine import RiskEngine, Finding
```

#### Initialization

```python
engine = RiskEngine(
    rules_path="config/risk_rules.json",  # Optional
    whitelist_path="config/whitelist.json"  # Optional
)
```

#### Methods

##### assess_process(row: pd.Series) -> int
Analyze a process for suspicious indicators.

```python
import pandas as pd

process = pd.Series({
    "name": "powershell.exe",
    "parent_name": "explorer.exe",
    "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "cmdline": "powershell -NoProfile -ExecutionPolicy Bypass",
    "pid": 1234,
    "SignatureStatus": "Valid"
})

score = engine.assess_process(process)
```

##### assess_network(row: pd.Series) -> str
Analyze a network connection.

```python
connection = pd.Series({
    "raddr": "192.168.1.100:4444",
    "laddr": "10.0.0.5:54321",
    "pid": 1234,
    "name": "cmd.exe",
    "status": "ESTABLISHED"
})

status = engine.assess_network(connection)
# Returns: "High Risk Port", "Normal", "Tor Connection", etc.
```

##### assess_event(event_id: int, event_details: dict) -> Optional[Finding]
Analyze a Windows event log entry.

```python
finding = engine.assess_event(
    event_id=1102,
    event_details={
        "LogName": "Security",
        "Time": "2026-02-07 14:30:00",
        "Message": "The audit log was cleared"
    }
)
```

##### assess_dns(name: str) -> str
Analyze a DNS query.

```python
status = engine.assess_dns("suspicious-domain.xyz")
# Returns: "Crypto Mining Pool", "DGA Domain", "Normal", etc.
```

##### assess_anti_forensics(entry: dict, source_type: str) -> Optional[Finding]
Detect anti-forensics activity.

```python
finding = engine.assess_anti_forensics({
    "cmdline": "vssadmin delete shadows /all",
    "name": "cmd.exe"
}, source_type="process")
```

##### assess_kerberos_attack(entry: dict, source_type: str) -> Optional[Finding]
Detect Kerberos attacks (Kerberoasting, Golden Ticket, etc.)

```python
finding = engine.assess_kerberos_attack({
    "cmdline": "Invoke-Kerberoast",
    "name": "powershell.exe"
}, source_type="process")
```

##### assess_brute_force(events: list) -> List[Finding]
Analyze events for brute force patterns.

```python
events = [
    {"EventID": 4625, "TargetUserName": "admin", "IpAddress": "10.0.0.1"},
    {"EventID": 4625, "TargetUserName": "admin", "IpAddress": "10.0.0.1"},
    # ... more failed logons
]
findings = engine.assess_brute_force(events)
```

##### get_global_score() -> int
Get the aggregated risk score (0-100).

```python
score = engine.get_global_score()
```

##### get_severity() -> str
Get severity level based on score.

```python
severity = engine.get_severity()
# Returns: "critical", "high", "medium", "low", "info"
```

##### get_top_findings(n: int = 5) -> List[Finding]
Get top findings by score.

```python
top5 = engine.get_top_findings(5)
for finding in top5:
    print(f"{finding.category}: {finding.score}")
```

##### reset()
Clear all findings for new analysis.

```python
engine.reset()
```

#### Finding Dataclass

```python
@dataclass
class Finding:
    category: str           # Category name
    description: str        # What was detected
    score: int              # Risk score (0-100)
    severity: str           # critical/high/medium/low/info
    mitre_techniques: List[str]  # MITRE IDs
    source: str             # Data source (process, network, etc.)
    evidence: Dict[str, Any]  # Raw evidence data
    confidence: str         # high/medium/low
    whitelisted: bool       # Whitelist applied?
    whitelist_reason: str   # Why whitelisted
    original_score: int     # Score before whitelist
```

---

### SigmaEngine

Sigma rule matching engine.

```python
from core.sigma_engine import SigmaEngine, YAML_AVAILABLE
```

#### Initialization

```python
if YAML_AVAILABLE:
    sigma = SigmaEngine("rules/sigma/")
    print(f"Loaded {len(sigma.rules)} rules")
```

#### Methods

##### match_process(process: dict) -> List[SigmaMatch]
Match a process against all rules.

```python
matches = sigma.match_process({
    "Image": "C:\\Windows\\System32\\cmd.exe",
    "CommandLine": "cmd /c whoami",
    "ParentImage": "C:\\Windows\\System32\\powershell.exe"
})

for match in matches:
    print(f"Rule: {match.rule_name}")
    print(f"Severity: {match.severity}")
    print(f"MITRE: {match.mitre_techniques}")
```

##### get_stats() -> dict
Get rule statistics.

```python
stats = sigma.get_stats()
print(f"Rules loaded: {stats['total_rules']}")
print(f"Matches found: {stats['matches_found']}")
```

---

### YaraEngine

YARA scanning engine.

```python
from core.yara_engine import YaraEngine, YARA_AVAILABLE
```

#### Initialization

```python
if YARA_AVAILABLE:
    yara = YaraEngine("rules/yara/")
```

#### Methods

##### scan_file(file_path: str) -> List[YaraMatch]
Scan a single file.

```python
matches = yara.scan_file("/path/to/suspect.exe")
```

##### scan_directory(dir_path: str, recursive: bool = True) -> List[YaraMatch]
Scan all files in a directory.

```python
matches = yara.scan_directory("Evidence_HOST/", recursive=True)
```

##### is_available() -> bool
Check if YARA is working.

```python
if yara.is_available():
    # Scan files
```

---

### DataLoader

Load and sanitize JSON evidence files.

```python
from core.data_loader import load_json, sanitize_dataframe
```

#### Functions

##### load_json(folder: str, filename: str) -> Optional[list]
Load a JSON file from evidence folder.

```python
processes = load_json("Evidence_HOST_20260207/", "processes.json")
```

##### sanitize_dataframe(df: pd.DataFrame) -> pd.DataFrame
Clean DataFrame for display.

```python
df = pd.DataFrame(processes)
df_clean = sanitize_dataframe(df)
```

---

### EvidenceCache

Preload all evidence into session state.

```python
from core.evidence_cache import load_all_evidence, get_evidence
```

#### Functions

##### load_all_evidence(folder: str) -> dict
Load all evidence files at once.

```python
all_data = load_all_evidence("Evidence_HOST_20260207/")
```

##### get_evidence(folder: str, artifact_type: str) -> Optional[list]
Get specific artifact from cache.

```python
processes = get_evidence(folder, "processes")
network = get_evidence(folder, "network")
events = get_evidence(folder, "events")
```

---

### PivotEngine

Cross-artifact correlation.

```python
from core.pivot_engine import PivotEngine
```

#### Initialization

```python
pivot = PivotEngine(evidence_folder="Evidence_HOST_20260207/")
```

#### Methods

##### search_all(query: str, case_sensitive: bool = False) -> dict
Search across all artifacts.

```python
results = pivot.search_all("mimikatz")
# Returns: {"processes": [...], "network": [...], "events": [...]}
```

##### pivot_on_indicator(indicator: str, indicator_type: str) -> dict
Find all references to an indicator.

```python
# Pivot on IP address
results = pivot.pivot_on_indicator("192.168.1.100", "ip")

# Pivot on file hash
results = pivot.pivot_on_indicator("abc123...", "hash")

# Pivot on username
results = pivot.pivot_on_indicator("DOMAIN\\admin", "user")
```

---

### ThreatIntelEngine

Threat intelligence lookups.

```python
from core.threat_intel import ThreatIntelEngine
```

#### Initialization

```python
intel = ThreatIntelEngine()
```

#### Methods

##### check_ip(ip: str) -> Optional[ThreatIndicator]
Check IP against threat feeds.

```python
result = intel.check_ip("1.2.3.4")
if result:
    print(f"Threat: {result.threat_type}")
    print(f"Confidence: {result.confidence}")
```

##### check_domain(domain: str) -> Optional[ThreatIndicator]
Check domain against threat feeds.

```python
result = intel.check_domain("evil.com")
```

##### check_hash(hash: str) -> Optional[ThreatIndicator]
Check file hash against threat feeds.

```python
result = intel.check_hash("abc123...")
```

##### analyze_network_connections(connections: list) -> List[ThreatIndicator]
Bulk analyze network connections.

```python
indicators = intel.analyze_network_connections(network_data)
```

---

### Security Module

Secure key storage and utilities.

```python
from core.security import get_api_key, SecureKeyStorage, escape_html
```

#### Functions

##### get_api_key(key_name: str) -> Optional[str]
Retrieve encrypted API key.

```python
vt_key = get_api_key("virustotal")
```

##### escape_html(text: str) -> str
Sanitize text for HTML display.

```python
safe_text = escape_html(user_input)
```

---

## Tab Modules

All tab modules follow the same interface:

```python
def render(evidence_folder: str, risk_engine: RiskEngine):
    """Render the tab content."""
    pass
```

### Example Custom Tab

```python
# tabs/custom_tab.py
import streamlit as st
from core.data_loader import load_json
from core.risk_engine import RiskEngine

def render(evidence_folder: str, risk_engine: RiskEngine):
    st.header("Custom Analysis")

    # Load data
    data = load_json(evidence_folder, "custom_artifact.json")

    if not data:
        st.warning("No custom artifacts found.")
        return

    # Display
    st.dataframe(data)

    # Add findings
    for item in data:
        if item.get("suspicious"):
            from core.risk_engine import Finding
            finding = Finding(
                category="Custom Detection",
                description="Suspicious item found",
                score=35,
                severity="high",
                mitre_techniques=["T1059"],
                source="custom",
                evidence=item
            )
            risk_engine._add_finding(finding)
```

### Adding to Dashboard

In `dashboard.py`:

```python
from tabs import custom_tab

# In tab list
tab_names = [..., "Custom"]

# In tab rendering
with tabs[-1]:
    custom_tab.render(selected_folder, risk_engine)
```

---

## Utility Functions

### Timestamp Helpers (collector.py)

```python
from collector import utc_now, to_utc_str, timestamp_from_epoch

# Current UTC time
now = utc_now()

# Format datetime to string
time_str = to_utc_str(now)  # "2026-02-07 14:30:00 UTC"

# Convert epoch to string
time_str = timestamp_from_epoch(1707312600.0)
```

### Hash Calculation

```python
import hashlib

def calculate_sha256(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()
```

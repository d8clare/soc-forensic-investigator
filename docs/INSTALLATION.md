# Installation Guide

## System Requirements

### Minimum Requirements
- **OS**: Windows 10/11 or Windows Server 2016+
- **Python**: 3.9 or higher
- **RAM**: 4 GB (8 GB recommended for large evidence sets)
- **Disk**: 500 MB for application + space for evidence

### For Evidence Collection
- **Administrator privileges** (required)
- **PowerShell 5.1+** (included in Windows 10+)

---

## Installation Methods

### Method 1: Standard Installation

```powershell
# 1. Clone the repository
git clone https://github.com/d8clare/soc-forensic-investigator.git
cd soc-forensic-investigator

# 2. Create virtual environment (recommended)
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify installation
python -c "import streamlit; print('Streamlit OK')"
python -c "import psutil; print('psutil OK')"
```

### Method 2: USB Portable Installation

For incident response, you may want a fully portable setup:

```powershell
# 1. Download Python Embeddable
# Get python-3.11.x-embed-amd64.zip from python.org

# 2. Extract to USB drive
# E:\soc-forensic-investigator\Python_Portable\

# 3. Install pip in embeddable Python
cd E:\soc-forensic-investigator\Python_Portable
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py

# 4. Install requirements
python -m pip install -r ..\requirements.txt
```

### Method 3: Offline Installation

For air-gapped environments:

```powershell
# On internet-connected machine:
pip download -r requirements.txt -d ./packages

# Copy packages folder to target machine, then:
pip install --no-index --find-links=./packages -r requirements.txt
```

---

## Dependencies

### Core Dependencies
| Package | Version | Purpose |
|---------|---------|---------|
| streamlit | >=1.28.0 | Web dashboard framework |
| pandas | >=2.0.0 | Data manipulation |
| plotly | >=5.15.0 | Interactive charts |
| psutil | >=5.9.0 | Process/system information |
| pywin32 | >=306 | Windows API access |
| pycryptodome | >=3.19.0 | DPAPI decryption |

### Optional Dependencies
| Package | Version | Purpose |
|---------|---------|---------|
| pyyaml | >=6.0.1 | Sigma rule parsing |
| yara-python | >=4.3.0 | YARA scanning |
| requests | >=2.31.0 | Threat intelligence APIs |

---

## Post-Installation Setup

### 1. Configure Authentication (Optional)

On first run, you'll be prompted to set a PIN. To disable authentication:

```json
// config/auth_config.json
{
  "enabled": false
}
```

### 2. Add Detection Rules (Optional)

**Sigma Rules**: Place `.yml` files in `rules/sigma/` or `config/sigma_rules/`

**YARA Rules**: Place `.yar` files in `rules/yara/`

### 3. Configure Whitelisting

Edit `config/whitelist.json` to reduce false positives for your environment:

```json
{
  "processes": {
    "known_good_lolbins": {
      "patterns": [
        {"process": "powershell.exe", "parent": "sccm", "reason": "SCCM management"}
      ]
    }
  }
}
```

### 4. Add RAM Dump Tool (Optional)

For memory acquisition, download DumpIt.exe and place in `tools/`:
- Comae DumpIt: https://www.yourdownloadlink.com

---

## Verification

### Test Collector
```powershell
# Run as Administrator
python collector.py --help
```

### Test Dashboard
```powershell
streamlit run dashboard.py
# Opens browser at http://localhost:8501
```

### Test Detection Engines
```python
from core.risk_engine import RiskEngine
from core.sigma_engine import SigmaEngine, YAML_AVAILABLE
from core.yara_engine import YaraEngine, YARA_AVAILABLE

print(f"Sigma available: {YAML_AVAILABLE}")
print(f"YARA available: {YARA_AVAILABLE}")

engine = RiskEngine()
print(f"Risk rules loaded: {len(engine.rules)} categories")
```

---

## Troubleshooting

### "pywin32 not found"
```powershell
pip install pywin32
python -c "import win32api"  # Verify
```

### "Streamlit command not found"
```powershell
# Add to PATH or use full path
python -m streamlit run dashboard.py
```

### "Access denied" during collection
- Right-click terminal → "Run as Administrator"
- Or use `runas /user:Administrator python collector.py`

### "YARA module not found"
YARA is optional. Install with:
```powershell
pip install yara-python
```

If compilation fails on Windows, use pre-built wheel from:
https://github.com/VirusTotal/yara-python/releases

---

## Updating

```powershell
cd soc-forensic-investigator
git pull origin master
pip install -r requirements.txt --upgrade
```

---

## Uninstallation

```powershell
# Remove virtual environment
rmdir /s /q venv

# Remove application
rmdir /s /q soc-forensic-investigator

# Evidence folders are in Evidence_HOSTNAME_* - remove as needed
```

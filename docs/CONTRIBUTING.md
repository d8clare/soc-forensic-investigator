# Contributing Guide

Thank you for your interest in contributing to SOC Forensic Investigator!

## Ways to Contribute

### 1. Report Bugs
- Use GitHub Issues
- Include steps to reproduce
- Attach relevant log files (sanitize sensitive data)

### 2. Suggest Features
- Open a GitHub Issue with `[Feature]` prefix
- Describe the use case
- Explain how it helps SOC analysts

### 3. Add Detection Rules
- Submit new Sigma or YARA rules
- Include test cases
- Document the threat being detected

### 4. Improve Documentation
- Fix typos or unclear sections
- Add examples
- Translate to other languages

### 5. Submit Code
- Bug fixes
- New features
- Performance improvements

---

## Development Setup

### 1. Fork and Clone
```bash
git clone https://github.com/YOUR_USERNAME/soc-forensic-investigator.git
cd soc-forensic-investigator
```

### 2. Create Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\Activate.ps1  # Windows
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
pip install pytest black flake8  # Dev dependencies
```

### 4. Create Feature Branch
```bash
git checkout -b feature/your-feature-name
```

---

## Code Style

### Python Style
- Follow PEP 8
- Use meaningful variable names
- Add docstrings to functions
- Maximum line length: 100 characters

### Formatting
```bash
# Format code
black --line-length 100 .

# Check linting
flake8 --max-line-length 100 .
```

### Example Function

```python
def assess_new_artifact(self, entry: dict) -> Optional[Finding]:
    """
    Assess a new artifact type for suspicious indicators.

    Args:
        entry: Dictionary containing artifact data with keys:
            - name: Artifact name
            - path: File path (optional)
            - data: Raw data

    Returns:
        Finding if suspicious activity detected, None otherwise.

    MITRE Techniques:
        - T1059: Command and Scripting Interpreter
    """
    name = str(entry.get('name', '')).lower()

    # Detection logic
    if 'suspicious_pattern' in name:
        return Finding(
            category="New Artifact Detection",
            description=f"Suspicious pattern in {name}",
            score=35,
            severity="high",
            mitre_techniques=["T1059"],
            source="new_artifact",
            evidence=entry
        )

    return None
```

---

## Adding New Artifacts

### 1. Update Collector

```python
# collector.py

def collect_new_artifact(self):
    """Collect new artifact type."""
    phase_start = self.log_phase("New Artifact...")

    data = []

    try:
        # Collection logic here
        result = self._collect_artifact_data()
        data.extend(result)
    except Exception as e:
        self.log_error("collect_new_artifact", str(e))

    self.save_json("new_artifact.json", data)
    self.log(f"    ✓ Collected {len(data)} items")
    self.log_phase_complete("New Artifact", phase_start)
```

### 2. Update Evidence Cache

```python
# core/evidence_cache.py

FILE_MAPPINGS = {
    # ... existing mappings ...
    "new_artifact": "new_artifact.json",
}
```

### 3. Add Assessment Method

```python
# core/risk_engine.py

def assess_new_artifact(self, entry: dict) -> Optional[Finding]:
    # Detection logic
    pass
```

### 4. Create Dashboard Tab

```python
# tabs/new_artifact.py

def render(evidence_folder: str, risk_engine: RiskEngine):
    st.header("New Artifact")
    # Display logic
```

### 5. Register in Dashboard

```python
# dashboard.py

from tabs import new_artifact

# Add to tab list and rendering
```

---

## Adding Detection Rules

### Sigma Rules

1. Create rule file in `rules/sigma/`:

```yaml
title: My New Detection
id: unique-uuid-here
status: experimental
description: Detects specific threat pattern
author: Your Name
date: 2026/02/07
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'suspicious_string'
    condition: selection
falsepositives:
    - Legitimate use case
level: medium
tags:
    - attack.execution
    - attack.t1059
```

2. Test the rule:

```python
from core.sigma_engine import SigmaEngine

engine = SigmaEngine("rules/sigma/")
matches = engine.match_process({
    "CommandLine": "test suspicious_string test"
})
assert len(matches) > 0
```

### YARA Rules

1. Create rule file in `rules/yara/`:

```yara
rule My_New_Detection
{
    meta:
        description = "Detects specific threat"
        author = "Your Name"
        severity = "high"
        mitre = "T1059"

    strings:
        $s1 = "pattern1" ascii wide
        $s2 = "pattern2" ascii wide

    condition:
        any of them
}
```

2. Test the rule:

```python
from core.yara_engine import YaraEngine

engine = YaraEngine("rules/yara/")
# Create test file with pattern
matches = engine.scan_file("test_file.txt")
```

---

## Testing

### Run Tests
```bash
pytest tests/ -v
```

### Test Categories

```python
# tests/test_risk_engine.py

def test_encoded_command_detection():
    engine = RiskEngine()
    process = pd.Series({
        "name": "powershell.exe",
        "cmdline": "powershell -enc SGVsbG8=",
        "exe": "C:\\Windows\\System32\\powershell.exe"
    })
    score = engine.assess_process(process)
    assert score > 0
    assert any("Encoded" in f.category for f in engine.all_findings)

def test_whitelist_reduces_score():
    engine = RiskEngine(whitelist_path="config/whitelist.json")
    # Test whitelist application
```

---

## Pull Request Process

### 1. Before Submitting
- [ ] Code follows style guide
- [ ] Tests pass locally
- [ ] Documentation updated
- [ ] Commit messages are clear

### 2. PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Detection rule
- [ ] Documentation

## Testing
How was this tested?

## MITRE ATT&CK
Relevant techniques (if applicable):
- T1059 - Command and Scripting Interpreter

## Checklist
- [ ] Code follows project style
- [ ] Self-reviewed code
- [ ] Added tests
- [ ] Updated documentation
```

### 3. Review Process
1. Maintainer reviews code
2. Automated tests run
3. Changes requested if needed
4. Merged when approved

---

## Security Considerations

### Do NOT commit:
- API keys or credentials
- Evidence files
- Personal information
- Internal IP ranges

### Reporting Security Issues
- Email: security@yourproject.com
- Do NOT open public issues for vulnerabilities

---

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help newcomers learn
- Credit others' contributions

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

## Questions?

- Open a GitHub Discussion
- Check existing issues
- Read the documentation

Thank you for contributing!

"""
Integrity & Chain of Custody Tab.
Displays cryptographic hashes of collected evidence with verification tools.
"""
import streamlit as st
import pandas as pd
import os
import re
from datetime import datetime

from core.data_loader import load_json, sanitize_dataframe
from core.risk_engine import RiskEngine
from config.theme import THEME


# MITRE ATT&CK Techniques related to evidence integrity
MITRE_TECHNIQUES = {
    "T1485": {"name": "Data Destruction", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1485/"},
    "T1565": {"name": "Data Manipulation", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1565/"},
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1070/"},
}

# File type categories for analysis
FILE_CATEGORIES = {
    "executables": {
        "extensions": ['.exe', '.dll', '.sys', '.drv', '.ocx', '.scr', '.pif', '.com'],
        "icon": "⚙️",
        "description": "Executable files - high forensic value"
    },
    "scripts": {
        "extensions": ['.ps1', '.bat', '.cmd', '.vbs', '.js', '.wsf', '.hta', '.py', '.sh'],
        "icon": "📜",
        "description": "Script files - may contain malicious code"
    },
    "documents": {
        "extensions": ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.rtf', '.odt'],
        "icon": "📄",
        "description": "Document files - check for macros"
    },
    "archives": {
        "extensions": ['.zip', '.rar', '.7z', '.tar', '.gz', '.cab', '.iso'],
        "icon": "📦",
        "description": "Archive files - may contain hidden content"
    },
    "system": {
        "extensions": ['.reg', '.inf', '.ini', '.cfg', '.config', '.xml', '.json'],
        "icon": "🔧",
        "description": "System/config files - persistence indicators"
    },
    "database": {
        "extensions": ['.db', '.sqlite', '.mdb', '.accdb', '.sql', '.ldf', '.mdf'],
        "icon": "🗄️",
        "description": "Database files - may contain credentials"
    },
    "logs": {
        "extensions": ['.log', '.evt', '.evtx', '.etl'],
        "icon": "📋",
        "description": "Log files - event evidence"
    },
    "images": {
        "extensions": ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.webp'],
        "icon": "🖼️",
        "description": "Image files - check for steganography"
    },
    "memory": {
        "extensions": ['.dmp', '.hdmp', '.mdmp', '.vmem', '.raw'],
        "icon": "💾",
        "description": "Memory dumps - volatile data"
    }
}


def categorize_file(filepath: str) -> dict:
    """Categorize a file based on its extension."""
    if not filepath or pd.isna(filepath):
        return {"category": "other", "icon": "📁", "description": "Other files"}

    ext = os.path.splitext(str(filepath).lower())[1]

    for category, data in FILE_CATEGORIES.items():
        if ext in data["extensions"]:
            return {
                "category": category,
                "icon": data["icon"],
                "description": data["description"]
            }

    return {"category": "other", "icon": "📁", "description": "Other files"}


def get_filename(filepath: str) -> str:
    """Extract filename from path."""
    if not filepath or pd.isna(filepath):
        return "Unknown"
    return os.path.basename(str(filepath))


def validate_sha256(hash_str: str) -> bool:
    """Validate SHA256 hash format."""
    if not hash_str:
        return False
    return bool(re.match(r'^[a-fA-F0-9]{64}$', hash_str.strip()))


def analyze_evidence_stats(df: pd.DataFrame) -> dict:
    """Analyze evidence collection statistics."""
    stats = {
        "total_files": len(df),
        "unique_hashes": 0,
        "duplicate_hashes": 0,
        "categories": {},
        "extensions": {},
        "potential_issues": []
    }

    if df.empty:
        return stats

    # Count unique hashes
    if 'SHA256' in df.columns:
        unique_hashes = df['SHA256'].dropna().nunique()
        stats["unique_hashes"] = unique_hashes
        stats["duplicate_hashes"] = len(df) - unique_hashes

        if stats["duplicate_hashes"] > 0:
            stats["potential_issues"].append(f"{stats['duplicate_hashes']} duplicate file(s) detected")

    # Categorize files
    if 'Path' in df.columns:
        for path in df['Path'].dropna():
            cat_info = categorize_file(path)
            category = cat_info["category"]
            stats["categories"][category] = stats["categories"].get(category, 0) + 1

            ext = os.path.splitext(str(path).lower())[1]
            if ext:
                stats["extensions"][ext] = stats["extensions"].get(ext, 0) + 1

    return stats


def render(evidence_folder: str, risk_engine: RiskEngine):
    """
    Render the Integrity & Chain of Custody tab.

    Args:
        evidence_folder: Path to the evidence folder
        risk_engine: RiskEngine instance
    """
    # Check for registry hives
    hives_dir = os.path.join(evidence_folder, "registry_hives")
    registry_hives = []
    if os.path.exists(hives_dir):
        try:
            for f in os.listdir(hives_dir):
                fpath = os.path.join(hives_dir, f)
                if os.path.isfile(fpath):
                    size = os.path.getsize(fpath)
                    registry_hives.append({
                        'name': f,
                        'path': fpath,
                        'size': size
                    })
        except Exception:
            pass

    # Simple header with blue styling
    st.markdown(f'<div style="color:#e6edf3;font-size:1.1rem;margin-bottom:15px;"><b>Integrity</b> | Registry Hives: {len(registry_hives)}</div>', unsafe_allow_html=True)

    # Create subtabs
    tab_hashes, tab_verify, tab_manifest, tab_registry = st.tabs([
        "File Hashes", "Verify Hash", "Manifest", f"Registry Hives ({len(registry_hives)})"
    ])

    # Load hash data
    hashes = load_json(evidence_folder, "file_hashes.json")

    if not hashes:
        with tab_hashes:
            st.warning("No integrity hashes found in this evidence folder.")
        return

    df_hash = pd.DataFrame(hashes)

    # Analyze statistics
    stats = analyze_evidence_stats(df_hash)

    with tab_hashes:
        render_hashes_tab(df_hash, stats)

    # ==================== TAB 3: Verify Hash ====================
    with tab_verify:
        render_verify_tab(df_hash)

    # ==================== TAB 4: Manifest ====================
    with tab_manifest:
        render_manifest_tab(df_hash, evidence_folder)

    # ==================== TAB 5: Registry Hives ====================
    with tab_registry:
        render_registry_hives_tab(registry_hives, hives_dir)


def render_hashes_tab(df: pd.DataFrame, stats: dict):
    """Render the file hashes subtab."""

    # Filter Section
    col1, col2, col3 = st.columns([2, 1, 1])

    with col1:
        search = st.text_input("🔍 Search Filename / Hash", placeholder="Enter keywords...", key="hash_search")

    with col2:
        categories = ['All'] + [cat.title() for cat in stats['categories'].keys()]
        sel_category = st.selectbox("Category", categories, key="hash_cat")

    with col3:
        sort_by = st.selectbox("Sort By", ['Path', 'Category', 'Filename'], key="hash_sort")

    # Add category and filename columns
    df_display = df.copy()

    if 'Path' in df_display.columns:
        df_display['Filename'] = df_display['Path'].apply(get_filename)
        df_display['Category'] = df_display['Path'].apply(lambda x: categorize_file(x)['category'].title())
        df_display['Icon'] = df_display['Path'].apply(lambda x: categorize_file(x)['icon'])

    # Apply search filter
    if search:
        mask = df_display.astype(str).apply(
            lambda x: x.str.contains(search, case=False, na=False)
        ).any(axis=1)
        df_display = df_display[mask]

    # Apply category filter
    if sel_category != 'All':
        df_display = df_display[df_display['Category'] == sel_category]

    # Sort
    if sort_by == 'Category' and 'Category' in df_display.columns:
        df_display = df_display.sort_values('Category')
    elif sort_by == 'Filename' and 'Filename' in df_display.columns:
        df_display = df_display.sort_values('Filename')

    # Reorder columns
    display_cols = ['Icon', 'Category', 'Filename', 'SHA256', 'Path']
    existing_cols = [c for c in display_cols if c in df_display.columns]
    other_cols = [c for c in df_display.columns if c not in display_cols]
    df_display = df_display[existing_cols + other_cols]

    # Display table
    st.dataframe(
        sanitize_dataframe(df_display),
        width="stretch",
        column_config={
            "Icon": st.column_config.TextColumn("", width="small"),
            "Category": st.column_config.TextColumn("Type", width="medium"),
            "Filename": st.column_config.TextColumn("Filename", width="medium"),
            "SHA256": st.column_config.TextColumn("SHA256 Hash", width="large"),
            "Path": st.column_config.TextColumn("Full Path", width="large")
        },
        hide_index=True
    )

    st.caption(f"Showing {len(df_display):,} of {len(df):,} files | ⚙️ Exe 📜 Script 📄 Doc 📦 Archive 🔧 System 🗄️ DB 📋 Log")


def render_verify_tab(df: pd.DataFrame):
    """Render the hash verification subtab."""
    hash_input = st.text_input("SHA256 hash to verify:", placeholder="Enter hash...", key="verify_hash")

    if hash_input:
        hash_clean = hash_input.strip().lower()
        if not validate_sha256(hash_clean):
            st.error("Invalid SHA256 format (must be 64 hex characters)")
        elif 'SHA256' in df.columns:
            matches = df[df['SHA256'].str.lower() == hash_clean]
            if not matches.empty:
                for idx, row in matches.iterrows():
                    path = row.get('Path', 'Unknown')
                    st.success(f"Found: {get_filename(path)} - {path}")
            else:
                st.warning(f"Not found. [Check VirusTotal](https://www.virustotal.com/gui/file/{hash_clean})")


def render_manifest_tab(df: pd.DataFrame, evidence_folder: str):
    """Render the evidence manifest subtab."""
    col1, col2 = st.columns(2)
    with col1:
        case_number = st.text_input("Case Number:", "CASE-2024-001")
        examiner = st.text_input("Examiner:", "")
    with col2:
        collection_date = st.date_input("Collection Date:", datetime.now())
        organization = st.text_input("Organization:", "")

    if st.button("Generate Manifest"):
        manifest_lines = [
            "=" * 60,
            "DIGITAL EVIDENCE MANIFEST",
            "=" * 60,
            f"Case Number:      {case_number}",
            f"Examiner:         {examiner or 'Not specified'}",
            f"Organization:     {organization or 'Not specified'}",
            f"Collection Date:  {collection_date}",
            f"Generated:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Evidence Source:  {evidence_folder}",
            f"Total Files:      {len(df)}",
            "-" * 60,
            "FILE HASHES (SHA-256)",
            "-" * 60,
        ]
        for idx, row in df.iterrows():
            manifest_lines.append(f"{row.get('Path', 'Unknown')}")
            manifest_lines.append(f"  SHA256: {row.get('SHA256', 'Unknown')}")
        manifest_lines.append("-" * 60)
        manifest_text = '\n'.join(manifest_lines)

        st.text_area("Manifest:", manifest_text, height=300)

        col1, col2 = st.columns(2)
        with col1:
            st.download_button("Download TXT", manifest_text, f"manifest_{case_number}.txt", "text/plain")
        with col2:
            import json
            manifest_json = {
                "case_number": case_number, "examiner": examiner, "organization": organization,
                "collection_date": str(collection_date), "generated": datetime.now().isoformat(),
                "evidence_source": evidence_folder, "total_files": len(df), "files": df.to_dict('records')
            }
            st.download_button("Download JSON", json.dumps(manifest_json, indent=2), f"manifest_{case_number}.json", "application/json")


def render_registry_hives_tab(registry_hives: list, hives_dir: str):
    """Render the registry hives backup subtab."""
    if not registry_hives:
        st.info("No registry hive backups found.")
        return

    total_size = sum(h['size'] for h in registry_hives)
    size_mb = total_size / (1024 * 1024)
    st.caption(f"Hives: {len(registry_hives)} | Size: {size_mb:.1f} MB | Path: {hives_dir}")

    # Hive descriptions
    hive_info = {
        'sam': 'User accounts and password hashes',
        'system': 'System config, services, drivers',
        'software': 'Installed software, persistence keys',
        'security': 'Security policies, LSA secrets',
        'ntuser': 'User MRU lists, TypedURLs, UserAssist',
        'usrclass': 'Shellbags, file associations',
        'amcache': 'Program execution history',
    }

    # Build table with descriptions
    hive_rows = []
    for h in registry_hives:
        name_lower = h['name'].lower()
        desc = 'Registry hive'
        for key, val in hive_info.items():
            if key in name_lower:
                desc = val
                break
        hive_rows.append({
            'Name': h['name'],
            'Description': desc,
            'Size': f"{h['size']/1024:.1f} KB"
        })

    st.dataframe(pd.DataFrame(hive_rows), width="stretch", hide_index=True)

    # Analysis tools reference
    st.caption("Tools: RegRipper, Registry Explorer (EZ), RECmd, Autopsy")
    st.caption("Key paths: Run/RunOnce, UserAssist, Shimcache, USBSTOR")

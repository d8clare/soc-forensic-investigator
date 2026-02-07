"""
Drop Zone Analysis Tab - Professional Forensic Investigation View.
Displays recent files with risk scoring for suspicious payloads.
"""
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta

from core.data_loader import load_json, sanitize_dataframe
from core.risk_engine import RiskEngine


# Dangerous file extensions
DANGEROUS_EXTENSIONS = {
    'executable': ['.exe', '.dll', '.scr', '.pif', '.com', '.msi', '.msp'],
    'script': ['.ps1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta'],
    'office_macro': ['.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.xlam'],
    'archive': ['.zip', '.rar', '.7z', '.iso', '.img', '.cab'],
    'shortcut': ['.lnk', '.url', '.scf'],
}

# All dangerous extensions flattened
ALL_DANGEROUS = [ext for exts in DANGEROUS_EXTENSIONS.values() for ext in exts]

# Suspicious locations
SUSPICIOUS_LOCATIONS = [
    'temp', 'tmp', 'appdata\\local\\temp', 'appdata\\roaming',
    'programdata', 'public', 'recycle', '$recycle'
]


def render(evidence_folder: str, risk_engine: RiskEngine):
    """Render the File System Analysis tab."""

    # Load all data
    files_data = load_json(evidence_folder, "recent_files.json")
    jumplist_data = load_json(evidence_folder, "jump_lists.json")
    shellbags_data = load_json(evidence_folder, "shellbags.json")

    total_files = len(files_data or [])
    total_jumplists = len(jumplist_data or [])
    total_shellbags = len(shellbags_data or [])

    # Simple header with blue styling
    st.markdown(f'<div style="color:#e6edf3;font-size:1.1rem;margin-bottom:15px;"><b>Files</b> | Recent: {total_files} | Jump Lists: {total_jumplists} | Shellbags: {total_shellbags}</div>', unsafe_allow_html=True)

    # Create tabs
    file_tabs = st.tabs([
        f"Recent Files ({total_files})",
        f"Jump Lists ({total_jumplists})",
        f"Shellbags ({total_shellbags})"
    ])

    # Tab 1: Recent Files
    with file_tabs[0]:
        render_recent_files_tab(files_data, risk_engine)

    # Tab 2: Jump Lists
    with file_tabs[1]:
        render_jumplists_tab(jumplist_data)

    # Tab 3: Shellbags
    with file_tabs[2]:
        render_shellbags_tab(shellbags_data)


def render_recent_files_tab(files_data, risk_engine):
    """Render the Recent Files subtab."""

    if not files_data:
        st.info("No recent files found.")
        return

    # Analyze files for stats
    file_stats = analyze_file_stats(files_data, risk_engine)

    total_files = len(files_data)
    high_risk = file_stats.get('high_risk', 0)
    executables = file_stats.get('executables', 0)
    scripts = file_stats.get('scripts', 0)

    st.caption(f"High Risk: {high_risk} | Executables: {executables} | Scripts: {scripts} | Total: {total_files}")

    df = pd.DataFrame(files_data)

    # Filter Section
    col_search, col_type, col_risk = st.columns([2, 1.5, 1.5])

    with col_search:
        search_files = st.text_input("Search", placeholder="Filename or path...", key="files_search")

    with col_type:
        type_filter = st.selectbox("Type", ["All", "Executables", "Scripts", "Office Macros", "Archives", "Shortcuts"], key="files_type_filter")

    with col_risk:
        risk_filter = st.selectbox("Risk", ["All", "High Risk", "Suspicious", "Recent (24h)"], key="files_risk_filter")

    # Analyze each file
    def analyze_file(row):
        filename = str(row.get('filename', '')).lower()
        path = str(row.get('path', '')).lower()
        size_mb = row.get('size_mb', 0) or 0

        # Get base risk score
        score, reasons = risk_engine.assess_file(row)

        # Get extension
        ext = ''
        if '.' in filename:
            ext = '.' + filename.rsplit('.', 1)[-1]

        # Determine file type
        file_type = "Other"
        for type_name, extensions in DANGEROUS_EXTENSIONS.items():
            if ext in extensions:
                file_type = type_name.replace('_', ' ').title()
                break

        # Enhanced risk indicators
        if score >= 80 or ext in DANGEROUS_EXTENSIONS['executable'] or ext in DANGEROUS_EXTENSIONS['script']:
            risk = "🔴 High Risk"
        elif score >= 50 or ext in DANGEROUS_EXTENSIONS['office_macro']:
            risk = "🟠 Suspicious"
        elif score >= 20 or any(loc in path for loc in SUSPICIOUS_LOCATIONS):
            risk = "🟡 Notable"
        else:
            risk = "✅ Normal"

        # Check for double extensions (masquerading) - smart detection
        # Only flag when harmless-looking extension is followed by dangerous one
        # Example: invoice.pdf.exe (malicious) vs report.final.docx (legitimate)
        if filename.count('.') >= 2:
            parts = filename.split('.')
            if len(parts) >= 3:
                second_to_last = parts[-2].lower()
                last_ext = parts[-1].lower()

                # Decoy extensions that look harmless
                decoy_exts = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf',
                              'jpg', 'jpeg', 'png', 'gif', 'bmp', 'mp3', 'mp4', 'wav', 'avi',
                              'zip', 'rar', '7z', 'csv', 'xml', 'html', 'htm'}

                # Dangerous extensions that can execute
                dangerous_exts = {'exe', 'scr', 'bat', 'cmd', 'ps1', 'vbs', 'vbe', 'js', 'jse',
                                  'wsf', 'wsh', 'hta', 'pif', 'com', 'msi', 'dll', 'lnk', 'jar'}

                # [decoy].[dangerous] - Classic masquerading attack
                if second_to_last in decoy_exts and last_ext in dangerous_exts:
                    risk = "🔴 High Risk"
                    reasons.append(f"Double extension masquerading (.{second_to_last}.{last_ext})")

                # [dangerous].[harmless] - Potentially renamed malware
                elif second_to_last in dangerous_exts and last_ext in decoy_exts:
                    if risk != "🔴 High Risk":  # Don't downgrade if already high risk
                        risk = "🟠 Suspicious"
                    reasons.append(f"Potentially renamed executable (.{second_to_last}.{last_ext})")

        return pd.Series([risk, score, file_type, ', '.join(reasons) if reasons else 'No issues'])

    df[['Risk', 'Score', 'Type', 'Analysis']] = df.apply(analyze_file, axis=1)

    # Parse timestamps
    if 'created' in df.columns:
        df['created'] = pd.to_datetime(df['created'], errors='coerce')

    # Apply search filter
    if search_files:
        search_lower = search_files.lower()
        df = df[
            df['filename'].str.lower().str.contains(search_lower, na=False) |
            df['path'].str.lower().str.contains(search_lower, na=False)
        ]

    # Apply type filter
    type_map = {
        "Executables": "Executable",
        "Scripts": "Script",
        "Office Macros": "Office Macro",
        "Archives": "Archive",
        "Shortcuts": "Shortcut"
    }
    if type_filter != "All":
        df = df[df['Type'] == type_map.get(type_filter, type_filter)]

    # Apply risk filter
    if risk_filter == "High Risk":
        df = df[df['Risk'].str.contains("🔴")]
    elif risk_filter == "Suspicious":
        df = df[df['Risk'].str.contains("🔴|🟠", regex=True)]
    elif risk_filter == "Recent (24h)" and 'created' in df.columns:
        cutoff = datetime.now() - timedelta(hours=24)
        df = df[df['created'] >= cutoff]

    # Sort by score (highest first)
    df = df.sort_values('Score', ascending=False)

    st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(df)} files</div>', unsafe_allow_html=True)

    # Data table
    column_order = ["Risk", "filename", "Type", "created", "size_mb", "Analysis", "path", "sha256"]

    st.dataframe(
        sanitize_dataframe(df),
        column_order=[c for c in column_order if c in df.columns],
        width="stretch",
        height=400,
        column_config={
            "Risk": st.column_config.TextColumn("Risk", width="small"),
            "filename": st.column_config.TextColumn("Filename", width="medium"),
            "Type": st.column_config.TextColumn("Type", width="small"),
            "created": st.column_config.DatetimeColumn("Created", format="D/M/Y H:mm"),
            "size_mb": st.column_config.NumberColumn("Size (MB)", format="%.2f"),
            "Analysis": st.column_config.TextColumn("Analysis", width="medium"),
            "path": st.column_config.TextColumn("Path", width="large"),
            "sha256": st.column_config.TextColumn("SHA256", width="medium")
        },
        hide_index=True
    )

    # Export section
    st.markdown("---")
    high_risk_df = df[df['Risk'].str.contains("🔴")]
    col1, col2, col3 = st.columns(3)

    with col1:
        df_export = df[['filename', 'path', 'created', 'size_mb', 'Risk', 'Type', 'Analysis', 'sha256']].copy()
        df_export['created'] = df_export['created'].dt.strftime('%Y-%m-%d %H:%M:%S')
        st.download_button("📁 Export All Files", df_export.to_csv(index=False), "recent_files.csv", "text/csv", key="files_export")

    with col2:
        if not high_risk_df.empty:
            hr_export = high_risk_df[['filename', 'path', 'created', 'size_mb', 'Analysis', 'sha256']].copy()
            if 'created' in hr_export.columns:
                hr_export['created'] = hr_export['created'].dt.strftime('%Y-%m-%d %H:%M:%S')
            st.download_button(f"🔴 Export High Risk ({len(high_risk_df)})", hr_export.to_csv(index=False), "high_risk_files.csv", "text/csv", key="hr_export")
        else:
            st.button("🔴 No High Risk Files", disabled=True, key="hr_export_disabled")

    with col3:
        # Export hashes only
        if 'sha256' in df.columns:
            hashes = df['sha256'].dropna().tolist()
            if hashes:
                hash_content = '\n'.join(hashes)
                st.download_button("🔑 Export Hashes", hash_content, "file_hashes.txt", "text/plain", key="hash_export")
            else:
                st.button("🔑 No Hashes", disabled=True, key="hash_export_disabled")
        else:
            st.button("🔑 No Hashes", disabled=True, key="hash_export_disabled2")


def analyze_file_stats(files_data, risk_engine):
    """Analyze files for statistics."""
    stats = {'high_risk': 0, 'executables': 0, 'scripts': 0, 'recent_24h': 0}

    cutoff_24h = datetime.now() - timedelta(hours=24)

    for f in files_data:
        filename = str(f.get('filename', '')).lower()
        score, _ = risk_engine.assess_file(f)

        # Get extension
        ext = ''
        if '.' in filename:
            ext = '.' + filename.rsplit('.', 1)[-1]

        # Count by type
        if ext in DANGEROUS_EXTENSIONS['executable']:
            stats['executables'] += 1
        if ext in DANGEROUS_EXTENSIONS['script']:
            stats['scripts'] += 1

        # Count high risk
        if score >= 80 or ext in DANGEROUS_EXTENSIONS['executable'] or ext in DANGEROUS_EXTENSIONS['script']:
            stats['high_risk'] += 1

        # Count recent
        created = f.get('created')
        if created:
            try:
                created_dt = pd.to_datetime(created)
                if created_dt >= cutoff_24h:
                    stats['recent_24h'] += 1
            except:
                pass

    return stats


def render_jumplists_tab(jumplist_data):
    """Render the Jump Lists subtab."""


    if not jumplist_data:
        st.info("No Jump List data collected. Jump Lists show recently accessed files for each application.")
        return

    df = pd.DataFrame(jumplist_data)

    # Search and filter
    col_search, col_filter = st.columns([3, 2])

    with col_search:
        search_jl = st.text_input("🔍 Search", placeholder="Search path or application...", key="jl_search")

    with col_filter:
        risk_filter = st.selectbox("Filter", ["All Entries", "Suspicious Only", "Executables Only"], key="jl_filter")

    # Risk analysis - use collector field names: TargetPath, Application, AppId, AccessTime
    def analyze_jumplist_risk(row):
        # Handle both old and new field names
        path = str(row.get('TargetPath', row.get('target_path', row.get('path', '')))).lower()
        filename = path.split('\\')[-1] if '\\' in path else path

        # Check for dangerous extensions
        for ext_list in DANGEROUS_EXTENSIONS.values():
            for ext in ext_list:
                if filename.endswith(ext):
                    return "🔴 Suspicious"

        # Check for suspicious paths
        if any(loc in path for loc in SUSPICIOUS_LOCATIONS):
            return "🟠 Notable"

        return "✅ Normal"

    df['Risk'] = df.apply(analyze_jumplist_risk, axis=1)

    # Parse timestamps - handle collector's AccessTime field
    for col in ['AccessTime', 'access_time', 'modified_time', 'creation_time']:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors='coerce')

    # Apply search
    if search_jl:
        search_lower = search_jl.lower()
        mask = df.astype(str).apply(lambda x: x.str.lower().str.contains(search_lower, na=False)).any(axis=1)
        df = df[mask]

    # Apply risk filter
    if risk_filter == "Suspicious Only":
        df = df[df['Risk'].str.contains("🔴|🟠", regex=True)]
    elif risk_filter == "Executables Only":
        # Handle both field naming conventions
        df = df[df.apply(lambda r: any(str(r.get('TargetPath', r.get('target_path', ''))).lower().endswith(ext)
                                        for ext in DANGEROUS_EXTENSIONS['executable']), axis=1)]

    # Sort by risk
    risk_order = {"🔴": 0, "🟠": 1, "✅": 2}
    df['_sort'] = df['Risk'].apply(lambda x: min([risk_order.get(k, 3) for k in risk_order if k in x], default=3))
    df = df.sort_values('_sort').drop('_sort', axis=1)

    st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(df)} Jump List entries</div>', unsafe_allow_html=True)

    # Create display-friendly column names
    col_mapping = {
        'TargetPath': 'Target Path',
        'Application': 'Application',
        'AppId': 'App ID',
        'User': 'User',
        'Source': 'Source',
        'AccessTime': 'Last Access',
        'LnkFile': 'LNK File',
    }

    # Rename columns for display
    display_df = df.copy()
    for old_col, new_col in col_mapping.items():
        if old_col in display_df.columns:
            display_df[new_col] = display_df[old_col]

    # Data table - use display names
    column_order = ["Risk", "Target Path", "Application", "User", "Last Access", "Source", "App ID"]

    st.dataframe(
        sanitize_dataframe(display_df),
        column_order=[c for c in column_order if c in display_df.columns],
        width="stretch",
        height=400,
        column_config={
            "Risk": st.column_config.TextColumn("Risk", width="small"),
            "Target Path": st.column_config.TextColumn("Target Path", width="large"),
            "Application": st.column_config.TextColumn("Application", width="medium"),
            "User": st.column_config.TextColumn("User", width="small"),
            "Last Access": st.column_config.DatetimeColumn("Last Access", format="D/M/Y H:mm"),
            "Source": st.column_config.TextColumn("Source", width="small"),
            "App ID": st.column_config.TextColumn("App ID", width="medium"),
        },
        hide_index=True
    )

    # Export
    if len(df) > 0:
        st.download_button("📥 Export Jump Lists", df.to_csv(index=False), "jump_lists.csv", "text/csv", key="jl_export")

    # Analyst explanation
    with st.expander("📖 What are Jump Lists?"):
        st.markdown("""
**Jump Lists** are Windows taskbar feature that tracks recently/frequently accessed files per application.

| Field | Description |
|-------|-------------|
| **Target Path** | Path to the file that was accessed |
| **Application** | Program that accessed the file (from App ID) |
| **App ID** | Unique identifier for the application |
| **Last Access** | When the file was last accessed via this app |
| **User** | User who accessed the file |

**Forensic Value:**
- **File Access History**: Shows what files users opened with specific applications
- **Deleted File Evidence**: References persist even after files are deleted
- **Application Usage**: Reveals which applications were used
- **Network Shares**: Can show access to network paths
- **USB/Removable Media**: Evidence of external storage access

**Key Points for Analysts:**
- Each application has its own Jump List (identified by App ID)
- Two types: AutomaticDestinations (recent) and CustomDestinations (pinned)
- Contains embedded LNK data with timestamps and paths
- Limited entries per application (typically ~20-30 recent items)

**Common App IDs:**
| App ID | Application |
|--------|-------------|
| `1b4dd67f29cb1962` | Windows Explorer |
| `9b9cdc69c1c24e2b` | Notepad |
| `5d696d521de238c3` | Chrome |
| `fb3b0dbfee58fac8` | Microsoft Word |

**Suspicious Indicators:**
- Access to sensitive directories (System32, etc.)
- Recently accessed executables in temp folders
- Access to files on removable media around incident time

**MITRE ATT&CK:** T1083 (File and Directory Discovery)

**Location:** `%APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\`
        """)


def render_shellbags_tab(shellbags_data):
    """Render the Shellbags subtab."""


    if not shellbags_data:
        st.info("No Shellbags data collected. Shellbags record folder access history, even for deleted folders.")
        return

    df = pd.DataFrame(shellbags_data)

    # Search and filter
    col_search, col_filter = st.columns([3, 2])

    with col_search:
        search_sb = st.text_input("🔍 Search", placeholder="Search folder path...", key="sb_search")

    with col_filter:
        # Include Source filter for collector data
        filter_options = ["All Entries", "Suspicious Paths", "Network/Removable", "Mount Points", "Run Commands", "Typed Paths"]
        risk_filter = st.selectbox("Filter", filter_options, key="sb_filter")

    # Risk analysis - handle collector fields: User, FolderType, Path, Source
    def analyze_shellbag_risk(row):
        # Handle both old and new field names
        path = str(row.get('Path', row.get('path', row.get('folder_path', '')))).lower()
        folder_type = str(row.get('FolderType', row.get('Source', ''))).lower()

        # Network shares / Mount points
        if path.startswith('\\\\') or 'network' in path or '##' in path:
            return "🟠 Network Share"

        # Mount points to removable drives
        if 'mount' in folder_type:
            if any(f'{d}:' in path.lower() for d in 'defghij'):
                return "🟠 Removable Media"
            return "🟡 Mount Point"

        # Run commands - potentially suspicious
        if 'run' in folder_type:
            if any(kw in path for kw in ['cmd', 'powershell', 'wscript', 'cscript', 'mshta']):
                return "🔴 Suspicious Command"
            return "🟡 Run Command"

        # Typed paths - user-entered locations
        if 'typed' in folder_type:
            if any(loc in path for loc in SUSPICIOUS_LOCATIONS):
                return "🟠 Suspicious Typed Path"
            return "🟡 Typed Path"

        # Suspicious locations
        if any(loc in path for loc in SUSPICIOUS_LOCATIONS):
            return "🟡 Suspicious Path"

        # Hidden or system folders
        if '$recycle' in path or 'system volume' in path:
            return "🟡 System/Hidden"

        return "✅ Normal"

    df['Risk'] = df.apply(analyze_shellbag_risk, axis=1)

    # Parse timestamps
    for col in ['AccessTime', 'access_time', 'modified_time', 'creation_time', 'last_accessed', 'last_modified']:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors='coerce')

    # Apply search
    if search_sb:
        search_lower = search_sb.lower()
        mask = df.astype(str).apply(lambda x: x.str.lower().str.contains(search_lower, na=False)).any(axis=1)
        df = df[mask]

    # Apply risk filter
    if risk_filter == "Suspicious Paths":
        df = df[df['Risk'].str.contains("🟡|🟠|🔴", regex=True)]
    elif risk_filter == "Network/Removable":
        df = df[df['Risk'].str.contains("Network|Removable", regex=True)]
    elif risk_filter == "Mount Points":
        df = df[df.apply(lambda r: 'mount' in str(r.get('FolderType', r.get('Source', ''))).lower(), axis=1)]
    elif risk_filter == "Run Commands":
        df = df[df.apply(lambda r: 'run' in str(r.get('FolderType', r.get('Source', ''))).lower(), axis=1)]
    elif risk_filter == "Typed Paths":
        df = df[df.apply(lambda r: 'typed' in str(r.get('FolderType', r.get('Source', ''))).lower(), axis=1)]

    # Sort by risk
    risk_order = {"🔴": 0, "🟠": 1, "🟡": 2, "✅": 3}
    df['_sort'] = df['Risk'].apply(lambda x: min([risk_order.get(k, 4) for k in risk_order if k in x], default=4))
    df = df.sort_values('_sort').drop('_sort', axis=1)

    st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(df)} Shellbag entries</div>', unsafe_allow_html=True)

    # Create display-friendly column names
    col_mapping = {
        'Path': 'Folder Path',
        'FolderType': 'Type',
        'User': 'User',
        'Source': 'Source',
        'AccessTime': 'Access Time',
    }

    # Rename columns for display
    display_df = df.copy()
    for old_col, new_col in col_mapping.items():
        if old_col in display_df.columns:
            display_df[new_col] = display_df[old_col]

    # Data table - prefer new field names
    column_order = ["Risk", "Folder Path", "Type", "User", "Source", "Access Time"]

    st.dataframe(
        sanitize_dataframe(display_df),
        column_order=[c for c in column_order if c in display_df.columns],
        width="stretch",
        height=400,
        column_config={
            "Risk": st.column_config.TextColumn("Risk", width="small"),
            "Folder Path": st.column_config.TextColumn("Folder Path", width="large"),
            "Type": st.column_config.TextColumn("Type", width="medium"),
            "User": st.column_config.TextColumn("User", width="small"),
            "Source": st.column_config.TextColumn("Source", width="small"),
            "Access Time": st.column_config.DatetimeColumn("Access Time", format="D/M/Y H:mm"),
        },
        hide_index=True
    )

    # Export
    if len(df) > 0:
        st.download_button("📥 Export Shellbags", df.to_csv(index=False), "shellbags.csv", "text/csv", key="sb_export")

    # Analyst explanation
    with st.expander("📖 What are Shellbags?"):
        st.markdown("""
**Shellbags** are Windows registry artifacts that store folder viewing preferences and prove folder access.

| Field | Description |
|-------|-------------|
| **Folder Path** | Path to the folder that was accessed |
| **Type** | Type of shellbag entry (folder, zip, network, etc.) |
| **User** | User who accessed the folder |
| **Access Time** | When the folder was last accessed |
| **Source** | Registry key location (NTUSER.DAT or UsrClass.dat) |

**Forensic Value:**
- **Folder Access Proof**: Shows folders the user navigated to in Explorer
- **Deleted Folder Evidence**: Entries persist even after folders are deleted
- **Network Share Access**: Reveals access to network paths (\\\\server\\share)
- **Removable Media**: Evidence of browsing USB drives, external storage
- **Timestamp Analysis**: Helps build user activity timeline

**Key Points for Analysts:**
- Stored in two locations per user: NTUSER.DAT and UsrClass.dat
- Only records Explorer navigation (not programmatic file access)
- Includes window size, position, sort order preferences
- Can reveal folder names even when folders no longer exist

**Entry Types:**
| Type | Meaning |
|------|---------|
| **Directory** | Regular folder browsing |
| **Zip** | ZIP file contents viewed |
| **Network** | Network share access |
| **Drive** | Drive root access |
| **ControlPanel** | Control Panel access |

**Suspicious Indicators:**
- Access to temp/appdata folders (malware staging)
- Network share access to unusual servers
- Browsing of sensitive system directories
- Access to removable media around incident time
- Evidence of deleted folders that contained malware

**MITRE ATT&CK:** T1083 (File and Directory Discovery)

**Registry Locations:**
- `NTUSER.DAT\\Software\\Microsoft\\Windows\\Shell\\BagMRU`
- `UsrClass.dat\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU`
        """)

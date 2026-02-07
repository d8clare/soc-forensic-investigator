"""
USB Forensics Tab - Professional Forensic Investigation View.
Displays USB registry artifacts, connection events, and SetupAPI history.
"""
import re
import streamlit as st
import pandas as pd
from datetime import datetime

from core.data_loader import load_json, load_text_file, sanitize_dataframe
from core.risk_engine import RiskEngine


# Device type indicators
DEVICE_TYPES = {
    'storage': {'keywords': ['disk', 'storage', 'mass', 'usbstor', 'thumb', 'flash', 'sandisk', 'kingston', 'seagate', 'wd', 'toshiba'], 'icon': '💾', 'risk': 'high'},
    'phone': {'keywords': ['phone', 'android', 'iphone', 'samsung', 'huawei', 'xiaomi', 'mtp', 'ptp'], 'icon': '📱', 'risk': 'medium'},
    'hid': {'keywords': ['hid', 'keyboard', 'mouse', 'input'], 'icon': '⌨️', 'risk': 'low'},
    'hub': {'keywords': ['hub', 'root'], 'icon': '🔌', 'risk': 'low'},
    'audio': {'keywords': ['audio', 'speaker', 'headset', 'microphone'], 'icon': '🎧', 'risk': 'low'},
    'camera': {'keywords': ['camera', 'webcam', 'video'], 'icon': '📷', 'risk': 'low'},
    'printer': {'keywords': ['printer', 'print'], 'icon': '🖨️', 'risk': 'low'},
    'network': {'keywords': ['ethernet', 'wifi', 'wireless', 'network', 'lan'], 'icon': '🌐', 'risk': 'low'},
}

# Known suspicious indicators
SUSPICIOUS_INDICATORS = [
    'rubber ducky', 'badusb', 'teensy', 'digispark', 'attiny', 'hak5',
    'lan turtle', 'bash bunny', 'usb armory', 'facedancer'
]


def render(evidence_folder: str, risk_engine: RiskEngine):
    """Render the USB Forensics tab."""

    # Load all data first for stats
    usb_reg = load_json(evidence_folder, "usb_history_reg.json")
    usb_evt = load_json(evidence_folder, "usb_events.json")
    usb_deep = load_json(evidence_folder, "usb_setupapi_parsed.json")

    # Analyze USB stats
    usb_stats = analyze_usb_stats(usb_reg, usb_evt, usb_deep)

    total_devices = usb_stats.get('total_devices', 0)
    storage_devices = usb_stats.get('storage', 0)
    recent_connections = usb_stats.get('recent', 0)
    total_events = len(usb_evt) if usb_evt else 0

    # Simple header with blue styling
    st.markdown(f'<div style="color:#e6edf3;font-size:1.1rem;margin-bottom:15px;"><b>USB</b> | Devices: {total_devices} | Storage: {storage_devices} | Events: {total_events}</div>', unsafe_allow_html=True)

    # Create subtabs
    u_tab1, u_tab2, u_tab3 = st.tabs([
        f"Registry ({len(usb_reg) if usb_reg else 0})",
        f"Events ({total_events})",
        "SetupAPI"
    ])

    # Tab 1: Registry Artifacts (USBSTOR)
    with u_tab1:
        render_registry_tab(usb_reg)

    # Tab 2: Connection Events
    with u_tab2:
        render_events_tab(usb_evt)

    # Tab 3: SetupAPI Deep History
    with u_tab3:
        render_setupapi_tab(usb_deep, evidence_folder)

    # Export section
    st.markdown("---")
    col1, col2, col3 = st.columns(3)

    with col1:
        if usb_reg:
            df_export = pd.DataFrame(usb_reg)
            st.download_button("📋 Export Registry", df_export.to_csv(index=False), "usb_registry.csv", "text/csv", key="usb_reg_export")
        else:
            st.button("📋 No Registry Data", disabled=True, key="usb_reg_export_disabled")

    with col2:
        if usb_evt:
            df_export = pd.DataFrame(usb_evt)
            st.download_button("⏱️ Export Events", df_export.to_csv(index=False), "usb_events.csv", "text/csv", key="usb_evt_export")
        else:
            st.button("⏱️ No Events Data", disabled=True, key="usb_evt_export_disabled")

    with col3:
        if usb_deep:
            df_export = pd.DataFrame(usb_deep)
            st.download_button("📜 Export SetupAPI", df_export.to_csv(index=False), "usb_setupapi.csv", "text/csv", key="usb_setup_export")
        else:
            st.button("📜 No SetupAPI Data", disabled=True, key="usb_setup_export_disabled")


def analyze_usb_stats(usb_reg, usb_evt, usb_deep):
    """Analyze USB data for statistics."""
    stats = {'total_devices': 0, 'storage': 0, 'recent': 0}

    # Count from registry
    if usb_reg:
        stats['total_devices'] = len(usb_reg)
        for device in usb_reg:
            device_str = str(device).lower()
            if any(kw in device_str for kw in DEVICE_TYPES['storage']['keywords']):
                stats['storage'] += 1

    # If no registry, try events
    elif usb_evt:
        unique_devices = set()
        for evt in usb_evt:
            device_id = evt.get('Device', evt.get('DeviceId', evt.get('device', '')))
            if device_id:
                unique_devices.add(str(device_id))
        stats['total_devices'] = len(unique_devices)

    return stats


def classify_device(device_info):
    """Classify a USB device based on its information."""
    device_str = str(device_info).lower()

    # Check for suspicious devices first
    if any(sus in device_str for sus in SUSPICIOUS_INDICATORS):
        return "🔴 Suspicious", "Suspicious Device"

    # Check device types
    for type_name, type_info in DEVICE_TYPES.items():
        if any(kw in device_str for kw in type_info['keywords']):
            icon = type_info['icon']
            risk = type_info['risk']
            if risk == 'high':
                return f"🟠 {icon}", type_name.title()
            elif risk == 'medium':
                return f"🟡 {icon}", type_name.title()
            else:
                return f"✅ {icon}", type_name.title()

    return "⚪ ❓", "Unknown"


def render_registry_tab(usb_reg):
    """Render the Registry Artifacts subtab."""


    if not usb_reg:
        st.info("No USB Registry artifacts found.")
        return

    df = pd.DataFrame(usb_reg)

    # Search filter
    search_reg = st.text_input("search_reg", placeholder="🔍 Search device name, vendor, serial...", key="usb_reg_search", label_visibility="collapsed")

    # Classify devices
    def classify_row(row):
        # Combine all fields for classification
        all_info = ' '.join([str(v) for v in row.values])
        status, device_type = classify_device(all_info)
        return pd.Series([status, device_type])

    df[['Status', 'Type']] = df.apply(classify_row, axis=1)

    # Apply search
    if search_reg:
        search_lower = search_reg.lower()
        mask = df.astype(str).apply(lambda x: x.str.lower().str.contains(search_lower, na=False)).any(axis=1)
        df = df[mask]

    # Sort - storage devices first
    type_order = {"Storage": 0, "Phone": 1, "Unknown": 2}
    df['_sort'] = df['Type'].map(type_order).fillna(3)
    df = df.sort_values('_sort').drop('_sort', axis=1)

    st.caption(f"Showing {len(df)} USB devices from registry")

    # Determine columns to show
    priority_cols = ['Status', 'Type', 'FriendlyName', 'DeviceName', 'Device', 'Name', 'Vendor', 'Manufacturer', 'Serial', 'SerialNumber', 'FirstInstall', 'LastConnected']
    available_cols = [c for c in priority_cols if c in df.columns]
    other_cols = [c for c in df.columns if c not in available_cols and c not in ['Status', 'Type']]
    column_order = ['Status', 'Type'] + [c for c in available_cols if c not in ['Status', 'Type']] + other_cols[:3]

    st.dataframe(
        sanitize_dataframe(df),
        column_order=[c for c in column_order if c in df.columns],
        width="stretch",
        height=400,
        column_config={
            "Status": st.column_config.TextColumn("Status", width="small"),
            "Type": st.column_config.TextColumn("Type", width="small"),
            "FriendlyName": st.column_config.TextColumn("Device Name", width="medium"),
            "DeviceName": st.column_config.TextColumn("Device Name", width="medium"),
            "Serial": st.column_config.TextColumn("Serial Number", width="medium"),
            "SerialNumber": st.column_config.TextColumn("Serial Number", width="medium"),
        },
        hide_index=True
    )


def render_events_tab(usb_evt):
    """Render the Connection Events subtab."""


    if not usb_evt:
        st.info("No USB connection events found.")
        return

    df = pd.DataFrame(usb_evt)

    # Search and filter row
    col_search, col_filter = st.columns([3, 2])

    with col_search:
        search_evt = st.text_input("search_evt", placeholder="🔍 Search events...", key="usb_evt_search", label_visibility="collapsed")

    with col_filter:
        event_types = ["All Events"]
        if 'Type' in df.columns:
            event_types += df['Type'].unique().tolist()
        elif 'EventType' in df.columns:
            event_types += df['EventType'].unique().tolist()
        type_filter = st.selectbox("type_filter", event_types, key="usb_evt_type_filter", label_visibility="collapsed")

    # Parse timestamps
    time_cols = ['Time', 'Timestamp', 'DateTime', 'EventTime']
    for col in time_cols:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors='coerce')
            break

    # Classify events
    def classify_event(row):
        all_info = ' '.join([str(v) for v in row.values])
        status, device_type = classify_device(all_info)
        return pd.Series([status, device_type])

    df[['Status', 'DeviceType']] = df.apply(classify_event, axis=1)

    # Apply search
    if search_evt:
        search_lower = search_evt.lower()
        mask = df.astype(str).apply(lambda x: x.str.lower().str.contains(search_lower, na=False)).any(axis=1)
        df = df[mask]

    # Apply type filter
    if type_filter != "All Events":
        if 'Type' in df.columns:
            df = df[df['Type'] == type_filter]
        elif 'EventType' in df.columns:
            df = df[df['EventType'] == type_filter]

    # Sort by time (most recent first)
    for col in time_cols:
        if col in df.columns:
            df = df.sort_values(col, ascending=False)
            break

    st.caption(f"Showing {len(df)} USB events")

    # Determine columns to show
    priority_cols = ['Status', 'DeviceType', 'Time', 'Timestamp', 'Type', 'EventType', 'Device', 'DeviceName', 'Action']
    column_order = [c for c in priority_cols if c in df.columns]

    st.dataframe(
        sanitize_dataframe(df),
        column_order=column_order if column_order else None,
        width="stretch",
        height=350,
        column_config={
            "Status": st.column_config.TextColumn("", width="small"),
            "DeviceType": st.column_config.TextColumn("Type", width="small"),
            "Time": st.column_config.DatetimeColumn("Time", format="D/M/Y H:mm:ss"),
            "Timestamp": st.column_config.DatetimeColumn("Time", format="D/M/Y H:mm:ss"),
            "Type": st.column_config.TextColumn("Event", width="small"),
            "EventType": st.column_config.TextColumn("Event", width="small"),
            "Device": st.column_config.TextColumn("Device", width="large"),
            "DeviceName": st.column_config.TextColumn("Device", width="large"),
        },
        hide_index=True
    )


def render_setupapi_tab(usb_deep, evidence_folder):
    """Render the SetupAPI Deep History subtab."""


    if usb_deep:
        df = pd.DataFrame(usb_deep)

        # Search
        search_setup = st.text_input("search_setup", placeholder="🔍 Search SetupAPI entries...", key="usb_setup_search", label_visibility="collapsed")

        # Classify devices
        def classify_setup(row):
            all_info = ' '.join([str(v) for v in row.values])
            status, device_type = classify_device(all_info)
            return pd.Series([status, device_type])

        df[['Status', 'Type']] = df.apply(classify_setup, axis=1)

        # Apply search
        if search_setup:
            search_lower = search_setup.lower()
            mask = df.astype(str).apply(lambda x: x.str.lower().str.contains(search_lower, na=False)).any(axis=1)
            df = df[mask]

        st.caption(f"Showing {len(df)} SetupAPI entries")

        # Data table
        column_order = ['Status', 'Type'] + [c for c in df.columns if c not in ['Status', 'Type']][:5]

        st.dataframe(
            sanitize_dataframe(df),
            column_order=[c for c in column_order if c in df.columns],
            width="stretch",
            height=400,
            column_config={
                "Status": st.column_config.TextColumn("", width="small"),
                "Type": st.column_config.TextColumn("Type", width="small"),
            },
            hide_index=True
        )

    else:
        # Try to load and parse raw log
        raw_log = load_text_file(evidence_folder, "setupapi.dev.log")

        if raw_log:
            st.info("Displaying raw log content.")

            # Try to extract USB-related entries
            lines = raw_log.split('\n')
            usb_lines = [l for l in lines if 'usb' in l.lower() or 'disk' in l.lower() or 'storage' in l.lower()]

            if usb_lines:
                st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Found {len(usb_lines)} USB-related entries</div>', unsafe_allow_html=True)

                # Show USB entries
                usb_content = '\n'.join(usb_lines[:100])
                st.code(usb_content, language="text")

                if len(usb_lines) > 100:
                    st.caption(f"Showing 100 of {len(usb_lines)} USB-related entries")

            # Full log in expander
            with st.expander("📄 View Full SetupAPI Log"):
                # Limit display for performance
                if len(raw_log) > 50000:
                    st.text_area("Raw Log", raw_log[:50000] + "\n\n... (truncated)", height=400, key="setup_raw", label_visibility="collapsed")
                    st.caption("Log truncated for display. Download full log for complete analysis.")
                else:
                    st.text_area("Raw Log", raw_log, height=400, key="setup_raw", label_visibility="collapsed")

            # Download button for raw log
            st.download_button("📜 Download Raw Log", raw_log, "setupapi.dev.log", "text/plain", key="setup_raw_download")

        else:
            st.info("No SetupAPI data found. setupapi.dev.log was not collected or does not exist.")

"""
Reusable forensic data table component with risk highlighting.
"""
from typing import List, Dict, Any, Optional, Callable

import streamlit as st
import pandas as pd

from config.theme import THEME, get_risk_color


def create_virustotal_link(sha256: str) -> Optional[str]:
    """
    Create a VirusTotal lookup link for a SHA256 hash.

    Args:
        sha256: SHA256 hash string

    Returns:
        VirusTotal URL or None if invalid hash
    """
    if sha256 and len(str(sha256)) == 64:
        return f"https://www.virustotal.com/gui/file/{sha256}"
    return None


def create_abuseipdb_link(ip: str) -> Optional[str]:
    """
    Create an AbuseIPDB lookup link for an IP address.

    Args:
        ip: IP address string

    Returns:
        AbuseIPDB URL or None if invalid/local IP
    """
    if ip and ip not in ['0.0.0.0', '127.0.0.1', '::', 'localhost', '']:
        return f"https://www.abuseipdb.com/check/{ip}"
    return None


class ForensicTable:
    """
    Reusable table component with built-in risk highlighting and search.
    """

    def __init__(self, df: pd.DataFrame, risk_column: str = None):
        """
        Initialize the forensic table.

        Args:
            df: Source DataFrame
            risk_column: Column name containing risk scores/status for highlighting
        """
        self.df = df.copy()
        self.risk_column = risk_column
        self.search_columns: List[str] = []
        self.column_config: Dict[str, Any] = {}
        self.column_order: List[str] = []
        self.hidden_columns: List[str] = []

    def add_virustotal_column(self, hash_column: str = 'sha256', new_column: str = 'VirusTotal'):
        """Add a VirusTotal link column based on hash values."""
        if hash_column in self.df.columns:
            self.df[new_column] = self.df[hash_column].apply(create_virustotal_link)
            self.column_config[new_column] = st.column_config.LinkColumn(
                "VirusTotal",
                display_text="View Report"
            )
        return self

    def add_abuseipdb_column(self, ip_column: str = 'Remote IP', new_column: str = 'Reputation Check'):
        """Add an AbuseIPDB link column based on IP values."""
        if ip_column in self.df.columns:
            self.df[new_column] = self.df[ip_column].apply(create_abuseipdb_link)
            self.column_config[new_column] = st.column_config.LinkColumn(
                "AbuseIPDB",
                display_text="Check IP"
            )
        return self

    def set_column_order(self, columns: List[str]):
        """Set the display order of columns."""
        self.column_order = [c for c in columns if c in self.df.columns]
        return self

    def hide_columns(self, columns: List[str]):
        """Hide specified columns from display."""
        self.hidden_columns = columns
        return self

    def configure_column(self, column: str, config: Any):
        """Add custom Streamlit column configuration."""
        self.column_config[column] = config
        return self

    def enable_search(self, columns: List[str] = None, label: str = "Search:"):
        """
        Enable search functionality.

        Args:
            columns: Columns to search in (defaults to all)
            label: Label for search input
        """
        self.search_columns = columns or list(self.df.columns)

        search_term = st.text_input(label, "")
        if search_term:
            mask = self.df[self.search_columns].astype(str).apply(
                lambda x: x.str.contains(search_term, case=False, na=False)
            ).any(axis=1)
            self.df = self.df[mask]

        return self

    def _get_row_styler(self) -> Optional[Callable]:
        """Get the row styling function based on risk column."""
        if not self.risk_column or self.risk_column not in self.df.columns:
            return None

        def style_row(row):
            risk_val = row.get(self.risk_column, '')

            # Handle numeric risk scores
            if isinstance(risk_val, (int, float)):
                if risk_val >= 50:
                    return [f'background-color: {THEME.ROW_HIGH_RISK}'] * len(row)
                elif risk_val > 0:
                    return [f'background-color: {THEME.ROW_MEDIUM_RISK}'] * len(row)
                return [''] * len(row)

            # Handle string risk status
            risk_str = str(risk_val).lower()
            if any(kw in risk_str for kw in ['critical', 'high', 'danger']):
                return [f'background-color: {THEME.ROW_HIGH_RISK}'] * len(row)
            elif any(kw in risk_str for kw in ['suspicious', 'medium', 'warning']):
                return [f'background-color: {THEME.ROW_MEDIUM_RISK}'] * len(row)
            elif 'low' in risk_str:
                return [f'background-color: {THEME.ROW_LOW_RISK}'] * len(row)

            return [''] * len(row)

        return style_row

    def render(self, height: int = None, hide_index: bool = True) -> None:
        """
        Render the table with all configured options.

        Args:
            height: Optional fixed height for the table
            hide_index: Whether to hide the DataFrame index
        """
        from core.data_loader import sanitize_dataframe

        display_df = sanitize_dataframe(self.df)

        # Apply column order if set
        if self.column_order:
            cols = [c for c in self.column_order if c in display_df.columns]
            remaining = [c for c in display_df.columns if c not in cols and c not in self.hidden_columns]
            display_df = display_df[cols + remaining]

        # Remove hidden columns
        if self.hidden_columns:
            display_df = display_df.drop(columns=[c for c in self.hidden_columns if c in display_df.columns])

        # Get row styler
        styler = self._get_row_styler()

        # Build display arguments
        display_args = {
            "column_config": self.column_config,
            "hide_index": hide_index,
            "width": "stretch",
        }

        if height:
            display_args["height"] = height

        if self.column_order:
            display_args["column_order"] = [c for c in self.column_order if c in display_df.columns]

        # Render with or without styling
        if styler:
            st.dataframe(display_df.style.apply(styler, axis=1), **display_args)
        else:
            st.dataframe(display_df, **display_args)


def render_simple_table(
    data: List[Dict],
    columns: List[str] = None,
    height: int = None,
    column_config: Dict = None
) -> None:
    """
    Quick helper to render a simple table without the full class.

    Args:
        data: List of dictionaries
        columns: Optional column order
        height: Optional fixed height
        column_config: Optional column configuration
    """
    from core.data_loader import sanitize_dataframe

    if not data:
        st.info("No data available.")
        return

    df = sanitize_dataframe(pd.DataFrame(data))

    args = {"width": "stretch", "hide_index": True}

    if columns:
        args["column_order"] = [c for c in columns if c in df.columns]

    if height:
        args["height"] = height

    if column_config:
        args["column_config"] = column_config

    st.dataframe(df, **args)

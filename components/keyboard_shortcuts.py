"""
Keyboard Shortcuts Component - JavaScript-based keyboard navigation.
Provides Ctrl+F for search, tab navigation, and other shortcuts.
"""
import streamlit as st


def inject_keyboard_shortcuts():
    """
    Inject JavaScript for keyboard shortcuts into the Streamlit app.

    Shortcuts:
    - Ctrl+F / Cmd+F: Focus search input
    - Ctrl+K / Cmd+K: Quick search modal
    - 1-9: Jump to tab (when no input focused)
    - Esc: Close expanders, clear search
    - ?: Show help modal
    """

    shortcut_js = """
    <script>
    // Wait for Streamlit to fully load
    document.addEventListener('DOMContentLoaded', function() {
        initKeyboardShortcuts();
    });

    // Also run immediately in case DOM is already loaded
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
        setTimeout(initKeyboardShortcuts, 500);
    }

    function initKeyboardShortcuts() {
        // Prevent duplicate initialization
        if (window.keyboardShortcutsInitialized) return;
        window.keyboardShortcutsInitialized = true;

        document.addEventListener('keydown', function(e) {
            // Get active element
            const activeElement = document.activeElement;
            const isInputFocused = activeElement.tagName === 'INPUT' ||
                                   activeElement.tagName === 'TEXTAREA' ||
                                   activeElement.isContentEditable;

            // Ctrl+F or Cmd+F - Focus search input
            if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
                const searchInput = document.querySelector('input[placeholder*="filename"]') ||
                                   document.querySelector('input[placeholder*="Enter"]') ||
                                   document.querySelector('input[data-testid="stTextInput"]');
                if (searchInput) {
                    e.preventDefault();
                    searchInput.focus();
                    searchInput.select();
                }
            }

            // Ctrl+K or Cmd+K - Quick search (same as Ctrl+F for now)
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                const searchInput = document.querySelector('input[placeholder*="filename"]') ||
                                   document.querySelector('input[data-testid="stTextInput"]');
                if (searchInput) {
                    e.preventDefault();
                    searchInput.focus();
                    searchInput.select();
                }
            }

            // Escape - Clear focus, close modals
            if (e.key === 'Escape') {
                if (isInputFocused) {
                    activeElement.blur();
                }
                // Close any open expanders
                const openExpanders = document.querySelectorAll('[data-testid="stExpander"][aria-expanded="true"]');
                openExpanders.forEach(exp => {
                    const button = exp.querySelector('button');
                    if (button) button.click();
                });
            }

            // Number keys 1-9 for tab navigation (only when not typing)
            if (!isInputFocused && e.key >= '1' && e.key <= '9') {
                const tabIndex = parseInt(e.key) - 1;
                const tabs = document.querySelectorAll('[data-testid="stTabs"] button[role="tab"]');
                if (tabs[tabIndex]) {
                    e.preventDefault();
                    tabs[tabIndex].click();
                }
            }

            // Arrow keys for tab navigation when focused on tabs
            if (activeElement.getAttribute('role') === 'tab') {
                const tabs = document.querySelectorAll('[data-testid="stTabs"] button[role="tab"]');
                const currentIndex = Array.from(tabs).indexOf(activeElement);

                if (e.key === 'ArrowRight' && currentIndex < tabs.length - 1) {
                    e.preventDefault();
                    tabs[currentIndex + 1].focus();
                    tabs[currentIndex + 1].click();
                }
                if (e.key === 'ArrowLeft' && currentIndex > 0) {
                    e.preventDefault();
                    tabs[currentIndex - 1].focus();
                    tabs[currentIndex - 1].click();
                }
            }

            // ? - Show help (only when not typing)
            if (!isInputFocused && e.key === '?') {
                e.preventDefault();
                showShortcutsHelp();
            }

            // g then s - Go to Search tab
            if (!isInputFocused && e.key === 'g') {
                window.gKeyPressed = true;
                setTimeout(() => { window.gKeyPressed = false; }, 1000);
            }
            if (!isInputFocused && window.gKeyPressed && e.key === 's') {
                e.preventDefault();
                const searchTab = Array.from(document.querySelectorAll('[data-testid="stTabs"] button[role="tab"]'))
                    .find(tab => tab.textContent.includes('Search'));
                if (searchTab) searchTab.click();
                window.gKeyPressed = false;
            }

            // g then h - Go to Home tab
            if (!isInputFocused && window.gKeyPressed && e.key === 'h') {
                e.preventDefault();
                const homeTab = document.querySelector('[data-testid="stTabs"] button[role="tab"]');
                if (homeTab) homeTab.click();
                window.gKeyPressed = false;
            }

            // g then f - Go to Findings tab
            if (!isInputFocused && window.gKeyPressed && e.key === 'f') {
                e.preventDefault();
                const findingsTab = Array.from(document.querySelectorAll('[data-testid="stTabs"] button[role="tab"]'))
                    .find(tab => tab.textContent.includes('Findings'));
                if (findingsTab) findingsTab.click();
                window.gKeyPressed = false;
            }
        });

        console.log('SOC Investigator keyboard shortcuts initialized');
    }

    function showShortcutsHelp() {
        // Create and show a help modal
        const existingModal = document.getElementById('shortcuts-help-modal');
        if (existingModal) {
            existingModal.style.display = existingModal.style.display === 'none' ? 'flex' : 'none';
            return;
        }

        const modal = document.createElement('div');
        modal.id = 'shortcuts-help-modal';
        modal.innerHTML = `
            <div style="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:10000;">
                <div style="background:#1a1a2e;border-radius:12px;padding:30px;max-width:500px;width:90%;max-height:80vh;overflow-y:auto;border:1px solid rgba(102,126,234,0.3);">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
                        <h2 style="color:white;margin:0;font-size:1.3rem;">⌨️ Keyboard Shortcuts</h2>
                        <button onclick="this.closest('#shortcuts-help-modal').style.display='none'" style="background:none;border:none;color:#888;font-size:1.5rem;cursor:pointer;">&times;</button>
                    </div>
                    <div style="color:#ccc;">
                        <div style="margin-bottom:15px;">
                            <div style="font-weight:600;color:#667eea;margin-bottom:8px;">Navigation</div>
                            <div style="display:grid;grid-template-columns:100px 1fr;gap:5px;font-size:0.9rem;">
                                <kbd style="background:#333;padding:2px 8px;border-radius:4px;">1-9</kbd><span>Jump to tab</span>
                                <kbd style="background:#333;padding:2px 8px;border-radius:4px;">g s</kbd><span>Go to Search</span>
                                <kbd style="background:#333;padding:2px 8px;border-radius:4px;">g h</kbd><span>Go to Home</span>
                                <kbd style="background:#333;padding:2px 8px;border-radius:4px;">g f</kbd><span>Go to Findings</span>
                                <kbd style="background:#333;padding:2px 8px;border-radius:4px;">\u2190 \u2192</kbd><span>Navigate tabs</span>
                            </div>
                        </div>
                        <div style="margin-bottom:15px;">
                            <div style="font-weight:600;color:#667eea;margin-bottom:8px;">Search</div>
                            <div style="display:grid;grid-template-columns:100px 1fr;gap:5px;font-size:0.9rem;">
                                <kbd style="background:#333;padding:2px 8px;border-radius:4px;">Ctrl+F</kbd><span>Focus search</span>
                                <kbd style="background:#333;padding:2px 8px;border-radius:4px;">Ctrl+K</kbd><span>Quick search</span>
                                <kbd style="background:#333;padding:2px 8px;border-radius:4px;">Esc</kbd><span>Clear focus</span>
                            </div>
                        </div>
                        <div>
                            <div style="font-weight:600;color:#667eea;margin-bottom:8px;">Help</div>
                            <div style="display:grid;grid-template-columns:100px 1fr;gap:5px;font-size:0.9rem;">
                                <kbd style="background:#333;padding:2px 8px;border-radius:4px;">?</kbd><span>Show this help</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    }
    </script>
    """

    st.markdown(shortcut_js, unsafe_allow_html=True)


def render_shortcuts_help():
    """Render a help section showing available keyboard shortcuts."""

    st.markdown('''<div style="background:#1a1a2e;border-radius:10px;padding:20px;margin:10px 0;">
<div style="font-size:1.2rem;font-weight:bold;color:white;margin-bottom:15px;">⌨️ Keyboard Shortcuts</div>

<div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));gap:20px;">

<div>
<div style="color:#667eea;font-weight:600;margin-bottom:8px;">Navigation</div>
<div style="color:#888;font-size:0.85rem;line-height:1.8;">
<code style="background:#333;padding:2px 6px;border-radius:3px;">1-9</code> Jump to tab<br>
<code style="background:#333;padding:2px 6px;border-radius:3px;">g s</code> Go to Search<br>
<code style="background:#333;padding:2px 6px;border-radius:3px;">g h</code> Go to Home<br>
<code style="background:#333;padding:2px 6px;border-radius:3px;">\u2190 \u2192</code> Navigate tabs
</div>
</div>

<div>
<div style="color:#667eea;font-weight:600;margin-bottom:8px;">Search</div>
<div style="color:#888;font-size:0.85rem;line-height:1.8;">
<code style="background:#333;padding:2px 6px;border-radius:3px;">Ctrl+F</code> Focus search<br>
<code style="background:#333;padding:2px 6px;border-radius:3px;">Ctrl+K</code> Quick search<br>
<code style="background:#333;padding:2px 6px;border-radius:3px;">Esc</code> Clear focus
</div>
</div>

<div>
<div style="color:#667eea;font-weight:600;margin-bottom:8px;">Help</div>
<div style="color:#888;font-size:0.85rem;line-height:1.8;">
<code style="background:#333;padding:2px 6px;border-radius:3px;">?</code> Show shortcuts help
</div>
</div>

</div>
</div>''', unsafe_allow_html=True)

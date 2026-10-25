"""
Menoa's colors, the greens from the logo, and the stylesheet they fill (style.qss, where each $color_name is a color from the palette)
Pages take their colors from COLORS instead of writing their own, so dark and light mode both work
"""

import importlib.resources as pkg_resources
from string import Template
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

PALETTES = {
    "dark": {
        "background": "#252a2e", "sidebar": "#1f2326", "surface": "#2d3337", "border": "#40454a", "border_hover": "#50555a",
        "text": "#e0e0e0", "muted": "#a0a0a0",
        "accent": "#00b57b", "accent_light": "#00cf90", "accent_text": "#00cf90", "accent_hover": "#009a68", "accent_pressed": "#007f55",
        "on_accent": "#0b1f17", "accent_disabled": "#1a5c42", "text_disabled": "#6c7a6c",
        "good": "#00cf90", "warning": "#FF9800", "bad": "#F44336",
    },
    "light": {
        "background": "#f4f6f5", "sidebar": "#e9eeeb", "surface": "#ffffff", "border": "#d5dcd8", "border_hover": "#b9c3be",
        "text": "#1f2427", "muted": "#5f6b66",
        # Darker greens for text, the logo's green is too light to read on white
        "accent": "#00b57b", "accent_light": "#00cf90", "accent_text": "#00875c", "accent_hover": "#00c587", "accent_pressed": "#009a68",
        "on_accent": "#0b1f17", "accent_disabled": "#b5e3d1", "text_disabled": "#6f8a7f",
        "good": "#00875c", "warning": "#c76e00", "bad": "#d32f2f",
    },
}

COLORS = dict(PALETTES["dark"])  # Replaced by apply() before any page is made

def freshness_color(state: str) -> str:
    """
    Returns the color for one of clam_utils.database_freshness()'s states
    """
    return {"fresh": COLORS["good"], "outdated": COLORS["warning"]}.get(state, COLORS["bad"])

def apply(app: QApplication, scheme: Optional[str] = None) -> None:
    """
    Styles the app for scheme ("dark" or "light"), the desktop's color scheme without one
    """
    if scheme is None:
        scheme = "light" if app.styleHints().colorScheme() == Qt.ColorScheme.Light else "dark"
    COLORS.update(PALETTES[scheme])
    with pkg_resources.open_text("menoa", "style.qss") as f:
        app.setStyleSheet(Template(f.read()).substitute(COLORS))

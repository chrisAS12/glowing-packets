"""
Centralized UI Design System and Widget Library for SentinelWire.

Provides:
1. Unified Segoe UI typography hierarchy.
2. Unified Obsidian / Charcoal dark mode palette tokens.
3. Standardized, reusable component constructors:
   - `create_styled_button`: Uniform paddings, borders, hover feedback, and color styles.
   - `create_card_frame`: Elevated containers with crisp borders and optional headers.
   - `create_status_pill`: Color-coded status pills with standardized contrast.
   - `create_data_table`: Treeview tables with auto-stretching and dual-axis scrolling.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Dict, Optional, Sequence, Tuple


# ==============================================================================
# 1. Typography Scale (Pure Segoe UI + Consolas for Monospace)
# ==============================================================================

FONT_FAMILY = "Segoe UI"
FONT_MONO_FAMILY = "Consolas"

FONT_HEADER: Tuple[str, int, str] = (FONT_FAMILY, 12, "bold")
FONT_SECTION: Tuple[str, int, str] = (FONT_FAMILY, 10, "bold")
FONT_BODY: Tuple[str, int] = (FONT_FAMILY, 9)
FONT_BOLD: Tuple[str, int, str] = (FONT_FAMILY, 9, "bold")
FONT_MONO: Tuple[str, int] = (FONT_MONO_FAMILY, 9)
FONT_SMALL: Tuple[str, int] = (FONT_FAMILY, 8)
FONT_SMALL_BOLD: Tuple[str, int, str] = (FONT_FAMILY, 8, "bold")


# ==============================================================================
# 2. Obsidian / Charcoal Dark Mode Palette
# ==============================================================================

BG_CANVAS = "#09090b"          # Pure dark charcoal background
BG_SURFACE = "#121215"         # Sidebar & container surface
BG_CARD = "#18181b"            # Cards, editors, panels
BG_ELEVATED = "#27272a"        # Headers, secondary buttons, toolbars
BORDER_COLOR = "#27272a"       # Crisp card borders
BORDER_FOCUS = "#0284c7"       # Active focus cyan border
TEXT_MAIN = "#f4f4f5"          # Crisp high-readability silver/white
TEXT_MUTED = "#a1a1aa"         # Readable secondary metadata
TEXT_HINT = "#71717a"          # Subtle hint text

ACCENT_BLUE = "#0284c7"        # Electric Sentinel Blue (Primary)
ACCENT_GREEN = "#10b981"       # Verified safe emerald
ACCENT_RED = "#ef4444"          # Threat / kill switch coral red
ACCENT_YELLOW = "#f59e0b"       # Warning amber

# Compatibility tokens matching legacy usages
TEXT_TITLE = TEXT_MAIN
TEXT_BODY = TEXT_MAIN
ACCENT_EMERALD = ACCENT_GREEN
ALERT_RED = ACCENT_RED
ACCENT_HOVER = "#0369a1"


# ==============================================================================
# 3. Button Styles & Factory
# ==============================================================================

BUTTON_STYLES: Dict[str, Dict[str, str]] = {
    "primary": {
        "bg": ACCENT_BLUE,
        "fg": "#ffffff",
        "activebackground": "#0369a1",
        "activeforeground": "#ffffff",
        "hover_bg": "#0369a1",
    },
    "secondary": {
        "bg": BG_ELEVATED,
        "fg": TEXT_MAIN,
        "activebackground": "#3f3f46",
        "activeforeground": "#ffffff",
        "hover_bg": "#3f3f46",
    },
    "danger": {
        "bg": ACCENT_RED,
        "fg": "#ffffff",
        "activebackground": "#dc2626",
        "activeforeground": "#ffffff",
        "hover_bg": "#dc2626",
    },
    "accent": {
        "bg": "#7c3aed",
        "fg": "#ffffff",
        "activebackground": "#6d28d9",
        "activeforeground": "#ffffff",
        "hover_bg": "#6d28d9",
    },
    "warning": {
        "bg": ACCENT_YELLOW,
        "fg": "#000000",
        "activebackground": "#d97706",
        "activeforeground": "#000000",
        "hover_bg": "#d97706",
    },
    "ghost": {
        "bg": BG_CARD,
        "fg": TEXT_MUTED,
        "activebackground": BG_ELEVATED,
        "activeforeground": TEXT_MAIN,
        "hover_bg": BG_ELEVATED,
    },
}


def create_styled_button(
    parent: tk.Widget,
    text: str,
    command: Optional[Callable[[], Any]] = None,
    style: str = "primary",
    icon: Optional[str] = None,
    font: Optional[Tuple[Any, ...]] = None,
    padx: int = 12,
    pady: int = 4,
    cursor: str = "hand2",
    **kwargs: Any,
) -> tk.Button:
    """Creates a standardized dark-mode button with uniform hover feedback."""
    display_text = f"{icon}  {text}" if icon and not text.startswith(icon) else text
    style_key = style.lower() if style.lower() in BUTTON_STYLES else "secondary"
    style_cfg = BUTTON_STYLES[style_key]

    btn_font = font or FONT_BOLD

    btn = tk.Button(
        parent,
        text=display_text,
        command=command,
        font=btn_font,
        bg=style_cfg["bg"],
        fg=style_cfg["fg"],
        activebackground=style_cfg["activebackground"],
        activeforeground=style_cfg["activeforeground"],
        padx=padx,
        pady=pady,
        relief=tk.FLAT,
        bd=0,
        cursor=cursor,
        **kwargs,
    )

    normal_bg = style_cfg["bg"]
    hover_bg = style_cfg["hover_bg"]

    def _on_enter(event: tk.Event) -> None:
        try:
            if btn["state"] != tk.DISABLED:
                btn.configure(bg=hover_bg)
        except Exception:
            pass

    def _on_leave(event: tk.Event) -> None:
        try:
            if btn["state"] != tk.DISABLED:
                btn.configure(bg=normal_bg)
        except Exception:
            pass

    btn.bind("<Enter>", _on_enter)
    btn.bind("<Leave>", _on_leave)
    return btn


# ==============================================================================
# 4. Status Pill Component
# ==============================================================================

STATUS_PILL_STYLES: Dict[str, Dict[str, str]] = {
    "ok": {
        "fg": ACCENT_GREEN,
        "bg": "#064e3b",
    },
    "warning": {
        "fg": ACCENT_YELLOW,
        "bg": "#451a03",
    },
    "error": {
        "fg": ACCENT_RED,
        "bg": "#450a0a",
    },
    "info": {
        "fg": ACCENT_BLUE,
        "bg": "#082f49",
    },
    "neutral": {
        "fg": TEXT_MUTED,
        "bg": BG_ELEVATED,
    },
}


def create_status_pill(
    parent: tk.Widget,
    text: str,
    status: str = "ok",
    font: Optional[Tuple[Any, ...]] = None,
    padx: int = 10,
    pady: int = 3,
    **kwargs: Any,
) -> tk.Label:
    """Creates a color-coded status badge with high-contrast text and dark fill."""
    cfg = STATUS_PILL_STYLES.get(status.lower(), STATUS_PILL_STYLES["neutral"])
    pill = tk.Label(
        parent,
        text=text,
        font=font or FONT_BOLD,
        fg=cfg["fg"],
        bg=cfg["bg"],
        padx=padx,
        pady=pady,
        relief=tk.FLAT,
        **kwargs,
    )
    setattr(pill, "_status_name", status)
    return pill


def update_status_pill(pill: tk.Label, text: str, status: str = "ok") -> None:
    """Updates the text and color theme of an existing status pill."""
    cfg = STATUS_PILL_STYLES.get(status.lower(), STATUS_PILL_STYLES["neutral"])
    try:
        pill.configure(text=text, fg=cfg["fg"], bg=cfg["bg"])
        setattr(pill, "_status_name", status)
    except Exception:
        pass


# ==============================================================================
# 5. Card Frame Component
# ==============================================================================

def create_card_frame(
    parent: tk.Widget,
    title: Optional[str] = None,
    subtitle: Optional[str] = None,
    padx: int = 14,
    pady: int = 12,
    bg: str = BG_CARD,
    border_color: str = BORDER_COLOR,
    **kwargs: Any,
) -> tk.Frame:
    """Creates an elevated container frame with subtle border and optional header."""
    card = tk.Frame(
        parent,
        bg=bg,
        padx=padx,
        pady=pady,
        highlightbackground=border_color,
        highlightthickness=1,
        **kwargs,
    )
    if title:
        header_frame = tk.Frame(card, bg=bg)
        header_frame.pack(fill=tk.X, pady=(0, 4 if subtitle else 6))
        title_lbl = tk.Label(
            header_frame,
            text=title,
            font=FONT_SECTION,
            fg=TEXT_MAIN,
            bg=bg,
        )
        title_lbl.pack(side=tk.LEFT)
        setattr(card, "header_frame", header_frame)
        setattr(card, "title_label", title_lbl)
    if subtitle:
        sub_lbl = tk.Label(
            card,
            text=subtitle,
            font=FONT_SMALL,
            fg=TEXT_MUTED,
            bg=bg,
            justify=tk.LEFT,
            anchor="w",
        )
        sub_lbl.pack(fill=tk.X, pady=(0, 6))
        setattr(card, "subtitle_label", sub_lbl)
    return card


# ==============================================================================
# 6. Data Table Component (ttk.Treeview wrapper)
# ==============================================================================

def create_data_table(
    parent: tk.Widget,
    columns: Sequence[str],
    display_names: Dict[str, str],
    min_widths: Dict[str, int],
    height: int = 8,
    selectmode: str = "browse",
    stretch_column: Optional[str] = None,
    horizontal_scroll: bool = True,
) -> Tuple[ttk.Treeview, ttk.Scrollbar, tk.Frame]:
    """
    Creates a styled Treeview data table with auto-stretching and scrollbars.
    Returns (tree, vertical_scrollbar, container_frame).
    """
    container = tk.Frame(parent, bg=BG_CANVAS, highlightthickness=1, highlightbackground=BORDER_COLOR)

    tree = ttk.Treeview(
        container,
        columns=tuple(columns),
        show="headings",
        selectmode=selectmode,
        height=height,
    )

    if not stretch_column:
        if "indicator" in columns:
            stretch_column = "indicator"
        elif columns:
            stretch_column = max(columns, key=lambda c: min_widths.get(c, 100))

    for col in columns:
        heading_text = display_names.get(col, col)
        tree.heading(col, text=heading_text)
        w = min_widths.get(col, 100)
        is_stretch = (col == stretch_column)
        anchor = "center" if col in ("layer", "status", "id", "port") else "w"
        tree.column(col, width=w, minwidth=max(50, int(w * 0.7)), anchor=anchor, stretch=is_stretch)

    v_sb = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=v_sb.set)

    if horizontal_scroll:
        h_sb = ttk.Scrollbar(container, orient="horizontal", command=tree.xview)
        tree.configure(xscrollcommand=h_sb.set)

        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        tree.grid(row=0, column=0, sticky="nsew")
        v_sb.grid(row=0, column=1, sticky="ns")
        h_sb.grid(row=1, column=0, sticky="ew")
        setattr(tree, "h_scrollbar", h_sb)
    else:
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_sb.pack(side=tk.RIGHT, fill=tk.Y)

    setattr(tree, "container", container)
    setattr(tree, "scrollbar", v_sb)
    return tree, v_sb, container


# ==============================================================================
# 7. Styled Text Entry Helper
# ==============================================================================

def create_styled_entry(
    parent: tk.Widget,
    font: Optional[Tuple[Any, ...]] = None,
    **kwargs: Any,
) -> tk.Entry:
    """Creates a styled single-line text entry with crisp border and focus cursor."""
    return tk.Entry(
        parent,
        bg=BG_CANVAS,
        fg=TEXT_MAIN,
        insertbackground=BORDER_FOCUS,
        font=font or FONT_BODY,
        relief=tk.FLAT,
        highlightbackground=BORDER_COLOR,
        highlightthickness=1,
        **kwargs,
    )

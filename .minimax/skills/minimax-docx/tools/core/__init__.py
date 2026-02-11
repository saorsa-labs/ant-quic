"""
core - Shared library for docx validation, fixing, and editing

Modules:
    namespaces: XML namespace definitions
    schema_fixer: OpenXML element order definitions and fix functions
    integrity: Business rule validation (table grid, image aspect, comments)
    markup: High-level API for comments and track changes
"""

from .namespaces import W_NS, W14_NS, W15_NS, R_NS, WP_NS, A_NS, NS, w, r
from .schema_fixer import (
    RPR_ORDER, PPR_ORDER, SECTPR_ORDER, TCPR_ORDER, TBLPR_ORDER,
    TBLBORDERS_ORDER, LEVEL_ORDER, SETTINGS_ORDER,
    # NEW exports
    PBDR_ORDER, TCMAR_ORDER, TBLCELLMAR_ORDER, NUMBERING_ORDER,
    TR_ORDER, STYLE_ORDER, TBL_ORDER, BODY_ORDER,
    get_local_name, reorder_children, fix_element_order_in_tree, fix_settings,
    # NEW functions
    fix_body_order, wrap_border_elements, fix_table_width_conservative
)
from .integrity import (
    check_table_grid_consistency,
    check_image_aspect_ratio,
    check_comments_integrity,
    check_section_margins,
    get_image_dimensions
)

__all__ = [
    # namespaces
    'W_NS', 'W14_NS', 'W15_NS', 'R_NS', 'WP_NS', 'A_NS', 'NS', 'w', 'r',
    # schema_fixer (original)
    'RPR_ORDER', 'PPR_ORDER', 'SECTPR_ORDER', 'TCPR_ORDER', 'TBLPR_ORDER',
    'TBLBORDERS_ORDER', 'LEVEL_ORDER', 'SETTINGS_ORDER',
    # schema_fixer (NEW)
    'PBDR_ORDER', 'TCMAR_ORDER', 'TBLCELLMAR_ORDER', 'NUMBERING_ORDER',
    'TR_ORDER', 'STYLE_ORDER', 'TBL_ORDER', 'BODY_ORDER',
    'get_local_name', 'reorder_children', 'fix_element_order_in_tree', 'fix_settings',
    'fix_body_order', 'wrap_border_elements', 'fix_table_width_conservative',
    # integrity
    'check_table_grid_consistency', 'check_image_aspect_ratio',
    'check_comments_integrity', 'check_section_margins', 'get_image_dimensions',
    # markup (import via: from core.markup import ...)
    'markup',
]


# Lazy import for markup module
def __getattr__(name):
    if name == 'markup':
        from . import markup
        return markup
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

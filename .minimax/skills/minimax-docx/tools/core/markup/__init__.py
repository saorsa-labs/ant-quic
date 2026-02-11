"""
core.markup - High-level API for docx editing operations.

Usage:
    from core.markup import (
        DocxSession,
        add_comment, reply_comment, resolve_comment, delete_comment,
        insert_paragraph, insert_text, propose_deletion,
        reject_insertion, restore_deletion, enable_track_changes
    )

    with DocxSession("input.docx", "output.docx") as ctx:
        add_comment(ctx, "M-SVI index", "Please define", highlight="M-SVI")
        insert_text(ctx, "The method", after="method", new_text=" and materials")
    # Automatically saves and repacks
"""

from .session import (
    DocxSession,
    DocxEditError,
    ParagraphNotFoundError,
    AmbiguousTextError,
    CommentNotFoundError,
)
from .annotations import (
    add_comment,
    reply_comment,
    resolve_comment,
    delete_comment,
)
from .changetrack import (
    insert_paragraph,
    insert_text,
    propose_deletion,
    reject_insertion,
    restore_deletion,
    enable_track_changes,
)

__all__ = [
    # Session
    'DocxSession',
    # Exceptions
    'DocxEditError',
    'ParagraphNotFoundError',
    'AmbiguousTextError',
    'CommentNotFoundError',
    # Annotations
    'add_comment',
    'reply_comment',
    'resolve_comment',
    'delete_comment',
    # Changetrack
    'insert_paragraph',
    'insert_text',
    'propose_deletion',
    'reject_insertion',
    'restore_deletion',
    'enable_track_changes',
]

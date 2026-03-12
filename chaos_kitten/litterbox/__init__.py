"""The Litterbox - Security report generation."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from chaos_kitten.litterbox.reporter import Reporter

__all__ = ["Reporter"]

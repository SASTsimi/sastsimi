"""Compatibility export for the public report query port."""

from sastsimi.ports.report_query import current_report_drafts

persisted_report_drafts = current_report_drafts

__all__ = ["current_report_drafts", "persisted_report_drafts"]

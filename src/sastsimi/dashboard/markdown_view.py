"""Bounded Markdown preview with raw HTML disabled and an HTML allowlist."""

from __future__ import annotations

from dataclasses import dataclass

import nh3
from markdown_it import MarkdownIt

_MAX_PREVIEW_BYTES = 1024 * 1024
_PARSER = MarkdownIt("commonmark", {"html": False, "linkify": False}).enable("table")
_TAGS = {
    "a",
    "blockquote",
    "br",
    "code",
    "del",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "li",
    "ol",
    "p",
    "pre",
    "s",
    "strong",
    "table",
    "tbody",
    "td",
    "th",
    "thead",
    "tr",
    "ul",
}


@dataclass(frozen=True)
class MarkdownPreview:
    markdown: str
    rendered_html: str
    truncated: bool


def render_markdown_safe(source: str) -> str:
    """Render Markdown, then remove unsafe elements, attributes and links."""

    return nh3.clean(
        _PARSER.render(source),
        tags=_TAGS,
        attributes={"a": {"href", "title"}},
        url_schemes={"http", "https", "mailto"},
        strip_comments=True,
        link_rel="noopener noreferrer",
    )


def preview_markdown(source: str) -> MarkdownPreview:
    encoded = source.encode("utf-8")
    truncated = len(encoded) > _MAX_PREVIEW_BYTES
    preview = (
        encoded[:_MAX_PREVIEW_BYTES].decode("utf-8", "ignore") if truncated else source
    )
    return MarkdownPreview(
        markdown=preview,
        rendered_html=render_markdown_safe(preview),
        truncated=truncated,
    )

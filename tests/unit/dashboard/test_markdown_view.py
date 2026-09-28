from __future__ import annotations

from sastsimi.dashboard.markdown_view import preview_markdown, render_markdown_safe


def test_markdown_structure_includes_fences_tables_and_links() -> None:
    rendered = render_markdown_safe(
        "# Finding\n\n```python\nprint('ok')\n```\n\n"
        "| Step | Result |\n| --- | --- |\n| 1 | pass |\n\n"
        "[documentation](https://example.org/help)"
    )
    assert "<h1>Finding</h1>" in rendered
    assert "<pre>" in rendered and "print" in rendered
    assert "<table>" in rendered and "<td>pass</td>" in rendered
    assert 'href="https://example.org/help"' in rendered


def test_markdown_xss_is_removed() -> None:
    rendered = render_markdown_safe(
        "<script>alert(1)</script>\n\n"
        "[bad](javascript:alert(1))\n\n"
        "<img src=x onerror=alert(1)>\n\n"
        "[safe](https://example.org/)\n"
    )
    assert "<script" not in rendered
    assert "<img" not in rendered
    assert 'href="javascript:' not in rendered
    assert 'href="https://example.org/"' in rendered


def test_large_markdown_preview_stops_at_utf8_boundary() -> None:
    source = "한" * 400_000
    preview = preview_markdown(source)
    assert preview.truncated is True
    assert len(preview.markdown.encode("utf-8")) <= 1024 * 1024
    assert "\ufffd" not in preview.markdown
    assert "한" in preview.rendered_html

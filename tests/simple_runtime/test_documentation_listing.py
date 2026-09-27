from sastsimi.simple_runtime.bootstrap_stages import _documentation_listing


def test_documentation_is_listed_apart_from_source_shallowest_first() -> None:
    tracked = [
        "src/app/views.py",
        "src/app/deep/notes.md",
        "docs/usage.md",
        "SECURITY.md",
        "docs/index.rst",
    ]

    assert _documentation_listing(tracked) == [
        "SECURITY.md",
        "docs/index.rst",
        "docs/usage.md",
        "src/app/deep/notes.md",
    ]

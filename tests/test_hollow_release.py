"""Unit tests for Stage 5d v1.2 hollow release and lookalike dependency rules."""

from pathlib import Path

from release_sentinel.differ import compare_releases, is_lookalike_dependency
from release_sentinel.extractor import ReleaseContents
from release_sentinel.models import Decision
from release_sentinel.policy import decide, load_policy


def test_is_lookalike_dependency_affix() -> None:
    top = {"dayjs", "crypto-js", "chalk", "lodash"}
    # Prefix + suffix variant
    matched, target, _ = is_lookalike_dependency("easy-day-js", top_set=top)
    assert matched is True
    assert target == "dayjs"

    # Prefix variant
    matched, target, _ = is_lookalike_dependency("plain-crypto-js", top_set=top)
    assert matched is True
    assert target == "crypto-js"

    # Exact match is legitimate, not lookalike
    matched, target, _ = is_lookalike_dependency("dayjs", top_set=top)
    assert matched is False

    # Unrelated package
    matched, target, _ = is_lookalike_dependency("my-custom-internal-lib", top_set=top)
    assert matched is False


def test_is_lookalike_dependency_typosquat() -> None:
    top = {"chalk", "lodash"}
    matched, target, _ = is_lookalike_dependency("cha1k", top_set=top)
    assert matched is True
    assert target == "chalk"


def test_hollow_dependency_injection_flagged() -> None:
    old_rc = ReleaseContents(
        files={
            "package.json": b'{"name": "foo", "version": "1.0.0", "dependencies": {}}',
            "README.md": b"# Foo v1.0.0",
            "index.js": b"module.exports = 42;",
        }
    )
    # New release only changes package.json and README.md, but adds a dependency
    new_rc = ReleaseContents(
        files={
            "package.json": (
                b'{"name": "foo", "version": "1.0.1", '
                b'"dependencies": {"easy-day-js": "^1.0.0"}}'
            ),
            "README.md": b"# Foo v1.0.1",
            "index.js": b"module.exports = 42;",  # Exact same code!
        }
    )

    evs = compare_releases(old_rc, new_rc)
    ev_ids = [e.id for e in evs]
    assert "hollow_dependency_injection" in ev_ids
    assert "lookalike_dependency_name" in ev_ids

    # Verify policy evaluation reaches BLOCK
    policy = load_policy(Path("data/policy_default.toml"))
    decision, _ = decide(evs, policy=policy)
    assert decision == Decision.BLOCK


def test_hollow_not_flagged_when_code_changes() -> None:
    old_rc = ReleaseContents(
        files={
            "package.json": b'{"name": "foo", "version": "1.0.0", "dependencies": {}}',
            "index.js": b"module.exports = 42;",
        }
    )
    # New release modifies code alongside adding dependency
    new_rc = ReleaseContents(
        files={
            "package.json": (
                b'{"name": "foo", "version": "1.0.1", '
                b'"dependencies": {"dayjs": "^1.0.0"}}'
            ),
            "index.js": b"const dayjs = require('dayjs'); module.exports = dayjs();",
        }
    )

    evs = compare_releases(old_rc, new_rc)
    ev_ids = [e.id for e in evs]
    assert "hollow_dependency_injection" not in ev_ids
    assert "lookalike_dependency_name" not in ev_ids


def test_hollow_alone_allows_not_blocks() -> None:
    # A hollow release that adds a normal, non-lookalike dependency
    old_rc = ReleaseContents(
        files={
            "package.json": b'{"name": "foo", "version": "1.0.0", "dependencies": {}}',
            "index.js": b"module.exports = 42;",
        }
    )
    new_rc = ReleaseContents(
        files={
            "package.json": (
                b'{"name": "foo", "version": "1.0.1", '
                b'"dependencies": {"string-width": "^4.0.0"}}'
            ),
            "index.js": b"module.exports = 42;",
        }
    )

    evs = compare_releases(old_rc, new_rc)
    ev_ids = [e.id for e in evs]
    assert "hollow_dependency_injection" in ev_ids
    assert "lookalike_dependency_name" not in ev_ids

    policy = load_policy(Path("data/policy_default.toml"))
    decision, _ = decide(evs, policy=policy)
    assert decision == Decision.ALLOW

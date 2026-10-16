"""Tests for the release tag rule used by the publish workflow.

A GitHub Release must be published from an explicit version tag, never from a
branch name. workflow_dispatch runs report the branch in github.ref_name, so a
manual run must supply its own tag.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from release_tag import is_release_tag, resolve_release_tag  # noqa: E402

failures = 0


def check(what, ok):
    global failures
    print(f"[{'ok' if ok else 'FAIL'}] {what}")
    if not ok:
        failures += 1


def rejects(what, ref, ref_name, manual=None):
    try:
        resolve_release_tag(ref, ref_name, manual)
    except ValueError:
        check(what, True)
        return
    check(what, False)


def accepts(what, ref, ref_name, manual=None, want=None):
    try:
        got = resolve_release_tag(ref, ref_name, manual)
    except ValueError:
        check(what, False)
        return
    check(what, got == want)


def main():
    # tag pushes are accepted
    accepts('tag push v0.2.6 accepted', 'refs/tags/v0.2.6', 'v0.2.6', None, 'v0.2.6')
    accepts('prerelease tag accepted', 'refs/tags/v0.2.6-rc1', 'v0.2.6-rc1', None, 'v0.2.6-rc1')

    # branch refs are refused
    rejects('branch push (main) refused', 'refs/heads/main', 'main')
    rejects('branch push (fix/..) refused', 'refs/heads/fix/audit-hardening', 'fix/audit-hardening')

    # manual dispatch must pass an explicit version tag
    rejects('manual run without tag refused', 'refs/heads/main', 'main', None)
    rejects('manual run with branch name refused', 'refs/heads/main', 'main', 'main')
    rejects('manual run with malformed tag refused', 'refs/heads/main', 'main', 'v1.2')
    accepts('manual run with explicit tag accepted', 'refs/heads/main', 'main', 'v0.3.0', 'v0.3.0')

    # tag pattern basics
    check('is_release_tag accepts v1.2.3', is_release_tag('v1.2.3'))
    check('is_release_tag rejects bare version', not is_release_tag('1.2.3'))
    check('is_release_tag rejects branch', not is_release_tag('main'))
    check('is_release_tag rejects empty', not is_release_tag(''))

    print(f"\n{'RELEASE TAG TESTS FAILED' if failures else 'ALL RELEASE TAG TESTS PASSED'} ({failures} failures)")
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())

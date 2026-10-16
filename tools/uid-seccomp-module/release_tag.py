"""Resolve the release tag for the publish workflow.

A GitHub Release must be published from an explicit version tag, never from a
branch name. `workflow_dispatch` runs report the branch in `github.ref_name`,
so a manual run must supply its own tag. This module is the single place that
decides whether a ref may be used as a Release tag, which keeps the rule
testable instead of buried in workflow YAML.
"""
import re
import sys

# vMAJOR.MINOR.PATCH with an optional prerelease suffix, e.g. v0.2.6 or v0.2.6-rc1.
TAG_PATTERN = re.compile(r'^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?$')


def is_release_tag(value):
    return bool(value) and TAG_PATTERN.match(value) is not None


def resolve_release_tag(ref, ref_name, manual_tag=None):
    """Return the tag to publish, or raise ValueError with the reason.

    ref       - full ref, e.g. "refs/tags/v0.2.6" or "refs/heads/main"
    ref_name  - short ref name, e.g. "v0.2.6" or "main"
    manual_tag - explicit tag supplied by a manual workflow run (may be None)
    """
    if manual_tag is not None and manual_tag.strip() != '':
        candidate = manual_tag.strip()
        if not is_release_tag(candidate):
            raise ValueError(f'manual release tag is not a version tag: {candidate!r}')
        return candidate
    if ref.startswith('refs/tags/'):
        if not is_release_tag(ref_name):
            raise ValueError(f'tag does not match vX.Y.Z: {ref_name!r}')
        return ref_name
    raise ValueError(
        'release can only be published from a version tag; '
        f'got ref {ref!r} (branch name {ref_name!r} must not be used as a tag)')


def main(argv):
    # argv: ref ref_name [manual_tag]
    if len(argv) < 3:
        print('usage: release_tag.py <ref> <ref_name> [manual_tag]', file=sys.stderr)
        return 2
    try:
        tag = resolve_release_tag(argv[1], argv[2], argv[3] if len(argv) > 3 else None)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(tag)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))

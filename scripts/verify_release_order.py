#!/usr/bin/env python3
"""Fail closed if a release tag exists or would move latest backwards."""
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request


VERSION_TAG = re.compile(
    r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z"
)


def parse_version(tag):
    if not isinstance(tag, str):
        raise ValueError(f"Unsupported release tag {tag!r}; expected stable vMAJOR.MINOR.PATCH")
    match = VERSION_TAG.fullmatch(tag)
    if match is None:
        raise ValueError(
            f"Unsupported release tag {tag!r}; expected stable vMAJOR.MINOR.PATCH"
        )
    return tuple(map(int, match.groups()))


def is_newer(candidate, latest):
    return parse_version(candidate) > parse_version(latest)


def api_request(repository, path, token):
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    return request


def verify_repository_access(repository, token):
    request = api_request(repository, "", token)
    with urllib.request.urlopen(request, timeout=15) as response:
        json.load(response)


def fetch_release(repository, tag, token, latest=False):
    path = (
        "/releases/latest"
        if latest
        else f"/releases/tags/{urllib.parse.quote(tag, safe='')}"
    )
    request = api_request(repository, path, token)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def verify_release_order(repository, candidate, token, expected_latest=None):
    parse_version(candidate)
    verify_repository_access(repository, token)
    if fetch_release(repository, candidate, token) is not None:
        raise SystemExit(f"GitHub Release {candidate} already exists")

    latest = fetch_release(repository, "latest", token, latest=True)
    if latest is not None and not isinstance(latest.get("tag_name"), str):
        raise SystemExit("GitHub returned invalid latest release metadata")
    latest_tag = latest.get("tag_name") if latest is not None else None
    if expected_latest == "none":
        expected_latest = ""
    if expected_latest is not None and (latest_tag or "") != expected_latest:
        raise SystemExit(
            f"Latest release changed during build: expected {expected_latest or '(none)'}, "
            f"found {latest_tag or '(none)'}"
        )
    if latest_tag is None:
        print("No prior GitHub Release; initial release is allowed")
        return None

    if not is_newer(candidate, latest_tag):
        raise SystemExit(
            f"Release {candidate} must be newer than current latest {latest_tag}"
        )
    print(f"Release {candidate} is newer than current latest {latest_tag}")
    return latest_tag


if __name__ == "__main__":
    latest_tag = verify_release_order(
        os.environ["GITHUB_REPOSITORY"],
        os.environ["GITHUB_REF_NAME"],
        os.environ["GH_TOKEN"],
        os.environ.get("UPKIT_EXPECTED_LATEST_TAG"),
    )
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as stream:
            stream.write(f"latest_tag={latest_tag or 'none'}\n")

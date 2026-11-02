import importlib.util
import pathlib
import unittest
import urllib.error
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "verify_release_order", ROOT / "scripts" / "verify_release_order.py"
)
release_order = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_order)


class ReleaseOrderTests(unittest.TestCase):
    def test_semver_order(self):
        self.assertTrue(release_order.is_newer("v2.0.0", "v1.99.99"))
        self.assertTrue(release_order.is_newer("v1.3.0", "v1.2.99"))
        self.assertTrue(release_order.is_newer("v1.2.4", "v1.2.3"))

    def test_same_or_older_release_is_rejected(self):
        for candidate in ("v1.2.3", "v1.2.2"):
            with self.subTest(candidate=candidate):
                with patch.object(
                    release_order,
                    "fetch_release",
                    side_effect=[None, {"tag_name": "v1.2.3"}],
                ), patch.object(
                    release_order, "verify_repository_access"
                ), self.assertRaises(SystemExit):
                    release_order.verify_release_order(
                        "owner/repo", candidate, "token"
                    )

    def test_initial_release_allows_two_not_found_responses(self):
        with patch.object(release_order, "verify_repository_access"), patch.object(
            release_order, "fetch_release", side_effect=[None, None]
        ):
            self.assertIsNone(
                release_order.verify_release_order(
                    "owner/repo", "v1.2.3", "token", expected_latest="none"
                )
            )

    def test_latest_must_match_the_build_baseline(self):
        with patch.object(release_order, "verify_repository_access"), patch.object(
            release_order,
            "fetch_release",
            side_effect=[None, {"tag_name": "v1.2.4"}],
        ), self.assertRaises(SystemExit):
            release_order.verify_release_order(
                "owner/repo", "v1.2.5", "token", expected_latest="v1.2.3"
            )

    def test_fetch_treats_only_404_as_missing(self):
        not_found = urllib.error.HTTPError("url", 404, "missing", {}, None)
        with patch.object(release_order.urllib.request, "urlopen", side_effect=not_found):
            self.assertIsNone(
                release_order.fetch_release("owner/repo", "latest", "token", latest=True)
            )
            request = release_order.urllib.request.urlopen.call_args.args[0]
            self.assertEqual(
                request.full_url,
                "https://api.github.com/repos/owner/repo/releases/latest",
            )
            not_found.close()
        forbidden = urllib.error.HTTPError("url", 403, "forbidden", {}, None)
        with patch.object(release_order.urllib.request, "urlopen", side_effect=forbidden):
            with self.assertRaises(urllib.error.HTTPError) as raised:
                release_order.fetch_release("owner/repo", "latest", "token", latest=True)
            raised.exception.close()
        with patch.object(
            release_order.urllib.request,
            "urlopen",
            side_effect=urllib.error.URLError("network unavailable"),
        ):
            with self.assertRaises(urllib.error.URLError):
                release_order.fetch_release("owner/repo", "latest", "token", latest=True)

    def test_existing_release_is_rejected(self):
        with patch.object(release_order, "verify_repository_access"), patch.object(
            release_order, "fetch_release", return_value={"tag_name": "v1.2.3"}
        ):
            with self.assertRaises(SystemExit):
                release_order.verify_release_order("owner/repo", "v1.2.3", "token")

    def test_only_stable_tags_are_supported(self):
        for tag in (
            "v01.2.3",
            "v1.2.3-rc.1",
            "v1.2.3+build",
            "v1.2.3+build-rc",
            "latest",
        ):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release_order.parse_version(tag)

    def test_repository_access_errors_are_not_treated_as_no_releases(self):
        missing_repository = urllib.error.HTTPError("url", 404, "missing", {}, None)
        with patch.object(release_order.urllib.request, "urlopen", side_effect=missing_repository):
            with self.assertRaises(urllib.error.HTTPError) as raised:
                release_order.verify_repository_access("owner/repo", "token")
            raised.exception.close()

    def test_newer_candidate_passes_with_mocked_api(self):
        with patch.object(
            release_order,
            "fetch_release",
            side_effect=[None, {"tag_name": "v1.2.3"}],
        ), patch.object(release_order, "verify_repository_access"):
            self.assertEqual(
                release_order.verify_release_order(
                    "owner/repo", "v1.2.4", "token", expected_latest="v1.2.3"
                ),
                "v1.2.3",
            )


if __name__ == "__main__":
    unittest.main()

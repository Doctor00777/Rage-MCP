"""Consistency guards for the module registry.

Cheap checks that catch silent drift — e.g. a module added to ALL_MODULES but
never given a clean-description line, or a typo'd name in DEFAULT_ALL/CRAWL_MODULES.
These are exactly the kind of gaps that otherwise surface only as confusing output
on a live scan.
"""

import unittest

from _helpers import rage


class TestModuleRegistry(unittest.TestCase):

    def test_no_duplicate_modules(self):
        self.assertEqual(len(rage.ALL_MODULES), len(set(rage.ALL_MODULES)),
                         "ALL_MODULES contains duplicates")

    def test_every_module_has_clean_description(self):
        self.assertEqual(set(rage.ALL_MODULES), set(rage.CLEAN_DESCRIPTIONS),
                         "ALL_MODULES and CLEAN_DESCRIPTIONS keys must match exactly")

    def test_default_all_is_subset(self):
        self.assertTrue(set(rage.DEFAULT_ALL) <= set(rage.ALL_MODULES))

    def test_opt_in_modules_excluded_from_default(self):
        for m in ("sqlmap", "nuclei", "tlsaudit", "openapi"):
            with self.subTest(module=m):
                self.assertIn(m, rage.ALL_MODULES)
                self.assertNotIn(m, rage.DEFAULT_ALL,
                                 f"{m} is heavy/active and must be opt-in, not in DEFAULT_ALL")

    def test_crawl_modules_are_known(self):
        self.assertTrue(rage.CRAWL_MODULES <= set(rage.ALL_MODULES),
                        "CRAWL_MODULES references an unknown module name")

    def test_owasp_tags_valid(self):
        # Clean descriptions are keyed by module, but spot-check the OWASP map is sane.
        self.assertEqual(len(rage.OWASP_2026), 10)
        self.assertTrue(all(k.startswith("A") for k in rage.OWASP_2026))


if __name__ == "__main__":
    unittest.main()

"""Tests for '#2 lean on the engines': the --thorough convenience switch and the
rule that the authoritative TLS engine supersedes the limited built-in cipher
heuristic. All pure (no network) — they exercise rage._select_modules directly.
"""

import argparse
import unittest

from _helpers import rage


def _args(**kw):
    base = dict(target="https://t/", modules=["all"], sqlmap=False, nuclei=False,
                tls_audit=False, openapi=False, headless=False, thorough=False)
    base.update(kw)
    return argparse.Namespace(**base)


class TestThoroughFlag(unittest.TestCase):

    def test_default_runs_builtins_only(self):
        modules, headless, notes = rage._select_modules(_args())
        self.assertFalse(headless)
        self.assertEqual(notes, [])
        for engine in ("sqlmap", "nuclei", "tlsaudit", "openapi"):
            self.assertNotIn(engine, modules, f"{engine} must stay opt-in by default")
        self.assertIn("ciphers", modules)

    def test_thorough_enables_every_engine_and_headless(self):
        modules, headless, _notes = rage._select_modules(_args(thorough=True))
        self.assertTrue(headless, "--thorough implies a headless crawl")
        for engine in ("sqlmap", "nuclei", "tlsaudit", "openapi"):
            self.assertIn(engine, modules, f"--thorough must enable {engine}")

    def test_individual_engine_flag_still_works(self):
        modules, _h, _n = rage._select_modules(_args(sqlmap=True))
        self.assertIn("sqlmap", modules)
        self.assertNotIn("nuclei", modules)


class TestTlsEngineSupersedesCiphers(unittest.TestCase):
    """When the external TLS engine runs, drop the limited built-in cipher probe."""

    def test_thorough_drops_builtin_ciphers_with_a_note(self):
        modules, _h, notes = rage._select_modules(_args(thorough=True))
        self.assertNotIn("ciphers", modules, "built-in ciphers must yield to the TLS engine")
        self.assertIn("tlsaudit", modules)
        self.assertTrue(any("cipher check skipped" in n.title.lower() for n in notes),
                        "a note must explain the superseded cipher check")

    def test_explicit_ciphers_plus_tlsaudit_also_supersedes(self):
        modules, _h, notes = rage._select_modules(_args(modules=["ciphers", "tlsaudit"]))
        self.assertNotIn("ciphers", modules)
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0].module, "ciphers")
        self.assertEqual(notes[0].severity, "info")

    def test_ciphers_kept_when_tls_engine_off(self):
        modules, _h, notes = rage._select_modules(_args(modules=["ciphers"]))
        self.assertIn("ciphers", modules)
        self.assertEqual(notes, [])


if __name__ == "__main__":
    unittest.main()

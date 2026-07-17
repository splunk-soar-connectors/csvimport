# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

import unittest

from csvimport_utils import escape_csv_formula


class EscapeCsvFormulaTestCase(unittest.TestCase):
    def test_escapes_formula_prefixes(self):
        for value in ("=1+1", "+cmd", "-2+3", "@SUM(A1:A2)", "\t=1+1", "\r=1+1"):
            with self.subTest(value=value):
                self.assertEqual(escape_csv_formula(value), f"'{value}")

    def test_escapes_formula_prefix_after_whitespace(self):
        self.assertEqual(escape_csv_formula("  =1+1"), "'  =1+1")

    def test_preserves_safe_and_non_string_values(self):
        self.assertEqual(escape_csv_formula("example"), "example")
        self.assertEqual(escape_csv_formula(""), "")
        self.assertEqual(escape_csv_formula(42), 42)

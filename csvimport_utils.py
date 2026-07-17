# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def escape_csv_formula(value):
    if not isinstance(value, str):
        return value

    stripped_value = value.lstrip()
    if value.startswith(("\t", "\r")) or stripped_value.startswith(CSV_FORMULA_PREFIXES):
        return f"'{value}"

    return value

"""Rule package.

Importing this package imports every rule module, which is what populates the
global registry through the ``@register`` decorator.  Nothing else needs to
know which modules exist, so adding a detection is a one-line change here.
"""

from __future__ import annotations

import importlib.util
import os
from typing import Iterable

from ..core.rulebase import REGISTRY, Rule, ScanContext, run_rules
from . import (  # noqa: F401 - imported for their registration side effect
    r_composite,
    r_drift,
    r_injection,
    r_posture,
    r_supplychain,
)

__all__ = ["REGISTRY", "Rule", "ScanContext", "load_plugins", "run_rules"]


def load_plugins(paths: Iterable[str]) -> int:
    """Import extra rule modules from operator-supplied paths.

    Bulwark ships opinionated rules, but every organisation has one control
    nobody else needs -- an internal package registry, a banned vendor, a
    naming convention.  A plugin is an ordinary Python module that imports
    ``Rule`` and ``register`` and defines its rules; it lands in the same
    registry and reports through the same pipeline.

    Returns the number of modules successfully loaded.  Failures are skipped
    rather than raised: a broken custom rule should not stop a scan from
    finding real problems.
    """
    loaded = 0
    for raw_path in paths or ():
        path = os.path.abspath(str(raw_path))
        if not os.path.isfile(path):
            continue
        module_name = "bulwark_plugin_" + os.path.splitext(os.path.basename(path))[0]
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            loaded += 1
        except Exception:
            continue
    return loaded

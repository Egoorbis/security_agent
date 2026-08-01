"""Terraform HCL file parser.

Parses ``.tf`` files using ``python-hcl2`` and returns a normalised list of
resource dictionaries suitable for evaluation by the policy engine.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    import hcl2  # type: ignore[import]

    _HCL2_AVAILABLE = True
except ImportError:  # pragma: no cover
    _HCL2_AVAILABLE = False
    logger.warning("python-hcl2 not installed; Terraform parsing will be skipped.")


def parse_terraform_file(path: Path) -> list[dict[str, Any]]:
    """Parse a single ``.tf`` file and return a list of resource dicts.

    Each dict has the keys:
    - ``resource_type``  – e.g. ``"azurerm_storage_account"``
    - ``resource_name``  – the logical name given in the HCL
    - ``file``           – source file path (string)
    - ``config``         – raw attribute dict for the resource block
    """
    if not _HCL2_AVAILABLE:
        return []

    resources: list[dict[str, Any]] = []
    try:
        with open(path) as fh:
            data = hcl2.load(fh)
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return []

    for resource_block in data.get("resource", []):
        for resource_type, instances in resource_block.items():
            for resource_name, config_list in instances.items():
                # hcl2 wraps each block in a list
                config = config_list[0] if isinstance(config_list, list) else config_list
                resources.append(
                    {
                        "resource_type": resource_type,
                        "resource_name": resource_name,
                        "file": str(path),
                        "config": config,
                    }
                )
    return resources


def parse_terraform_files(paths: list[Path]) -> list[dict[str, Any]]:
    """Parse multiple ``.tf`` files and return combined resource list."""
    resources: list[dict[str, Any]] = []
    for path in paths:
        resources.extend(parse_terraform_file(path))
    logger.debug("Parsed %d resources from %d Terraform file(s)", len(resources), len(paths))
    return resources

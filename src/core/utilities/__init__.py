"""
Core Utilities Package.
Fornisce funzioni di supporto per IO sicuro, parsing OpenAPI e manipolazione URL.
"""

from src.core.utilities.file_io import safe_read_json, safe_write_json
from src.core.utilities.openapi_parser import load_openapi_spec
from src.core.utilities.url_utils import extract_resource_name_from_path

__all__ = [
    "safe_read_json",
    "safe_write_json",
    "load_openapi_spec",
    "extract_resource_name_from_path",
]

"""Lock-file parsers for the supply-chain SCA subsystem.

Importing the package registers every parser with the base dispatcher.
"""

from . import base  # noqa: F401
from . import python  # noqa: F401  (registers requirements/poetry/pipfile)
from . import javascript  # noqa: F401  (registers package-lock/yarn)

from .base import parse_all, normalize_name, make_purl

__all__ = ["parse_all", "normalize_name", "make_purl"]

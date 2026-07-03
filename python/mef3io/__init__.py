"""mef3io — MEF 3.0 read/write.

C++ backend (``_mef3io`` extension) with a pure-Python fallback. The public
API (``Reader``, ``Writer``) is filled in over the implementation phases; P0
exposes only backend availability so the build can be validated end to end.
"""

__version__ = "0.1.0.dev0"

try:
    from . import _mef3io  # noqa: F401

    _HAVE_CPP = True
except ImportError:  # pragma: no cover - exercised only on exotic platforms
    _mef3io = None
    _HAVE_CPP = False


def have_cpp_backend() -> bool:
    """True if the compiled C++ backend is importable."""
    return _HAVE_CPP


__all__ = ["have_cpp_backend", "__version__"]

"""Entry point for ``python -m tools.docgen`` (PEP 338 ``__main__``).

The implementation lives in ``tools.docgen.generate``; this module only
delegates to ``main()`` so the package stays runnable as a module.
"""

from __future__ import annotations

from tools.docgen.generate import main


if __name__ == "__main__":
    main()

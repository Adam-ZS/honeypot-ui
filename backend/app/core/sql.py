"""SQL text helpers.

LIKE escaping lived in two places and only one of them was right. The IOC
search escaped the two-character sequence ``\\\\`` rather than a single
backslash, and handed ``ilike`` a two-character escape where SQLAlchemy wants
one, so a ``%`` or ``_`` typed into that box was treated as a wildcard instead
of a literal. One implementation, used everywhere, is the fix.
"""

#: The escape character passed to ``ilike(..., escape=LIKE_ESCAPE)``. SQLAlchemy
#: requires exactly one character here.
LIKE_ESCAPE = "\\"


def escape_like(value: str) -> str:
    """Neutralise LIKE wildcards in user-supplied search text.

    The backslash must be doubled first, or it would go on to escape the
    escapes added for ``%`` and ``_``.
    """
    return (
        value.replace(LIKE_ESCAPE, LIKE_ESCAPE * 2)
        .replace("%", LIKE_ESCAPE + "%")
        .replace("_", LIKE_ESCAPE + "_")
    )

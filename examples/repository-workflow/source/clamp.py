"""Small, deliberately regressed source for the local workflow example."""


def clamp(value, lower, upper):
    """Constrain a finite number to inclusive bounds; reject reversed bounds."""
    if lower > upper:
        raise ValueError("lower must not exceed upper")
    if value < lower:
        return lower
    if value > upper:
        return upper
    return lower

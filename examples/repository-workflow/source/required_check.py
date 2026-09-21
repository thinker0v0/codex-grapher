"""Read-only acceptance examples; only clamp.py is an allowed worker edit."""

from runpy import run_path


clamp = run_path("clamp.py")["clamp"]
for value, lower, upper, expected in [
    (-1, 0, 5, 0),
    (0, 0, 5, 0),
    (3, 0, 5, 3),
    (5, 0, 5, 5),
    (6, 0, 5, 5),
    (1.5, 1.0, 2.0, 1.5),
    (4, 4, 4, 4),
]:
    actual = clamp(value, lower, upper)
    assert actual == expected, ((value, lower, upper), expected, actual)

try:
    clamp(0, 3, 2)
except ValueError:
    pass
else:
    raise AssertionError("Expected ValueError for reversed bounds")

print("Required clamp cases passed")

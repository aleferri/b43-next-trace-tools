"""Where the files the tools read live, outside the package."""
import os


def checkout():
    """The root of the source checkout the package runs from, or None.

    Some tools read the on-device sources next to the package, which an
    installed copy does not carry.
    """
    root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    if os.path.isfile(os.path.join(root, "pyproject.toml")):
        return root
    return None

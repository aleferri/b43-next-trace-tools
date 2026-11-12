"""Where the files the tools read live, outside the package.

The port, its unit harness and the wl-diag captures are in a b43-ac-wip
checkout, named by $B43_TREE. $B43_DATA overrides where the captures are
taken from: a directory with one subdirectory per board, as router-data/.
"""
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


def _directory(var, what, required):
    value = os.environ.get(var)
    if not value:
        if required:
            raise SystemExit(f"{var} is not set: point it at {what}")
        return None
    if not os.path.isdir(value):
        raise SystemExit(f"{var}={value}: not a directory")
    return value


def driver_tree(required=True):
    """The b43-ac-wip checkout, $B43_TREE."""
    return _directory("B43_TREE", "the b43-ac-wip checkout", required)


def driver_src():
    """The b43 sources of the port."""
    return os.path.join(driver_tree(), "b43")


def unit_dir():
    """The unit harness of the port, where ac_trace is built."""
    return os.path.join(driver_tree(), "test", "unit")


def data_dir(required=True):
    """The captures, one directory per board: $B43_DATA, else router-data/."""
    value = _directory("B43_DATA", "the captures, one directory per board",
                       required=False)
    if value:
        return value
    tree = driver_tree(required)
    return os.path.join(tree, "router-data") if tree else None

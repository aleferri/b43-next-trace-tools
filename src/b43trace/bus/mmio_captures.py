"""List the wl-mmio-trap captures of the b43-next-traces checkout.

One line per capture, tab separated: the label (chip/board/set/stem), the
ops mmio2ops decoded and the raw records, so a shell loop can cut the
column it needs. PATTERN keeps the captures whose label contains it.

  b43trace mmio-captures [PATTERN]
"""
import argparse

from b43trace import tracelib


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pattern", nargs="?", default="")
    a = ap.parse_args()
    for c in tracelib.mmio_captures():
        if a.pattern in c.label:
            print(f"{c.label}\t{c.ops}\t{c.raw or '-'}")


if __name__ == "__main__":
    main()

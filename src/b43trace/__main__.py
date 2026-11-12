"""b43trace TOOL [ARGS...]: run one of the tools; without TOOL, list them.

A tool is a module of the package that runs as a script; its command is the
module name with dashes, so `b43trace trace-filter` is
`python -m b43trace.pipeline.trace_filter`.
"""
import ast
import os
import pkgutil
import runpy
import sys

import b43trace


def _summary(name, tree, source):
    """The first sentence of the docstring, or of the header comment."""
    text = ast.get_docstring(tree)
    if not text:
        lines = []
        for line in source.splitlines():
            if not line.startswith("#"):
                break
            lines.append(line[1:].strip())
        text = "\n".join(lines)
    words = []
    for paragraph in text.strip().split("\n\n"):
        words = paragraph.split()
        if words and words[0].rstrip(":") == name + ".py":
            words = words[1:]
            if words and words[0] in ("-", ":"):
                words = words[1:]
        if words:
            break
    sentence = " ".join(words)
    end = sentence.find(". ")
    if end != -1:
        sentence = sentence[:end + 1]
    return sentence if len(sentence) <= 100 else sentence[:99] + "…"


def _is_script(tree):
    for node in tree.body:
        if (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name)
                and node.test.left.id == "__name__"):
            return True
    return False


def tools():
    """{command: (module, group, summary)}, from the sources, nothing imported."""
    found = {}
    for info in pkgutil.walk_packages(b43trace.__path__, "b43trace."):
        last = info.name.rsplit(".", 1)[-1]
        if info.ispkg or last.startswith("_"):
            continue
        path = os.path.join(info.module_finder.path, last + ".py")
        with open(path, encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source, path)
        if not _is_script(tree):
            continue
        command = last.replace("_", "-")
        if command in found:
            raise RuntimeError(f"two tools named {command}: "
                               f"{found[command][0]} and {info.name}")
        group = info.name.rsplit(".", 1)[0]
        found[command] = (info.name, group, _summary(last, tree, source))
    return found


def _groups():
    out = {}
    for info in pkgutil.iter_modules(b43trace.__path__, "b43trace."):
        if info.ispkg:
            path = os.path.join(info.module_finder.path,
                                info.name.rsplit(".", 1)[-1], "__init__.py")
            with open(path, encoding="utf-8") as f:
                out[info.name] = ast.get_docstring(ast.parse(f.read())) or ""
    return out


def usage(table, out):
    print(__doc__.strip().splitlines()[0], file=out)
    headers = _groups()
    headers["b43trace"] = "Other"
    by_group = {}
    for command, (_, group, summary) in sorted(table.items()):
        by_group.setdefault(group, []).append((command, summary))
    width = min(max(map(len, table)), 20)
    for group in sorted(by_group, key=lambda g: (g == "b43trace", g)):
        print(f"\n{headers.get(group, group)}", file=out)
        for command, summary in by_group[group]:
            if len(command) > width:
                print(f"  {command}\n  {'':<{width}}  {summary}", file=out)
            else:
                print(f"  {command:<{width}}  {summary}", file=out)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    table = tools()
    if not argv or argv[0] in ("-h", "--help"):
        usage(table, sys.stdout)
        return 0
    command, args = argv[0], argv[1:]
    if command not in table:
        print(f"b43trace: no tool {command!r}", file=sys.stderr)
        usage(table, sys.stderr)
        return 2
    sys.argv = [f"b43trace {command}"] + args
    runpy.run_module(table[command][0], run_name="__main__")
    return 0


if __name__ == "__main__":
    sys.exit(main())

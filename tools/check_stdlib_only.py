"""Enforce empty core dependencies and stdlib-only imports without executing source."""

from __future__ import annotations

import ast
import sys
from pathlib import Path


def check_imports(root: Path) -> list[str]:
    errors = []
    allowed = sys.stdlib_module_names | {"whalescan", "__future__"}
    tomllib_guard = ast.dump(ast.parse("sys.version_info >= (3, 11)", mode="eval").body)

    def visit(
        node: ast.AST,
        path: Path,
        function: bool = False,
        guarded: bool = False,
        versioned_stdlib: bool = False,
    ) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Defaults and decorators still execute at module scope.
            for child in (*node.decorator_list, node.args, *node.body):
                visit(child, path, function or child in node.body, False, versioned_stdlib)
            return
        if isinstance(node, ast.If) and ast.dump(node.test) == tomllib_guard:
            # tomllib is stdlib in 3.11+, but absent from 3.10's stdlib_module_names.
            # Permit only that guarded import; still check both branches for dependencies.
            for child in node.body:
                visit(child, path, function, guarded, True)
            for child in node.orelse:
                visit(child, path, function, guarded, versioned_stdlib)
            return
        if isinstance(node, ast.Try):
            catches_import = any(
                isinstance(h.type, ast.Name) and h.type.id == "ImportError" for h in node.handlers
            )
            for child in node.body:
                visit(child, path, function, guarded or (function and catches_import), versioned_stdlib)
            for child in (*node.handlers, *node.orelse, *node.finalbody):
                visit(child, path, function, guarded, versioned_stdlib)
            return
        modules = []
        if isinstance(node, ast.Import):
            modules = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            modules = [(node.module or "").split(".")[0]]
        for module in modules:
            if (
                module not in allowed
                and not (function and guarded)
                and not (module == "tomllib" and versioned_stdlib)
            ):
                errors.append(f"{path}:{getattr(node, 'lineno', 0)}: non-stdlib import: {module}")
        for child in ast.iter_child_nodes(node):
            visit(child, path, function, guarded, versioned_stdlib)

    for path in sorted(root.rglob("*.py")):
        visit(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)), path)
    return errors


def check_dependencies(manifest: Path) -> None:
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        # The engine's existing vendored TOML parser supports Python 3.10.
        sys.path.insert(0, str(manifest.parent / "src"))
        from whalescan._vendor import tomli as tomllib
    with manifest.open("rb") as stream:
        data = tomllib.load(stream)
    if data["project"].get("dependencies") != []:
        raise ValueError("[project].dependencies must be explicitly []")


def main() -> None:
    check_dependencies(Path("engine/pyproject.toml"))
    errors = check_imports(Path("engine/src/whalescan"))
    if errors:
        raise SystemExit("\n".join(errors))
    print("Core dependencies and imports are stdlib-only")


if __name__ == "__main__":
    main()

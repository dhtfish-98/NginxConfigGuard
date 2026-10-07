#!/usr/bin/env python3
# Copyright (c) 2026 dhtfish98
"""Stage tracked project inputs in an external central Build directory."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import uuid


EXCLUDED = {"Build", "node_modules", "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache", ".venv", ".tox", ".nox", "CMakeFiles"}


def relative(value):
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value or "\0" in value or any(p in {"", ".", "..", ".git"} for p in value.split("/")):
        raise ValueError("Invalid input path")
    return Path(value)


def regular_input(root, path):
    """Read a regular file only after checking each checkout path component."""
    source = root
    for index, part in enumerate(path.parts):
        source = source / part
        info = source.lstat()
        expected = stat.S_ISREG if index == len(path.parts) - 1 else stat.S_ISDIR
        if not expected(info.st_mode):
            raise ValueError("Input contains a link or non-regular path")
    return source.read_bytes(), stat.S_IMODE(info.st_mode)


def real_directory(path, *, new=False):
    """Create directories without following an existing linked component."""
    path = Path(path).absolute()
    if ".." in path.parts:
        raise ValueError("Output directory contains parent traversal")
    current = Path(path.anchor)
    for index, part in enumerate(path.parts[1:]):
        current = current / part
        try:
            current.mkdir()
        except FileExistsError:
            if new and index == len(path.parts) - 2:
                raise ValueError("Stage already exists; use a new independent output")
        if not stat.S_ISDIR(current.lstat().st_mode):
            raise ValueError("Output contains a link or non-directory path")
    return path


def build_root(root, requested):
    requested = requested.expanduser().absolute()
    if requested.is_symlink():
        raise ValueError("Build must be a real directory")
    # Canonical system ancestors (for example /var on macOS) are allowed, but
    # their resolved destination must remain outside the source checkout.
    build = requested.resolve()
    if build == root or root in build.parents:
        raise ValueError("Central Build must be outside the source checkout")
    return real_directory(build)


def project_directory(build, name):
    project = relative(name)
    if len(project.parts) != 1 or name in EXCLUDED:
        raise ValueError("Project must be one directory name")
    return real_directory(build / project)


def stage(root, directory, configuration):
    root = Path(root).resolve(strict=True)
    directory = Path(directory).absolute()
    resolved = directory.resolve()
    if resolved == root or root in resolved.parents:
        raise ValueError("Stage must be outside the source checkout")
    if directory.exists() or directory.is_symlink():
        raise ValueError("Stage already exists; use --build for a new independent output")
    listing = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "-z"],
        check=True, capture_output=True,
    ).stdout
    planned = {}
    for raw in filter(None, listing.split(b"\0")):
        name = raw.decode("utf-8")
        path = relative(name)
        if any(part in EXCLUDED or part.endswith((".egg-info", ".dist-info")) for part in path.parts):
            continue
        if path.name.endswith((".pyc", ".pyo")) or path.name == ".DS_Store":
            continue
        planned[path] = regular_input(root, path)
    tracked = set(planned)
    for item in configuration["restored_inputs"]:
        original = relative(item["original"])
        stored = relative(item["stored"])
        if stored not in tracked or any(part in EXCLUDED for part in original.parts):
            raise ValueError("Restored input must refer to a tracked project file")
        content, mode = planned[stored]
        if hashlib.sha256(content).hexdigest() != item["sha256"]:
            raise ValueError("Saved input changed")
        if original in planned and planned[original][0] != content:
            raise ValueError("Conflicting restored input")
        planned[original] = content, mode
    # Validate all inputs before creating any staged files. The caller owns
    # this checkout and output tree; concurrent modification is unsupported.
    real_directory(directory, new=True)
    for path, (content, mode) in planned.items():
        destination = directory / path
        real_directory(destination.parent)
        with destination.open("xb") as stream:
            stream.write(content)
        destination.chmod(mode)
    return directory


def environment(build):
    for rel in ("临时", "缓存/python", "缓存/pip", "缓存/npm", "缓存/ruff", "缓存/go", "缓存/go-mod", "缓存/go-path", "输出/go-bin", "缓存/cargo", "缓存/xdg", "缓存/ccache", "缓存/sccache"):
        real_directory(build / rel)
    return dict(os.environ, TMPDIR=str(build / "临时"), TMP=str(build / "临时"), TEMP=str(build / "临时"), PYTHONPYCACHEPREFIX=str(build / "缓存/python"), PIP_CACHE_DIR=str(build / "缓存/pip"), npm_config_cache=str(build / "缓存/npm"), RUFF_CACHE_DIR=str(build / "缓存/ruff"), GOCACHE=str(build / "缓存/go"), GOMODCACHE=str(build / "缓存/go-mod"), GOTMPDIR=str(build / "临时"), GOPATH=str(build / "缓存/go-path"), GOBIN=str(build / "输出/go-bin"), CARGO_HOME=str(build / "缓存/cargo"), XDG_CACHE_HOME=str(build / "缓存/xdg"), CCACHE_DIR=str(build / "缓存/ccache"), SCCACHE_DIR=str(build / "缓存/sccache"))


def main():
    parser = argparse.ArgumentParser(description="文档集中保存；只把已跟踪源码暂存到项目外的中央 Build。")
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--stage", action="store_true")
    operation.add_argument("--build", action="store_true")
    parser.add_argument("--ci", action="store_true", help="固定暂存到中央 Build/项目名/源码，供一次性 CI 使用")
    parser.add_argument("--build-root", type=Path, help="项目外的中央 Build 路径；默认是项目目录的同级 Build")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    build = build_root(root, args.build_root or root.parent / "Build")
    config = json.loads((root / "构建配置.json").read_text())
    project_build = project_directory(build, config["project"])
    env = environment(build)
    label = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    output = project_build / "新构建" / label
    source = project_build / "源码" if args.ci else output / "source"
    stage(root, source, config)
    if args.stage:
        print(json.dumps({"status": "STAGED_NO_BUILD_EXECUTED", "source": str(source)}, ensure_ascii=False))
        return 0
    output.mkdir(parents=True, exist_ok=True)
    packages = output / "发行"
    packages.mkdir()
    kind = config["kind"]
    if kind == "python":
        commands = [[sys.executable, "-m", "build", "--outdir", str(packages)]]
    elif kind == "python-wheel":
        commands = [[sys.executable, "-m", "build", "--wheel", "--outdir", str(packages)]]
    elif kind == "node":
        commands = [["npm", "pack", "--ignore-scripts", "--pack-destination", str(packages)]]
    elif kind == "cmake":
        binary = output / "编译"
        commands = [["cmake", "-S", str(source), "-B", str(binary), "-DCMAKE_BUILD_TYPE=Release"], ["cmake", "--build", str(binary), "--parallel", "2"], ["cmake", "--install", str(binary), "--prefix", str(output / "安装")]]
    elif kind == "rust":
        env["CARGO_TARGET_DIR"] = str(output / "编译")
        commands = [["cargo", "build", "--locked", "--manifest-path", config["cargo_manifest"]]]
    elif kind == "go":
        commands = [["go", "build", "-o", str(output / "编译") + "/", "./..."]]
    else:
        print(json.dumps({"status": "OPEN_MANUAL_ADAPTER", "source": str(source), "kind": kind}, ensure_ascii=False))
        return 3
    results = []
    for i, command in enumerate(commands, 1):
        log = output / f"{i:02}.log"
        with log.open("w") as stream:
            completed = subprocess.run(command, cwd=source, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=1800)
        results.append({"command": command, "exit_code": completed.returncode, "log": str(log)})
        if completed.returncode:
            break
    status = "PASS_BUILD_COMMANDS" if results and all(r["exit_code"] == 0 for r in results) else "FAIL"
    report = {"status": status, "source": str(source), "commands": results, "scope": "Build commands only; no project tests, installation to system applications, commit or publication."}
    (output / "build.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if status == "PASS_BUILD_COMMANDS" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError, UnicodeError) as exc:
        print(json.dumps({"status": "ERROR", "reason": str(exc)}, ensure_ascii=False), file=sys.stderr)
        sys.exit(2)

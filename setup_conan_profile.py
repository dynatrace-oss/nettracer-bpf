#!/usr/bin/env python3
"""
Sets up Conan 2.x profile for clang compiler.
Usage: python3 setup_conan_profile.py [--llvm-version 18]
"""
import argparse
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Tuple


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Setup Conan profile for clang")
    parser.add_argument("--llvm-version", type=int, default=18, help="LLVM version to use (default: 18)")
    parser.add_argument("--cppstd", type=int, default=23, help="C++ standard to use (default: 23)")
    parser.add_argument("--build-type", default="Release", choices=["Release", "Debug", "RelWithDebInfo", "MinSizeRel"], help="Build type (default: Release)")
    return parser.parse_args()


def setup_conan_remote() -> None:
    """Add conancenter remote if not already configured."""
    result = subprocess.run(
        ["conan", "remote", "list"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True
    )
    if "conancenter" not in result.stdout:
        print("Adding conancenter remote...")
        subprocess.run(
            ["conan", "remote", "add", "conancenter", "https://center.conan.io"],
            check=True
        )
    else:
        print("conancenter remote already configured.")


def find_compiler(llvm_version: int) -> Tuple[str, str]:
    if not isinstance(llvm_version, int) or llvm_version < 1 or llvm_version > 99:
        raise RuntimeError(f"Invalid LLVM version: {llvm_version}")
        
    clang = f"clang-{llvm_version}"
    clangpp = f"clang++-{llvm_version}"

    if not shutil.which(clang):
        raise RuntimeError(f"{clang} not found in PATH")
    if not shutil.which(clangpp):
        raise RuntimeError(f"{clangpp} not found in PATH")

    return clang, clangpp


def detect_compiler_version(clang: str) -> int:
    result = subprocess.run(
        [clang, "--version"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True
    )
    match = re.search(r"clang version (\d+)", result.stdout)
    if not match:
        raise RuntimeError(f"Cannot detect clang version from: {result.stdout}")
    return int(match.group(1))


def detect_conan_home() -> Path:
    result = subprocess.run(
        ["conan", "config", "home"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True
    )
    return Path(result.stdout.strip())


def detect_arch() -> str:
    machine = platform.machine()
    arch_map = {"x86_64": "x86_64", "aarch64": "armv8"}
    if machine not in arch_map:
        raise RuntimeError(f"Unsupported architecture: {machine}")
    return arch_map[machine]


def create_profile(
    conan_home: Path,
    clang: str,
    clangpp: str,
    compiler_version: int,
    cppstd: int,
    build_type: str,
    arch: str
) -> None:
    profiles_dir = conan_home / "profiles"
    profiles_dir.mkdir(parents=True, exist_ok=True)
    profile_path = profiles_dir / "default"

    profile_content = f"""\
[settings]
os=Linux
arch={arch}
compiler=clang
compiler.version={compiler_version}
compiler.libcxx=libstdc++11
compiler.cppstd={cppstd}
build_type={build_type}

[conf]
tools.build:compiler_executables={{"c": "{clang}", "cpp": "{clangpp}"}}
"""
    profile_path.write_text(profile_content, encoding="utf-8")
    print(f"Conan profile written to: {profile_path}")


def show_profile() -> None:
    subprocess.run(["conan", "profile", "show"], check=True)


def main() -> None:
    try:
        args = parse_args()

        print(f"Setting up Conan profile for clang-{args.llvm_version}...")

        clang, clangpp = find_compiler(args.llvm_version)
        compiler_version = detect_compiler_version(clang)
        arch = detect_arch()

        print(f"Detected compiler version: {compiler_version}")
        print(f"Detected architecture: {arch}")

        subprocess.run(["conan", "profile", "detect", "--force"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True)

        conan_home = detect_conan_home()
        create_profile(conan_home, clang, clangpp, compiler_version, args.cppstd, args.build_type, arch)
        setup_conan_remote()

        show_profile()
        print("Done.")
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
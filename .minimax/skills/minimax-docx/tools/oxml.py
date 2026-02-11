#!/usr/bin/env python3
"""
oxml.py - Cross-platform unified entry point for DOCX generation

Usage: python oxml.py {env|init|build|validate} [args]

Design principles:
- Single entry point, no need to remember multiple scripts
- Auto-detect environment, compatible with installed/not installed/partial
- Self-aware of skill directory location via __file__
- All output must pass validation
"""

import os
import platform
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Optional, Tuple

# Self-aware paths
SCRIPT_DIR = Path(__file__).parent.resolve()
SKILL_DIR = SCRIPT_DIR.parent.resolve()

# Error mapping for common C# compilation errors
ERROR_MAP = {
    "CS0246.*'Separator'": "Use 'SeparatorMark' instead of 'Separator'",
    "CS0246.*'ContinuationSeparator'": "Use 'ContinuationSeparatorMark'",
    "CS1009": "Unrecognized escape → Use @\"...\" verbatim string",
    "CS1010": "Newline in constant → Use @\"...\" for multiline",
    "CS0103.*'WordprocessingDocument'": "Add: using DocumentFormat.OpenXml.Packaging;",
    "CS0103.*'Body'": "Add: using DocumentFormat.OpenXml.Wordprocessing;",
    "CS0103.*'Paragraph'": "Add: using DocumentFormat.OpenXml.Wordprocessing;",
    "CS0029.*cannot implicitly convert": "Type mismatch: check int vs string for IDs",
}


def get_workspace_dir() -> Path:
    """
    Get workspace directory from environment or use current working directory.
    Desktop mode sets WORKSPACE_DIR env var.
    """
    env_workspace = os.environ.get("WORKSPACE_DIR")
    if env_workspace:
        return Path(env_workspace)
    return Path.cwd()


def get_work_dir() -> Path:
    """Get the .oxml working directory"""
    return get_workspace_dir() / ".oxml"


def get_output_dir() -> Path:
    """Get the output directory"""
    return get_workspace_dir() / "output"


# ============================================================================
# Dependency detection
# ============================================================================

def find_dotnet() -> Optional[Path]:
    """Find dotnet executable, return full path or None"""
    system = platform.system()

    # Common candidates
    candidates = ["dotnet"]

    if system == "Windows":
        candidates.extend([
            Path.home() / ".dotnet" / "dotnet.exe",
            Path(os.environ.get("ProgramFiles", "")) / "dotnet" / "dotnet.exe",
            Path(os.environ.get("ProgramFiles(x86)", "")) / "dotnet" / "dotnet.exe",
        ])
    else:
        candidates.extend([
            Path.home() / ".dotnet" / "dotnet",
            Path("/usr/local/share/dotnet/dotnet"),
            Path("/usr/share/dotnet/dotnet"),
            Path("/opt/dotnet/dotnet"),
        ])

    for candidate in candidates:
        if isinstance(candidate, str):
            # Check in PATH
            result = shutil.which(candidate)
            if result:
                return Path(result)
        elif candidate.exists() and candidate.is_file():
            return candidate

    return None


def check_dotnet_status() -> Tuple[str, Optional[Path], Optional[str]]:
    """
    Check dotnet status.
    Returns: (status, path, version)
    status: 'ok' | 'outdated' | 'broken' | 'missing'
    """
    dotnet_bin = find_dotnet()

    if not dotnet_bin:
        return ("missing", None, None)

    try:
        result = subprocess.run(
            [str(dotnet_bin), "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            try:
                major = int(version.split(".")[0])
                if major >= 6:
                    return ("ok", dotnet_bin, version)
                else:
                    return ("outdated", dotnet_bin, version)
            except (ValueError, IndexError):
                return ("broken", dotnet_bin, None)
        else:
            return ("broken", dotnet_bin, None)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ("broken", dotnet_bin, None)


def install_dotnet() -> Optional[Path]:
    """Install .NET SDK. Returns dotnet path on success."""
    system = platform.system()
    print("  Downloading .NET SDK...")

    try:
        if system == "Windows":
            # Use PowerShell to download and run install script
            script_url = "https://dot.net/v1/dotnet-install.ps1"
            install_dir = Path.home() / ".dotnet"

            ps_command = f"""
            $ErrorActionPreference = 'Stop'
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $script = Invoke-WebRequest -Uri '{script_url}' -UseBasicParsing
            $scriptBlock = [scriptblock]::Create($script.Content)
            & $scriptBlock -Channel 8.0 -InstallDir '{install_dir}'
            """

            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=300
            )

            dotnet_path = install_dir / "dotnet.exe"

        else:  # macOS / Linux
            script_url = "https://dot.net/v1/dotnet-install.sh"
            install_dir = Path.home() / ".dotnet"

            # Download script
            script_path = Path(tempfile.gettempdir()) / "dotnet-install.sh"
            subprocess.run(
                ["curl", "-sSL", script_url, "-o", str(script_path)],
                check=True,
                timeout=60
            )
            script_path.chmod(0o755)

            # Run install
            subprocess.run(
                [str(script_path), "--channel", "8.0", "--install-dir", str(install_dir)],
                check=True,
                timeout=300
            )

            dotnet_path = install_dir / "dotnet"

        if dotnet_path.exists():
            # Verify installation
            result = subprocess.run(
                [str(dotnet_path), "--version"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                print(f"  ✓ Installed: {result.stdout.strip()}")
                return dotnet_path

        print("  ✗ Installation failed")
        print("    Manual: https://dotnet.microsoft.com/download")
        return None

    except Exception as e:
        print(f"  ✗ Installation failed: {e}")
        print("    Manual: https://dotnet.microsoft.com/download")
        return None


def ensure_dotnet() -> Path:
    """Ensure dotnet is available. Returns dotnet path or exits."""
    status, dotnet_bin, version = check_dotnet_status()

    if status == "ok":
        return dotnet_bin
    elif status == "outdated":
        print(f"⚠ dotnet {version} too old (need 6+), upgrading...")
        result = install_dotnet()
        if result:
            return result
        sys.exit(1)
    elif status == "broken":
        print("⚠ dotnet broken, reinstalling...")
        dotnet_dir = Path.home() / ".dotnet"
        if dotnet_dir.exists():
            shutil.rmtree(dotnet_dir, ignore_errors=True)
        result = install_dotnet()
        if result:
            return result
        sys.exit(1)
    else:  # missing
        print("○ dotnet not found, installing...")
        result = install_dotnet()
        if result:
            return result
        sys.exit(1)


def check_python_deps() -> dict:
    """Check Python dependencies. Returns status dict."""
    deps = {}

    # lxml (required)
    try:
        import lxml
        deps["lxml"] = ("ok", getattr(lxml, "__version__", "unknown"))
    except ImportError:
        deps["lxml"] = ("missing", None)

    # pandoc (optional)
    pandoc_path = shutil.which("pandoc")
    if pandoc_path:
        try:
            result = subprocess.run(
                ["pandoc", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            version = result.stdout.split("\n")[0].split()[-1] if result.returncode == 0 else "unknown"
            deps["pandoc"] = ("ok", version)
        except Exception:
            deps["pandoc"] = ("ok", "unknown")
    else:
        deps["pandoc"] = ("optional", None)

    # playwright (optional)
    try:
        import playwright
        deps["playwright"] = ("ok", None)
    except ImportError:
        deps["playwright"] = ("optional", None)

    # matplotlib (optional)
    try:
        import matplotlib
        deps["matplotlib"] = ("ok", None)
    except ImportError:
        deps["matplotlib"] = ("optional", None)

    return deps


def ensure_lxml():
    """Ensure lxml is installed."""
    try:
        import lxml
        return True
    except ImportError:
        print("○ lxml not found, installing...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "lxml"],
                check=True,
                capture_output=True
            )
            print("  ✓ lxml installed")
            return True
        except subprocess.CalledProcessError:
            print("  ✗ Failed to install lxml")
            print("    Manual: pip install lxml")
            return False


# ============================================================================
# Workspace management
# ============================================================================

def get_dotnet_major_version(dotnet_bin: Path) -> Optional[int]:
    """Get the major version of dotnet SDK."""
    try:
        result = subprocess.run(
            [str(dotnet_bin), "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            return int(version.split(".")[0])
    except Exception:
        pass
    return None


def fix_csproj_target_framework(csproj_path: Path, dotnet_bin: Path) -> bool:
    """
    Fix csproj TargetFramework to match installed dotnet version.
    Returns True if fixed.
    """
    major = get_dotnet_major_version(dotnet_bin)
    if not major or major < 6:
        return False

    try:
        content = csproj_path.read_text(encoding="utf-8")
        import re
        match = re.search(r"<TargetFramework>net(\d+)\.0</TargetFramework>", content)
        if match:
            current_major = int(match.group(1))
            if current_major != major:
                new_content = re.sub(
                    r"<TargetFramework>net\d+\.0</TargetFramework>",
                    f"<TargetFramework>net{major}.0</TargetFramework>",
                    content
                )
                csproj_path.write_text(new_content, encoding="utf-8")
                return True
    except Exception:
        pass
    return False


def ensure_workspace(dotnet_bin: Optional[Path] = None):
    """Ensure workspace directories and template files exist."""
    work_dir = get_work_dir()
    output_dir = get_output_dir()

    work_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Copy templates (don't overwrite existing files)
    templates_dir = SKILL_DIR / "templates"

    csproj_src = templates_dir / "DocxProject.csproj"
    csproj_dst = work_dir / "DocxProject.csproj"
    if not csproj_dst.exists() and csproj_src.exists():
        shutil.copy2(csproj_src, csproj_dst)

    entry_src = templates_dir / "DocxEntry.cs"
    entry_dst = work_dir / "DocxEntry.cs"
    if not entry_dst.exists() and entry_src.exists():
        shutil.copy2(entry_src, entry_dst)

    # Auto-fix csproj TargetFramework if dotnet version mismatch
    if dotnet_bin and csproj_dst.exists():
        if fix_csproj_target_framework(csproj_dst, dotnet_bin):
            major = get_dotnet_major_version(dotnet_bin)
            print(f"  (auto-fixed TargetFramework to net{major}.0)")


# ============================================================================
# Error enhancement
# ============================================================================

def enhance_error(line: str) -> Optional[str]:
    """Check if error line matches known patterns and return fix suggestion."""
    import re
    for pattern, fix in ERROR_MAP.items():
        if re.search(pattern, line):
            return f"  → FIX: {fix}"
    return None


# ============================================================================
# Validation
# ============================================================================

def do_validate(file_path: Path, dotnet_bin: Path) -> bool:
    """
    Run validation on a docx file.
    Returns True if valid, False otherwise.
    """
    # 1. Python validation (element order fix + business rules)
    check_all_script = SCRIPT_DIR / "check_all.py"
    try:
        result = subprocess.run(
            [sys.executable, str(check_all_script), str(file_path)],
            capture_output=True,
            text=True
        )
        print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        if result.returncode != 0:
            return False
    except Exception as e:
        print(f"Validation error: {e}")
        return False

    # 2. OpenXML validation (DocxChecker.dll)
    # Use --roll-forward LatestMajor to allow newer .NET versions to run older DLLs
    checker_dll = SKILL_DIR / "docxchecker" / "DocxChecker.dll"
    if checker_dll.exists():
        try:
            result = subprocess.run(
                [str(dotnet_bin), "--roll-forward", "LatestMajor", str(checker_dll), str(file_path)],
                capture_output=True,
                text=True
            )
            print(result.stdout, end="")
            if result.stderr:
                print(result.stderr, end="", file=sys.stderr)
            if result.returncode != 0:
                return False
        except Exception as e:
            print(f"OpenXML validation error: {e}")
            return False

    return True


def get_doc_statistics(file_path: Path) -> dict:
    """Get document statistics using pandoc if available."""
    stats = {"chars": 0, "words": 0, "images": 0, "has_revisions": False, "has_comments": False}

    # Check for pandoc
    if not shutil.which("pandoc"):
        return stats

    try:
        # Get text content
        result = subprocess.run(
            ["pandoc", str(file_path), "-t", "plain"],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            text = result.stdout
            stats["chars"] = len(text)
            stats["words"] = len(text.split())

        # Count images and check for revisions/comments
        with zipfile.ZipFile(file_path, 'r') as zf:
            file_list = zf.namelist()
            stats["images"] = sum(1 for f in file_list if f.startswith("word/media/"))
            stats["has_comments"] = "word/comments.xml" in file_list

            # Check for revisions
            if "word/document.xml" in file_list:
                doc_content = zf.read("word/document.xml").decode("utf-8", errors="ignore")
                stats["has_revisions"] = "<w:ins" in doc_content or "<w:del" in doc_content

    except Exception:
        pass

    return stats


# ============================================================================
# Commands
# ============================================================================

def cmd_env():
    """Show environment status."""
    print("=== Paths ===")
    print(f"  Skill dir:     {SKILL_DIR}")
    print(f"  Workspace dir: {get_workspace_dir()}")
    print(f"  Work dir:      {get_work_dir()}")
    print(f"  Output dir:    {get_output_dir()}")
    print()

    print("=== Dependencies ===")

    # dotnet
    status, dotnet_bin, version = check_dotnet_status()
    if status == "ok":
        print(f"✓ dotnet {version}")
    elif status == "outdated":
        print(f"⚠ dotnet {version} (outdated, need 6+)")
    elif status == "broken":
        print("✗ dotnet broken")
    else:
        print("○ dotnet not installed")

    # Python
    print(f"✓ python3 {platform.python_version()}")

    # Python deps
    deps = check_python_deps()
    for name, (status, version) in deps.items():
        if status == "ok":
            ver_str = f" {version}" if version else ""
            print(f"✓ {name}{ver_str}")
        elif status == "missing":
            print(f"✗ {name} not installed (required)")
        else:
            print(f"○ {name} (optional)")

    print()
    print("=== Workspace ===")
    work_dir = get_work_dir()
    if work_dir.exists():
        print(f"✓ {work_dir}")
        entry_file = work_dir / "DocxEntry.cs"
        if entry_file.exists():
            print("  DocxEntry.cs exists")
    else:
        print(f"○ {work_dir} (run 'oxml.py init')")


def cmd_init():
    """Initialize environment and workspace."""
    print("=== Checking dependencies ===")
    dotnet_bin = ensure_dotnet()
    print(f"✓ dotnet {subprocess.run([str(dotnet_bin), '--version'], capture_output=True, text=True).stdout.strip()}")
    print(f"✓ python3 {platform.python_version()}")

    if not ensure_lxml():
        sys.exit(1)

    print()
    print("=== Setting up workspace ===")
    ensure_workspace(dotnet_bin)
    print(f"✓ {get_work_dir()}")

    print()
    print("Done!")
    print(f"  Edit:   {get_work_dir() / 'DocxEntry.cs'}")
    print(f"  Build:  python {Path(__file__).name} build")
    print(f"  Output: {get_output_dir()}/")


def cmd_build(output_path: Optional[str] = None):
    """Build and validate docx."""
    dotnet_bin = ensure_dotnet()
    if not ensure_lxml():
        sys.exit(1)
    ensure_workspace(dotnet_bin)

    work_dir = get_work_dir()
    output_dir = get_output_dir()

    if output_path:
        output_file = Path(output_path)
        if not output_file.is_absolute():
            output_file = output_dir / output_path
    else:
        output_file = output_dir / "output.docx"

    # Ensure output directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)

    print("▶ Compiling...")
    csproj = work_dir / "DocxProject.csproj"
    result = subprocess.run(
        [str(dotnet_bin), "build", str(csproj), "--verbosity", "quiet"],
        capture_output=True,
        text=True,
        cwd=str(work_dir)
    )

    if result.returncode != 0:
        print("❌ Compile failed")
        print()
        for line in result.stdout.split("\n") + result.stderr.split("\n"):
            if "error CS" in line:
                print(f"  {line}")
                fix = enhance_error(line)
                if fix:
                    print(fix)
        sys.exit(1)
    print("  ✓ Compiled")

    print("▶ Running...")
    result = subprocess.run(
        [str(dotnet_bin), "run", "--no-build", "--", str(output_file)],
        capture_output=True,
        text=True,
        cwd=str(work_dir)
    )

    if result.returncode != 0:
        print("❌ Generation failed")
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        sys.exit(1)

    if not output_file.exists():
        print(f"❌ Output not found: {output_file}")
        print("  Check your DocxEntry.cs output path")
        sys.exit(1)
    print("  ✓ Generated")

    # Mandatory validation
    print("▶ Validating...")
    if not do_validate(output_file, dotnet_bin):
        print()
        print("⚠️  VALIDATION FAILED - Document saved but may have issues")
        print("━" * 58)
        print(f"Document saved to: {output_file}")
        print("However, due to the errors above, it may not open correctly in Word/WPS.")
        print()
        print("Common causes:")
        print("  • If editing an existing document: the original file may be non-standard")
        print("  • If creating from scratch: check the error messages and fix your code")
        print("━" * 58)
        sys.exit(1)

    # Statistics
    stats = get_doc_statistics(output_file)
    if stats["chars"] > 0:
        if stats["images"] == 0:
            print(f"  ⚠️  {stats['chars']} chars, {stats['words']} words, 0 images - verify AddInlineImage() was called")
        else:
            print(f"  📊 {stats['chars']} chars, {stats['words']} words, {stats['images']} images")
        print(f"  💡 Structure validated. Now verify CONTENT with: pandoc \"{output_file}\" -t plain")
        if stats["has_revisions"] or stats["has_comments"]:
            print("     Revisions/comments detected - use --track-changes=all to verify marker positions")

    print()
    print(f"✓ Done: {output_file}")


def cmd_validate(file_path: str):
    """Validate existing docx file."""
    dotnet_bin = ensure_dotnet()
    if not ensure_lxml():
        sys.exit(1)

    file_path = Path(file_path)
    if not file_path.exists():
        print(f"✗ File not found: {file_path}")
        sys.exit(1)

    print(f"▶ Validating: {file_path}")
    if do_validate(file_path, dotnet_bin):
        print("✓ Valid")
    else:
        sys.exit(1)


def print_help():
    """Print usage help."""
    work_dir = get_work_dir()
    output_dir = get_output_dir()

    help_text = f"""
Usage: python oxml.py <command> [args]

Commands:
  env           Show environment status (no changes)
  init          Setup dependencies + workspace
  build [out]   Compile, run, validate (default: output/output.docx)
  validate FILE Validate existing docx

Dynamic Paths:
  Skill dir:    {SKILL_DIR}
  Workspace:    {work_dir}  (edit DocxEntry.cs here)
  Output:       {output_dir}  (final deliverables)

Create Workflow:
  1. python oxml.py init
  2. Edit {work_dir / 'DocxEntry.cs'}
  3. python oxml.py build report.docx

Edit Workflow:
  1. Examine uploaded .docx structure (unzip and read XML)
  2. Edit {work_dir / 'DocxEntry.cs'}
  3. python oxml.py build edited.docx
"""
    print(help_text.strip())


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print_help()
        sys.exit(0)

    command = sys.argv[1]

    if command == "env":
        cmd_env()
    elif command == "init":
        cmd_init()
    elif command == "build":
        output = sys.argv[2] if len(sys.argv) > 2 else None
        cmd_build(output)
    elif command == "validate":
        if len(sys.argv) < 3:
            print("Usage: python oxml.py validate <file.docx>")
            sys.exit(1)
        cmd_validate(sys.argv[2])
    else:
        print(f"Unknown command: {command}")
        print("Run 'python oxml.py help' for usage")
        sys.exit(1)


if __name__ == "__main__":
    main()

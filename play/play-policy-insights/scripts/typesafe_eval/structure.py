# Copyright 2026 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Structure layer: deterministic, language-agnostic code structure extraction.

This module is the *structure* half of the "structure is deterministic,
semantics are model-inferred" split described in
``docs/capability-based-evaluation.md``. It never decides what a library *does*
(that is the semantic layer, ``capabilities.py``); it only answers questions a
parser can answer without judgment:

- **Dependency inventory** — which third-party artifacts does the project
  declare? Parsed from Gradle (Groovy/Kotlin DSL), Gradle version catalogs,
  Maven, npm, and pub manifests into ``(ecosystem, coordinate)`` pairs.
- **Import inventory** — which modules/symbols does a source file import?
  Parsed for Java, Kotlin, Dart, JavaScript/TypeScript, C#, and Python.
- **Symbol references** — on which lines is each imported simple name used?
- **All occurrences** of a scanner pattern (not just the first — the first hit is
  frequently a comment, import, or doc string).
- **Enclosing scope** — the function/method body around a hit, found by brace
  depth (or indentation for Python), with a fixed-window fallback.
- **Sink proximity** — the line distance between a data-type hit and the nearest
  reference to a symbol the semantic layer labelled as a transfer sink.

Everything here is pure: it reads files under ``app_dir`` and returns plain
dicts/lists. No network, no model, no writes. It is intentionally regex-based
rather than a real parser so it stays standard-library-only and degrades
gracefully on unusual syntax (every extractor has a documented fallback).

Nothing in this module names a specific library, vendor, or framework; see the
identifier lint in ``selftest.py``.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import re
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence
from typing import Tuple

log = logging.getLogger("typesafe_eval.structure")

# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

_EXT_LANGUAGE = {
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".dart": "dart",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".cs": "csharp",
    ".py": "python",
    ".swift": "swift",
    ".xml": "xml",
}

# Directories that never contain first-party source worth inspecting.
IGNORED_DIR_NAMES = frozenset({
    ".git", ".gradle", ".idea", "build", "node_modules", ".dart_tool",
    "__pycache__", ".scratch", "out", "dist",
})


def language_of(relpath: str) -> str:
  """Best-effort language from the file extension (``"unknown"`` otherwise)."""
  _, ext = os.path.splitext(relpath.lower())
  return _EXT_LANGUAGE.get(ext, "unknown")


# ---------------------------------------------------------------------------
# Dependency inventory
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Dependency:
  """One declared third-party artifact.

  Attributes:
    ecosystem: ``"maven"``, ``"npm"``, or ``"pub"``.
    coordinate: ``group:artifact`` (maven), package name (npm/pub). Versions are
      deliberately dropped: capability is a property of the artifact, not the
      version, and dropping it keeps the capability cache hit rate high.
    source_file: The manifest the dependency was read from (relative path).
  """

  ecosystem: str
  coordinate: str
  source_file: str


# Gradle: implementation("group:artifact:version"), api 'g:a:v', etc.
_GRADLE_DEP_RE = re.compile(
    r"""\b(?:implementation|api|compileOnly|runtimeOnly|kapt|ksp|
          annotationProcessor|testImplementation|androidTestImplementation|
          debugImplementation|releaseImplementation)\s*\(?\s*
        ["'](?P<group>[A-Za-z0-9_.\-]+):(?P<artifact>[A-Za-z0-9_.\-]+)(?::[^"']*)?["']""",
    re.VERBOSE,
)
# Gradle Kotlin DSL map form: implementation(group = "g", name = "a", version = "v")
_GRADLE_MAP_RE = re.compile(
    r"""group\s*[=:]\s*["'](?P<group>[A-Za-z0-9_.\-]+)["']\s*,\s*
        name\s*[=:]\s*["'](?P<artifact>[A-Za-z0-9_.\-]+)["']""",
    re.VERBOSE,
)
# Version catalog (libs.versions.toml) library entries.
_TOML_MODULE_RE = re.compile(
    r"""^\s*[A-Za-z0-9_\-]+\s*=\s*\{[^}]*module\s*=\s*
        ["'](?P<group>[A-Za-z0-9_.\-]+):(?P<artifact>[A-Za-z0-9_.\-]+)["']""",
    re.VERBOSE | re.MULTILINE,
)
_TOML_GROUP_NAME_RE = re.compile(
    r"""^\s*[A-Za-z0-9_\-]+\s*=\s*\{[^}]*group\s*=\s*["'](?P<group>[A-Za-z0-9_.\-]+)["']
        [^}]*name\s*=\s*["'](?P<artifact>[A-Za-z0-9_.\-]+)["']""",
    re.VERBOSE | re.MULTILINE,
)
# Maven pom.xml <dependency><groupId>..</groupId><artifactId>..</artifactId>
_POM_DEP_RE = re.compile(
    r"<dependency>.*?<groupId>\s*(?P<group>[^<\s]+)\s*</groupId>.*?"
    r"<artifactId>\s*(?P<artifact>[^<\s]+)\s*</artifactId>.*?</dependency>",
    re.DOTALL,
)
# package.json "dependencies": { "name": "version", ... }
_PKG_JSON_SECTION_RE = re.compile(
    r'"(?:dependencies|devDependencies|peerDependencies)"\s*:\s*\{(?P<body>[^}]*)\}',
    re.DOTALL,
)
_PKG_JSON_NAME_RE = re.compile(r'"(?P<name>(?:@[A-Za-z0-9_.\-]+/)?[A-Za-z0-9_.\-]+)"\s*:')

_MANIFEST_FILENAMES = (
    "build.gradle", "build.gradle.kts", "libs.versions.toml", "pom.xml",
    "package.json", "pubspec.yaml",
)


def _iter_manifest_files(app_dir: str) -> Iterable[Tuple[str, str]]:
  """Yields ``(relpath, filename)`` for every dependency manifest under app_dir."""
  for root, dirs, files in os.walk(app_dir):
    dirs[:] = [d for d in dirs if d not in IGNORED_DIR_NAMES]
    for name in files:
      full = os.path.join(root, name)
      if name in _MANIFEST_FILENAMES or name.endswith(".versions.toml"):
        yield os.path.relpath(full, app_dir), name
      elif name.endswith(".toml") and os.path.basename(root) == "gradle":
        # Version catalogs may use any name (Gradle only requires the
        # ``[libraries]`` table); treat every toml under ``gradle/`` as one.
        if "[libraries]" in _read(full):
          yield os.path.relpath(full, app_dir), name


def _read(path: str) -> str:
  try:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
      return f.read()
  except OSError:
    return ""


def _parse_pubspec(content: str) -> List[str]:
  """Minimal YAML walk: package names listed under ``dependencies:`` blocks."""
  names: List[str] = []
  in_block = False
  for line in content.splitlines():
    if re.match(r"^(dependencies|dev_dependencies|dependency_overrides):\s*$", line):
      in_block = True
      continue
    if in_block:
      if line and not line.startswith((" ", "\t")):
        in_block = False
        continue
      m = re.match(r"^\s{2}(?P<name>[A-Za-z0-9_]+)\s*:", line)
      if m and m.group("name") not in ("flutter", "sdk"):
        names.append(m.group("name"))
  return names


def dependency_inventory(app_dir: str) -> List[Dependency]:
  """Parses every recognised manifest under ``app_dir`` into dependencies.

  Duplicates (the same coordinate declared in several modules) are collapsed;
  the first manifest seen is recorded as ``source_file``. Returns a sorted list
  so downstream batching and caching are deterministic.
  """
  seen: Dict[Tuple[str, str], Dependency] = {}

  def _add(ecosystem: str, coordinate: str, relpath: str) -> None:
    key = (ecosystem, coordinate)
    if key not in seen:
      seen[key] = Dependency(ecosystem, coordinate, relpath)

  for relpath, name in _iter_manifest_files(app_dir):
    content = _read(os.path.join(app_dir, relpath))
    if not content:
      continue
    if name.endswith((".gradle", ".gradle.kts")):
      for m in _GRADLE_DEP_RE.finditer(content):
        _add("maven", f"{m.group('group')}:{m.group('artifact')}", relpath)
      for m in _GRADLE_MAP_RE.finditer(content):
        _add("maven", f"{m.group('group')}:{m.group('artifact')}", relpath)
    elif name.endswith(".toml"):
      for m in _TOML_MODULE_RE.finditer(content):
        _add("maven", f"{m.group('group')}:{m.group('artifact')}", relpath)
      for m in _TOML_GROUP_NAME_RE.finditer(content):
        _add("maven", f"{m.group('group')}:{m.group('artifact')}", relpath)
    elif name == "pom.xml":
      for m in _POM_DEP_RE.finditer(content):
        _add("maven", f"{m.group('group')}:{m.group('artifact')}", relpath)
    elif name == "package.json":
      for section in _PKG_JSON_SECTION_RE.finditer(content):
        for m in _PKG_JSON_NAME_RE.finditer(section.group("body")):
          _add("npm", m.group("name"), relpath)
    elif name == "pubspec.yaml":
      for pkg in _parse_pubspec(content):
        _add("pub", pkg, relpath)

  deps = sorted(seen.values(), key=lambda d: (d.ecosystem, d.coordinate))
  log.info("dependency_inventory: %d artifacts from %s", len(deps), app_dir)
  return deps


# ---------------------------------------------------------------------------
# Import inventory and symbol references
# ---------------------------------------------------------------------------

_IMPORT_PATTERNS: Dict[str, re.Pattern] = {
    # import a.b.C; / import a.b.C as D / import a.b.*  (the wildcard is kept so
    # ``package_of`` sees ``a.b.*`` as belonging to package ``a.b``, not ``a``)
    "java": re.compile(r"^\s*import\s+(?:static\s+)?(?P<mod>[\w.]+?(?:\.\*)?)\s*;", re.M),
    "kotlin": re.compile(r"^\s*import\s+(?P<mod>[\w.]+?(?:\.\*)?)(?:\s+as\s+\w+)?\s*$", re.M),
    # import 'package:foo/bar.dart'; import 'dart:io';
    "dart": re.compile(r"^\s*import\s+['\"](?P<mod>[^'\"]+)['\"]", re.M),
    # import x from 'mod'; import 'mod'; require('mod')
    "javascript": re.compile(
        r"(?:^\s*import\s+(?:[^'\"]*?\s+from\s+)?['\"](?P<mod>[^'\"]+)['\"])"
        r"|(?:require\(\s*['\"](?P<mod2>[^'\"]+)['\"]\s*\))", re.M),
    "csharp": re.compile(r"^\s*using\s+(?:static\s+)?(?P<mod>[\w.]+)\s*;", re.M),
    "python": re.compile(
        r"(?:^\s*import\s+(?P<mod>[\w.]+))|(?:^\s*from\s+(?P<mod2>[\w.]+)\s+import)", re.M),
    "swift": re.compile(r"^\s*import\s+(?P<mod>[\w.]+)", re.M),
}
_IMPORT_PATTERNS["typescript"] = _IMPORT_PATTERNS["javascript"]


def import_inventory(content: str, language: str) -> List[str]:
  """Returns the distinct imported module paths in ``content`` for ``language``.

  Relative imports (``./x``, ``../x``) and the file's own package are
  first-party by construction and are skipped; the capability of first-party
  code is exactly what the finding battery evaluates from the snippet.
  """
  pattern = _IMPORT_PATTERNS.get(language)
  if pattern is None:
    return []
  mods: List[str] = []
  for m in pattern.finditer(content):
    mod = m.groupdict().get("mod") or m.groupdict().get("mod2")
    if not mod:
      continue
    if mod.startswith((".", "/")):
      continue
    if mod not in mods:
      mods.append(mod)
  return mods


def package_of(module_path: str) -> str:
  """The containing package/library of an import, for coarse classification.

  ``a.b.C`` -> ``a.b``; ``package:foo/bar.dart`` -> ``package:foo``;
  ``@scope/pkg/sub`` -> ``@scope/pkg``; ``pkg/sub`` -> ``pkg``; ``dart:io`` ->
  ``dart:io``. A bare single-segment import is its own package.

  The semantic layer classifies packages first (few, highly cacheable) and only
  refines to class level inside packages that look transfer-capable, which cuts
  classification volume by roughly two thirds on real apps.
  """
  mod = module_path.strip()
  if mod.startswith("package:"):
    rest = mod[len("package:"):]
    return "package:" + rest.split("/", 1)[0]
  if ":" in mod and "/" not in mod and "." not in mod.split(":", 1)[1]:
    return mod  # e.g. dart:io
  if "/" in mod:
    parts = mod.split("/")
    if mod.startswith("@") and len(parts) >= 2:
      return "/".join(parts[:2])
    return parts[0]
  if "." in mod:
    return mod.rsplit(".", 1)[0]
  return mod


_PACKAGE_DECL_RE = re.compile(r"^\s*(?:package|namespace)\s+(?P<pkg>[\w.]+)\s*;?\s*$", re.M)


def declared_package(content: str) -> str:
  """The file's own ``package``/``namespace`` declaration, or ``""``.

  Used to recognise first-party imports without trusting the manifest alone:
  an import whose package is declared by any analysed source file is the app's
  own code, whose behaviour the finding battery judges from the snippet rather
  than from the semantic layer.
  """
  m = _PACKAGE_DECL_RE.search(content)
  return m.group("pkg") if m else ""


def simple_name(module_path: str) -> str:
  """The last path segment of an import (``a.b.C`` -> ``C``; ``pkg/x.dart`` -> ``x``)."""
  seg = re.split(r"[./:]", module_path.rstrip("/"))
  seg = [s for s in seg if s]
  if not seg:
    return module_path
  last = seg[-1]
  return re.sub(r"\.(dart|js|ts)$", "", last)


def symbol_references(
    lines: Sequence[str], imports: Sequence[str], max_lines_per_symbol: int = 12
) -> Dict[str, List[int]]:
  """Maps each import to the 0-based line indices where its simple name is used.

  Import lines and comment-only lines are excluded (a symbol mentioned in a doc
  comment is not a call site). Matching is whole-word so ``Log`` does not match
  ``Logger``. Kotlin/Java wildcard imports have no usable simple name and are
  skipped (their package path is still classified by the semantic layer).
  """
  refs: Dict[str, List[int]] = {}
  for mod in imports:
    name = simple_name(mod)
    if not name or name == "*" or not re.match(r"^\w+$", name):
      continue
    word = re.compile(r"(?<![\w.])" + re.escape(name) + r"(?!\w)")
    hits: List[int] = []
    for i, line in enumerate(lines):
      stripped = line.lstrip()
      if stripped.startswith(_IMPORT_PREFIXES) or stripped.startswith(_COMMENT_PREFIXES):
        continue
      if word.search(line):
        hits.append(i)
        if len(hits) >= max_lines_per_symbol:
          break
    if hits:
      refs[mod] = hits
  return refs


# ---------------------------------------------------------------------------
# Occurrences and enclosing scope
# ---------------------------------------------------------------------------


_COMMENT_PREFIXES = ("//", "*", "/*", "#", "<!--")
_IMPORT_PREFIXES = ("import ", "using ", "from ", "package ")


def all_occurrences(lines: Sequence[str], pattern: str, cap: int = 5) -> List[int]:
  """0-based indices of every line containing ``pattern``, up to ``cap``.

  Comment-only and import lines are demoted (kept only if nothing else matches)
  because the first mention of an API in a file is very often its import or its
  documentation, neither of which is where data flows.
  """
  if not pattern:
    return []
  code_hits: List[int] = []
  demoted_hits: List[int] = []
  for i, line in enumerate(lines):
    if pattern in line:
      stripped = line.lstrip()
      if stripped.startswith(_COMMENT_PREFIXES) or stripped.startswith(_IMPORT_PREFIXES):
        demoted_hits.append(i)
      else:
        code_hits.append(i)
  hits = code_hits or demoted_hits
  return hits[:cap]


_DECL_HINT_RE = re.compile(
    r"\b(fun|def|void|public|private|protected|internal|static|override|suspend|"
    r"func|function|async|constructor|init|get|set|class|object|interface)\b"
    r"|=>\s*\{?\s*$|\)\s*(?::\s*[\w<>\[\]?., ]+)?\s*\{?\s*$"
)


def _depth_profile(lines: Sequence[str]) -> List[int]:
  """Brace depth *before* each line, ignoring braces in strings and comments.

  Approximate: handles ``//`` line comments, ``/* */`` block comments and
  simple string literals. Good enough for locating method bodies; exotic
  syntax falls through to the window fallback.
  """
  depth = 0
  profile: List[int] = []
  in_block_comment = False
  for line in lines:
    profile.append(depth)
    i = 0
    in_str: Optional[str] = None
    while i < len(line):
      ch = line[i]
      nxt = line[i + 1] if i + 1 < len(line) else ""
      if in_block_comment:
        if ch == "*" and nxt == "/":
          in_block_comment = False
          i += 2
          continue
        i += 1
        continue
      if in_str:
        if ch == "\\":
          i += 2
          continue
        if ch == in_str:
          in_str = None
        i += 1
        continue
      if ch == "/" and nxt == "/":
        break
      if ch == "/" and nxt == "*":
        in_block_comment = True
        i += 2
        continue
      if ch in ("'", '"'):
        in_str = ch
      elif ch == "{":
        depth += 1
      elif ch == "}":
        depth = max(0, depth - 1)
      i += 1
  profile.append(depth)
  return profile


def enclosing_scope(
    lines: Sequence[str],
    index: int,
    language: str = "unknown",
    max_lines: int = 80,
    fallback_context: int = 6,
) -> Tuple[int, int]:
  """Returns ``(start, end)`` 0-based, end-exclusive, of the scope around ``index``.

  Strategy:
    1. Python: walk back to the nearest ``def``/``class`` at lower indentation
       and forward while indentation stays deeper.
    2. Brace languages: walk back through the brace-depth profile to the
       innermost opener whose header line looks like a declaration; walk
       forward to the matching close.
    3. Fallback (no structure found, or the scope exceeds ``max_lines``): a
       window of ``fallback_context`` lines each side, widened to include the
       hit and clipped to ``max_lines``.

  The result always contains ``index``.
  """
  n = len(lines)
  if n == 0:
    return 0, 0
  index = max(0, min(index, n - 1))

  if language == "python":
    return _python_scope(lines, index, max_lines, fallback_context)

  profile = _depth_profile(lines)
  target_depth = profile[index]
  # Walk back for an opener that reduces depth below the hit's depth.
  start = None
  depth_wanted = target_depth
  i = index
  while i >= 0 and depth_wanted > 0:
    if profile[i] < depth_wanted:
      # Line i opens a block enclosing the hit. Is it a declaration?
      header = lines[i]
      if _DECL_HINT_RE.search(header) and "(" in header:
        start = i
        break
      # A bare "{" on its own line: the header is the previous line.
      if header.strip() == "{" and i > 0 and _DECL_HINT_RE.search(lines[i - 1]):
        start = i - 1
        break
      depth_wanted = profile[i]
    i -= 1

  if start is not None:
    open_depth = profile[start]
    # ``profile[i]`` is the depth *before* line i, so the closing-brace line
    # (depth still > open_depth before it closes) is included and the loop
    # stops on the first line at the header's depth.
    end = index + 1
    while end < n and profile[end] > open_depth:
      end += 1
    if end - start <= max_lines:
      return start, end
    # Too long: keep the header plus a window around the hit inside the scope.
    half = max_lines // 2
    ws = max(start, index - half)
    we = min(end, ws + max_lines)
    return ws, we

  s = max(0, index - fallback_context)
  e = min(n, index + fallback_context + 1)
  return s, e


def _python_scope(lines, index, max_lines, fallback_context) -> Tuple[int, int]:
  def indent(s: str) -> int:
    return len(s) - len(s.lstrip(" \t"))

  hit_indent = indent(lines[index])
  start = None
  for i in range(index, -1, -1):
    stripped = lines[i].lstrip()
    if stripped.startswith(("def ", "async def ", "class ")) and indent(lines[i]) < hit_indent:
      start = i
      break
  if start is None:
    s = max(0, index - fallback_context)
    return s, min(len(lines), index + fallback_context + 1)
  base = indent(lines[start])
  end = index + 1
  while end < len(lines):
    if lines[end].strip() and indent(lines[end]) <= base:
      break
    end += 1
  if end - start > max_lines:
    half = max_lines // 2
    ws = max(start, index - half)
    return ws, min(end, ws + max_lines)
  return start, end


def render_lines(lines: Sequence[str], indices: Iterable[int]) -> str:
  """Renders ``Lnn: source`` for sorted ``indices``, marking gaps with ``...``."""
  out: List[str] = []
  prev: Optional[int] = None
  for i in sorted(set(indices)):
    if i < 0 or i >= len(lines):
      continue
    if prev is not None and i > prev + 1:
      out.append("    ...")
    out.append(f"L{i + 1}: {lines[i]}")
    prev = i
  return "\n".join(out)


# ---------------------------------------------------------------------------
# Sink proximity
# ---------------------------------------------------------------------------


def sink_proximity(hit_lines: Sequence[int], sink_lines: Sequence[int]) -> Optional[int]:
  """Smallest ``|hit - sink|`` line distance, or None when either side is empty.

  Used to *rank* candidates for the model (closer is more likely to be the real
  data flow), never to decide anything on its own.
  """
  if not hit_lines or not sink_lines:
    return None
  return min(abs(h - s) for h in hit_lines for s in sink_lines)


@dataclasses.dataclass
class FileStructure:
  """Everything the structure layer knows about one source file."""

  relpath: str
  language: str
  lines: List[str]
  imports: List[str]
  references: Dict[str, List[int]]
  package: str = ""

  @property
  def line_count(self) -> int:
    return len(self.lines)


def analyze_file(app_dir: str, relpath: str) -> FileStructure:
  """Reads and structurally indexes one file (imports + symbol references)."""
  content = _read(os.path.join(app_dir, relpath))
  language = language_of(relpath)
  lines = content.splitlines()
  imports = import_inventory(content, language)
  refs = symbol_references(lines, imports)
  package = declared_package(content) if language in ("java", "kotlin", "csharp") else ""
  log.debug("analyze_file %s: lang=%s lines=%d imports=%d referenced=%d package=%s",
            relpath, language, len(lines), len(imports), len(refs), package)
  return FileStructure(relpath, language, lines, imports, refs, package)

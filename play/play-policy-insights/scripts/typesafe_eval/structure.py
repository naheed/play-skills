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
- **First-party class index and callee references** (WP6) — which of the app's
  own class files does a capitalised identifier in a caller refer to, and on
  which lines is it referenced? Resolution uses the caller's imports and
  package, never the class's behaviour.
- **Destination hints** (WP7) — does a scope read its host/URL from a
  preference or UI field, hand data to a system chooser, or name a literal
  endpoint (under the developer's own domain or not)? Priors for the
  ``destination_class`` question, never decisions.

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
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence
from typing import Tuple

from typesafe_eval import constants

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
    lines: Sequence[str], imports: Sequence[str], max_lines_per_symbol: Optional[int] = None
) -> Dict[str, List[int]]:
  """Maps each import to the 0-based line indices where its simple name is used.

  Import lines and comment-only lines are excluded (a symbol mentioned in a doc
  comment is not a call site). Matching is whole-word so ``Log`` does not match
  ``Logger``. Kotlin/Java wildcard imports have no usable simple name and are
  skipped (their package path is still classified by the semantic layer).

  ``max_lines_per_symbol`` defaults to ``constants.MAX_SYMBOL_REFERENCE_LINES``
  (a generous bound). Ranking needs *every* call site of a sink symbol: with the
  old default of 12 a file using ``Intent`` fourteen times had its last two
  ``startActivity`` sites hidden from scope/proximity ranking. The model-facing
  lists are bounded separately in :mod:`context`.
  """
  if max_lines_per_symbol is None:
    max_lines_per_symbol = constants.MAX_SYMBOL_REFERENCE_LINES
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


def all_occurrences(lines: Sequence[str], pattern: str, cap: int = 5,
                    prefer_boundary: bool = True) -> List[int]:
  """0-based indices of every line containing ``pattern``, up to ``cap``.

  Comment-only and import lines are demoted (kept only if nothing else matches)
  because the first mention of an API in a file is very often its import or its
  documentation, neither of which is where data flows.

  With ``prefer_boundary`` (WP2) and an identifier-shaped pattern, lines where
  the pattern sits at an *identifier boundary* in a value position rank first,
  then boundary hits in a type position, then raw substring hits, then the
  demoted lines. This makes the anchor land on ``audio_record`` rather than
  ``recorder`` when both exist, without changing which lines are eligible.
  """
  if not pattern:
    return []
  if prefer_boundary and is_identifier_pattern(pattern):
    lex = lexical_hits(lines, pattern)
    ordered = lex.ranked_lines()
    if ordered:
      return ordered[:cap]
    return lex.demoted_lines[:cap]
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


# ---------------------------------------------------------------------------
# Identifier-boundary lexical pre-gate (WP2, lesson L1)
# ---------------------------------------------------------------------------
#
# Scanner patterns are matched as raw substrings, so ``record`` fires on
# ``recorder``/``LogRecord``, ``dob`` on a Croatian verb stem, ``race`` on
# ``grace``, ``imap`` on ``HashMultimap``. Each of those used to cost a model
# call before the relevance gate dismissed it. The helpers below decide, with no
# policy knowledge, whether a pattern occurs as an identifier *word* -- at a
# camelCase / snake_case / kebab-case / dot boundary on both sides -- and
# whether that word sits in a *type* position (class header, generic argument,
# declared type, supertype) rather than a *value* position (call, field,
# parameter, constructor). Only identifier-shaped patterns are subject to this;
# MIME types (``audio/*``) and other punctuation-bearing patterns keep raw
# substring semantics because they are not identifiers.

_IDENTIFIER_PATTERN_RE = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$")
_IDENT_CHARS_RE = re.compile(r"[\w.]")

# English derivational affixes glued to a word in lower case are still *that
# word* for the scanner's purpose: ``recorder``, ``recording``, ``tracker``,
# ``logins``, ``relogin`` all name the concept ``record`` / ``track`` / ``login``.
# A foreign stem (``dobiti``, ``gráfico``) or an unrelated container word
# (``HashMultimap`` for ``imap``, ``grace`` for ``race``) does not carry one of
# these affixes and is rejected. Deliberately short lists: every entry widens
# what survives to the (model) relevance gate, never what is dropped.
_ENGLISH_SUFFIXES = ("s", "es", "ed", "er", "ers", "or", "ors", "ing", "ings", "ion", "ions", "able", "y")
_ENGLISH_PREFIXES = ("re", "un", "pre", "de", "auto", "non", "sub", "mis", "multi", "co")

# Keywords that make the *following* identifier a type. Language-agnostic
# superset for Kotlin / Java / Dart / Swift / TypeScript / C#. ``new`` is
# absent on purpose: ``new Foo(`` creates a value.
_TYPE_LEADING_KEYWORDS = (
    "class", "interface", "object", "enum", "typealias", "extends", "implements",
    "instanceof", "is", "as", "throws", "struct", "protocol", "typedef",
)
_TYPE_LEADING_RE = re.compile(
    r"(?:^|[\s(<,])(" + "|".join(_TYPE_LEADING_KEYWORDS) + r")\s*$")
# Java/C#/Dart-style declaration: ``Type name =``, ``Type name;``, ``Type name)``,
# ``Type name,``, ``Type name(`` (method return type) -- after optional generics/array.
_DECLARED_TYPE_TAIL_RE = re.compile(r"^(?:<[^<>]*(?:<[^<>]*>[^<>]*)*>)?(?:\[\])*\s+[A-Za-z_]\w*\s*[=;,)(:{]")
_DECL_MODIFIERS = (
    "public", "private", "protected", "static", "final", "val", "var", "override",
    "internal", "lateinit", "const", "readonly", "abstract", "synchronized", "volatile",
    "transient", "native", "default", "late", "open", "inline", "suspend", "external",
)


@dataclasses.dataclass
class LexicalHits:
  """Per-file classification of where an identifier pattern occurs.

  Attributes:
    value_lines: Boundary hits in a value position (call, field, argument,
      constructor, parameter name...). A pattern with at least one of these
      is a genuine identifier use and always survives the pre-gate.
    type_lines: Boundary hits that occur only in type positions on their line
      (class header, generic argument, declared type, supertype, ``is``/``as``).
    substring_lines: Lines where the pattern occurs only *inside* a longer
      identifier word (``recorder``, ``dobiti``, ``HashMultimap``).
    demoted_lines: Comment-only and import lines containing the pattern.
    examples: ``line_index -> stripped line`` for one representative of each
      non-empty class, for the triage record.
  """

  value_lines: List[int] = dataclasses.field(default_factory=list)
  type_lines: List[int] = dataclasses.field(default_factory=list)
  substring_lines: List[int] = dataclasses.field(default_factory=list)
  demoted_lines: List[int] = dataclasses.field(default_factory=list)
  examples: Dict[str, str] = dataclasses.field(default_factory=dict)
  # Subset of ``value_lines`` where the scanner's exact spelling occurs (as
  # opposed to the capitalised camelCase variant). Preferred as anchors.
  exact_value_lines: List[int] = dataclasses.field(default_factory=list)

  def ranked_lines(self) -> List[int]:
    """Anchor preference order: exact value, variant value, type, substring."""
    ordered = list(self.exact_value_lines)
    ordered += [l for l in self.value_lines if l not in ordered]
    ordered += [l for l in self.type_lines if l not in ordered]
    ordered += [l for l in self.substring_lines if l not in ordered]
    return ordered

  @property
  def verdict(self) -> str:
    """``value`` / ``type_only`` / ``substring_only`` / ``demoted_only`` / ``none``."""
    if self.value_lines:
      return "value"
    if self.type_lines:
      return "type_only"
    if self.substring_lines:
      return "substring_only"
    if self.demoted_lines:
      return "demoted_only"
    return "none"


def is_identifier_pattern(pattern: str) -> bool:
  """True for ``record``, ``full_name``, ``getDeviceId``, ``MediaStore.Images``."""
  return bool(pattern) and bool(_IDENTIFIER_PATTERN_RE.match(pattern))


def _word_run_before(line: str, start: int) -> str:
  """The camelCase word immediately preceding ``start``, lower-cased.

  Walks back over lower-case letters and includes the single upper-case
  letter that opens the word, so ``Relogin`` -> ``re`` and ``autoLogin`` is
  not reached here (that is a camel boundary already).
  """
  lo = start
  while lo > 0 and line[lo - 1].islower():
    lo -= 1
  if lo > 0 and line[lo - 1].isupper():
    lo -= 1
  return line[lo:start].lower()


def _word_run_after(line: str, end: int) -> str:
  """Lower-case letters immediately following ``end`` up to the next boundary."""
  hi = end
  while hi < len(line) and line[hi].islower():
    hi += 1
  return line[end:hi]


def _starts_at_boundary(line: str, start: int, token: str) -> bool:
  if start == 0:
    return True
  prev = line[start - 1]
  if not prev.isalnum():
    return True                      # ``_``, ``-``, ``.``, space, punctuation
  first = token[0]
  if first.isupper() and (prev.islower() or prev.isdigit()):
    return True                      # camelCase: ``audioRecord``, ``LogRecord``
  if prev.isdigit():
    return True                      # ``v2record`` -- digit/letter transition
  if prev.islower() and first.islower():
    # ``relogin`` / ``autoupdate``: an English prefix glued to the word is
    # still the word; ``gráfico`` / ``dobiti`` are not.
    run = _word_run_before(line, start)
    return run in _ENGLISH_PREFIXES
  return False


def _ends_at_boundary(line: str, end: int, token: str) -> bool:
  if end >= len(line):
    return True
  nxt = line[end]
  if not nxt.isalnum():
    return True                      # ``_``, ``-``, ``.``, ``(``, space...
  if nxt.isupper() or nxt.isdigit():
    return True                      # camelCase continuation: ``recordAudio``, ``uid2``
  # ``recorder`` / ``Recording`` / ``logins``: an English suffix keeps the word;
  # ``dobiti`` / ``Tracke`` (nonsense) do not.
  run = _word_run_after(line, end)
  return run in _ENGLISH_SUFFIXES


def boundary_matches(line: str, pattern: str) -> List[Tuple[int, bool]]:
  """``(start_column, exact_case)`` for every identifier-word occurrence on ``line``.

  Matches the exact pattern, and -- when the pattern is all lower-case -- its
  capitalised form at a camelCase boundary (``record`` also matches the
  ``Record`` word in ``AudioRecord`` / ``startRecord``), because the scanner's
  lower-case pattern names the *word*, not one spelling of it. ``exact_case``
  is False for the capitalised variant so callers can prefer the spelling the
  scanner actually matched when ranking anchors.
  """
  variants = [(pattern, True)]
  if pattern.islower() and pattern[0].isalpha():
    variants.append((pattern[0].upper() + pattern[1:], False))
  found: Dict[int, bool] = {}
  for variant, exact in variants:
    start = line.find(variant)
    while start != -1:
      end = start + len(variant)
      if _starts_at_boundary(line, start, variant) and _ends_at_boundary(line, end, variant):
        found[start] = found.get(start, False) or exact
      start = line.find(variant, start + 1)
  return sorted(found.items())


def boundary_columns(line: str, pattern: str) -> List[int]:
  """Start columns where ``pattern`` occurs as an identifier word on ``line``."""
  return [c for c, _ in boundary_matches(line, pattern)]


def _enclosing_identifier(line: str, col: int, length: int) -> Tuple[int, int]:
  """Span of the whole ``[\\w.]`` identifier chain containing ``line[col:col+length]``."""
  lo = col
  while lo > 0 and _IDENT_CHARS_RE.match(line[lo - 1]):
    lo -= 1
  hi = col + length
  while hi < len(line) and _IDENT_CHARS_RE.match(line[hi]):
    hi += 1
  return lo, hi


def is_type_position(line: str, col: int, length: int) -> bool:
  """True when the identifier containing ``line[col:col+length]`` names a type.

  Positions treated as *type*:

  - preceded by a declaration / relation keyword: ``class``, ``interface``,
    ``object``, ``enum``, ``typealias``, ``extends``, ``implements``,
    ``instanceof``, ``is``, ``as``, ``throws`` ...
  - a Kotlin/Swift/TypeScript type annotation or supertype: ``: Type``
  - a generic argument: ``<Type>``, ``Map<String, Type>``
  - an annotation: ``@Type``
  - a Java/C#/Dart declared type followed by a name: ``Type name =``,
    ``Type name;``, ``Type name)``, ``Type name(``

  ``new Type(...)`` and every other position is a *value* use. A line is
  never judged as a whole: a declaration line ``AudioRecord r = new AudioRecord()``
  has one type-position hit and one value-position hit.
  """
  lo, hi = _enclosing_identifier(line, col, length)
  before = line[:lo].rstrip()
  after = line[hi:]
  if before.endswith("@"):
    return True
  if _TYPE_LEADING_RE.search(before):
    return True
  if before.endswith(":") and not before.endswith("::"):
    return True
  if before.endswith("<"):
    return True
  if before.endswith(",") and before.count("<") > before.count(">"):
    return True
  if _DECLARED_TYPE_TAIL_RE.match(after):
    # ``Type name = ...`` / ``Type name;`` / ``Type method(`` / ``f(Type name,``:
    # a type when it opens a statement, follows a modifier, or opens a
    # parameter slot. ``return x foo(`` and ``= x foo(`` are not valid code, so
    # anything else is treated as a value to stay on the recall side.
    if not before or before[-1] in "{;}(,":
      return True
    if before.split()[-1] in _DECL_MODIFIERS:
      return True
  return False


def code_portion(line: str) -> str:
  """``line`` with a trailing ``//`` or ``/*`` comment removed (WP9).

  Comment openers inside string literals (``"http://host"``) are kept: the
  scan tracks ``"`` / ``'`` quoting and only cuts at an opener that is
  outside every literal. Used so that a token mentioned only in a trailing
  comment (``String TAG = "Adapter";  // MediaStore``) is classified as a
  comment mention rather than a value use, which otherwise makes it the
  anchor of a per-file question. Full-line comments are handled separately by
  the ``_COMMENT_PREFIXES`` check.
  """
  quote: Optional[str] = None
  i = 0
  n = len(line)
  while i < n:
    ch = line[i]
    if quote is not None:
      if ch == "\\":
        i += 2
        continue
      if ch == quote:
        quote = None
    elif ch in ("\"", "'"):
      quote = ch
    elif ch == "/" and i + 1 < n and line[i + 1] in ("/", "*"):
      return line[:i]
    i += 1
  return line


def lexical_hits(lines: Sequence[str], pattern: str) -> LexicalHits:
  """Classifies every occurrence of an identifier pattern (see :class:`LexicalHits`)."""
  out = LexicalHits()
  if not is_identifier_pattern(pattern):
    return out
  variant = (pattern[0].upper() + pattern[1:]) if pattern.islower() else None
  for i, raw in enumerate(lines):
    if pattern not in raw and not (variant is not None and variant in raw):
      continue
    stripped = raw.lstrip()
    if stripped.startswith(_COMMENT_PREFIXES) or stripped.startswith(_IMPORT_PREFIXES):
      out.demoted_lines.append(i)
      out.examples.setdefault("demoted", stripped[:160])
      continue
    # WP9: a mention that survives only in a trailing comment is a comment mention.
    line = code_portion(raw)
    if pattern not in line and not (variant is not None and variant in line):
      out.demoted_lines.append(i)
      out.examples.setdefault("demoted", stripped[:160])
      continue
    matches = boundary_matches(line, pattern)
    if not matches:
      out.substring_lines.append(i)
      out.examples.setdefault("substring", stripped[:160])
      continue
    value_cols = [c for c, _ in matches if not is_type_position(line, c, len(pattern))]
    if not value_cols:
      out.type_lines.append(i)
      out.examples.setdefault("type", stripped[:160])
    else:
      out.value_lines.append(i)
      out.examples.setdefault("value", stripped[:160])
      if any(exact for c, exact in matches if c in value_cols):
        out.exact_value_lines.append(i)
  return out


_DECL_HINT_RE = re.compile(
    r"\b(fun|def|void|public|private|protected|internal|static|override|suspend|"
    r"func|function|async|constructor|init|get|set|class|object|interface)\b"
    r"|=>\s*\{?\s*$|\)\s*(?::\s*[\w<>\[\]?., ]+)?\s*\{?\s*$"
)

# Control-flow block headers also end in ``) {`` and would otherwise satisfy the
# last alternative of ``_DECL_HINT_RE``. They are *not* declarations: a hit
# inside ``switch (x) { ... }`` must still resolve to the enclosing function so
# that a sink called two lines after the block (``startActivity(intent)``)
# counts as "in scope". Found on a dev app where a MIME literal inside a
# ``switch`` lost its IPC sink and the anchor ranked tier 3 (WP2).
_CONTROL_HEADER_RE = re.compile(
    r"^\s*\}?\s*(?:else\s+)?"
    r"(?:if|else|for|while|do|switch|when|case|try|catch|finally|synchronized|"
    r"with|repeat|foreach|until|unless|lock|using|select)\b"
)
# Expression-form control blocks: ``val mime = when (which) {``,
# ``return if (x) {``, ``= try {`` (Kotlin/Scala/Swift-style).
_EXPR_CONTROL_RE = re.compile(r"(?:=|\breturn|\bthrow)\s*(?:if|when|try|switch|match)\b")


def is_declaration_header(line: str) -> bool:
  """True when ``line`` opens a function/class/lambda body (not a control block)."""
  if _CONTROL_HEADER_RE.match(line) or _EXPR_CONTROL_RE.search(line):
    return False
  return bool(_DECL_HINT_RE.search(line))


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
      if is_declaration_header(header) and "(" in header:
        start = i
        break
      # A bare "{" on its own line: the header is the previous line.
      if header.strip() == "{" and i > 0 and is_declaration_header(lines[i - 1]):
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


_CLASS_FILE_EXTENSIONS = (".kt", ".java", ".cs")
_TEST_DIR_MARKERS = ("/src/test", "/src/androidTest", "/test/", "/androidTest/")


def find_class_files(app_dir: str, class_name: str) -> List[str]:
  """Relative paths of source files that plausibly declare ``class_name`` (WP5).

  ``class_name`` may be fully qualified (``com.x.svc.Foo``) or manifest-relative
  (``.Foo``); only the simple name is used, matched against the file's base
  name (Java requires it; Kotlin convention follows it). Build outputs,
  vendored trees and test source sets are skipped. Returns the shipped-source
  matches sorted for determinism; several matches (same simple name in two
  flavours) are all returned so a caller can check each.
  """
  simple = class_name.rsplit(".", 1)[-1].strip()
  if not simple:
    return []
  wanted = {simple + ext for ext in _CLASS_FILE_EXTENSIONS}
  out: List[str] = []
  for root, dirs, files in os.walk(app_dir):
    dirs[:] = [d for d in dirs if d not in IGNORED_DIR_NAMES]
    rel_root = "/" + os.path.relpath(root, app_dir).replace(os.sep, "/") + "/"
    if any(marker in rel_root for marker in _TEST_DIR_MARKERS):
      continue
    for name in files:
      if name in wanted:
        out.append(os.path.relpath(os.path.join(root, name), app_dir).replace(os.sep, "/"))
  return sorted(out)


def value_reference_lines(app_dir: str, relpath: str, identifier: str) -> List[int]:
  """1-based lines where the *exact* identifier ``identifier`` is referenced in
  ``relpath``. Unlike the scanner pre-gate (which matches camelCase *words*),
  this is an exact-identifier match: ``startForegroundService`` does not count
  for ``startForeground``. Comment-only and import lines are skipped. Used by
  manifest policies that need one code fact (WP5)."""
  exact = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(identifier) + r"(?![A-Za-z0-9_])")
  out: List[int] = []
  for i, line in enumerate(_read(os.path.join(app_dir, relpath)).splitlines()):
    stripped = line.lstrip()
    if stripped.startswith(_COMMENT_PREFIXES) or stripped.startswith(_IMPORT_PREFIXES):
      continue
    if exact.search(line):
      out.append(i + 1)
  return out


# ---------------------------------------------------------------------------
# First-party class index and one-hop callee references (WP6, lesson L3)
# ---------------------------------------------------------------------------
#
# Java requires one public top-level class per file named after the file;
# Kotlin and C# follow the convention closely enough that "simple class name ==
# file base name" is a usable, parser-free index of the app's own classes. The
# index answers one question for the context builder: *which first-party file
# does the identifier ``Uploader`` on this line most plausibly refer to?* It
# never says what that file does -- the callee's imports are classified by the
# semantic layer and its sinks are computed by ``context.file_sinks`` exactly
# like the caller's.

# A capitalised identifier in value/type position that is not part of a dotted
# chain (``foo.Bar`` is a member access, ``com.app.Bar`` a qualified name --
# both rare enough as *first-party constructor/static call* forms to skip, and
# skipping them keeps the reference regex aligned with ``symbol_references``).
_CLASS_REF_RE = re.compile(r"(?<![\w.@])([A-Z][A-Za-z0-9_]*)(?![\w])")

# Kotlin/Java/C# source that declares a class per file. Dart and JS/TS files
# are snake-case and multi-class, so simple-name matching does not apply.
_INDEXED_EXTENSIONS = (".kt", ".java", ".cs")


@dataclasses.dataclass
class CalleeRef:
  """One first-party class referenced from a caller file.

  Attributes:
    symbol: The simple class name as written in the caller (``Uploader``).
    relpath: The first-party file the name resolved to, relative to the app.
    lines: 0-based caller lines that reference the symbol (import and
      comment lines excluded). The context builder intersects these with an
      anchor's scope to decide whether the callee is reached from it.
    resolution: How the file was chosen -- ``import`` (the caller imports it
      from a first-party package), ``same_package`` (implicit import),
      ``unique`` (only one file declares the name), ``nearest`` (several
      files; the one sharing the longest directory prefix with the caller).
      Recorded in the decision trace for auditability.
    members_by_line: ``caller line -> member names`` called on the symbol on
      that line (``Uploader.send(x)`` -> ``send``; ``Uploader(ctx).send(x)``
      -> ``send``; ``Uploader::send`` -> ``send``). Empty for a line that
      only names the type or constructs it without a chained call; the
      context layer then falls back to the callee's file-level sinks.
  """

  symbol: str
  relpath: str
  lines: List[int]
  resolution: str
  members_by_line: Dict[int, List[str]] = dataclasses.field(default_factory=dict)


def _member_call_re(symbol: str) -> re.Pattern:
  """Members called on ``symbol`` on one line (see :attr:`CalleeRef.members_by_line`).

  Alternatives, in order: ``Symbol.member`` / ``Symbol::member`` (static or
  singleton access; Java-calling-Kotlin ``Symbol.INSTANCE.member`` and Kotlin
  ``Symbol.Companion.member`` are collapsed to ``member``), and
  ``Symbol(args).member`` (construct-then-call, arguments with one level of
  nested parentheses). A bare ``Symbol(args)`` or a type position yields no
  member.
  """
  sym = re.escape(symbol)
  return re.compile(
      rf"(?<![\w.]){sym}\s*(?:\.|::)\s*(?:(?:INSTANCE|Companion)\s*\.\s*)?([A-Za-z_]\w*)"
      rf"|(?<![\w.]){sym}\s*\((?:[^()]|\([^()]*\))*\)\s*\.\s*([A-Za-z_]\w*)")


def called_members(line: str, symbol: str) -> List[str]:
  """Distinct member names called on ``symbol`` in ``line``, in order."""
  out: List[str] = []
  for m in _member_call_re(symbol).finditer(line):
    name = m.group(1) or m.group(2)
    if name and name not in out:
      out.append(name)
  return out


# Declaration of a member named ``X`` inside a callee file. Kotlin/Swift/Scala
# style (``fun X(``, ``val X``, ``var X``), Python (``def X(``), and Java/C#
# style (``<modifiers> <Type> X(`` where the text before the name is only
# modifiers, annotations, generics and array brackets). Property declarations
# count because a caller reading ``Config.endpoint`` reaches the initializer.
_KOTLIN_FUN_RE_TMPL = r"\bfun\s+(?:<[^<>]*>\s+)?(?:[\w.]+(?:<[^<>]*>)?\??\.)?{name}\s*\("
_KOTLIN_PROP_RE_TMPL = r"\b(?:val|var|const\s+val|lateinit\s+var)\s+{name}\b"
_PY_DEF_RE_TMPL = r"\b(?:async\s+)?def\s+{name}\s*\("
_JAVA_DECL_BEFORE_RE = re.compile(
    r"^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|private|protected|static|final|abstract|"
    r"synchronized|native|default|override|virtual|internal|async|sealed|readonly|extern|"
    r"unsafe|partial|new)\s+)*(?:[\w.]+(?:<[^<>]*(?:<[^<>]*>[^<>]*)*>)?(?:\[\])*\s+)?$")


def member_declaration_lines(lines: Sequence[str], name: str) -> List[int]:
  """0-based lines that declare a function/method/property named ``name``.

  Language-agnostic by construction (a Kotlin ``fun``, a Python ``def``, a
  Java/C# ``Type name(`` header, a Kotlin/Swift property). Comment and import
  lines are skipped. Several lines are returned for overloads. A line where
  the name is *called* rather than declared (``return name(``, ``x = name(``,
  ``obj.name(``) never matches because the text before the name is not a
  declaration prefix.
  """
  if not re.match(r"^[A-Za-z_]\w*$", name):
    return []
  k_fun = re.compile(_KOTLIN_FUN_RE_TMPL.format(name=re.escape(name)))
  k_prop = re.compile(_KOTLIN_PROP_RE_TMPL.format(name=re.escape(name)))
  py_def = re.compile(_PY_DEF_RE_TMPL.format(name=re.escape(name)))
  java_call = re.compile(r"(?<![\w.])" + re.escape(name) + r"\s*\(")
  out: List[int] = []
  for i, line in enumerate(lines):
    if name not in line:
      continue
    stripped = line.lstrip()
    if stripped.startswith(_COMMENT_PREFIXES) or stripped.startswith(_IMPORT_PREFIXES):
      continue
    if k_fun.search(line) or py_def.search(line):
      out.append(i)
      continue
    if k_prop.search(line):
      out.append(i)
      continue
    m = java_call.search(line)
    if m and _JAVA_DECL_BEFORE_RE.match(line[:m.start()]) and line[:m.start()].strip():
      # ``Type name(`` -- a Java/C# method header (or constructor when the
      # prefix is only modifiers and the name is the class name).
      out.append(i)
      continue
    if m and not line[:m.start()].strip() and is_declaration_header(line):
      out.append(i)
  return out


def declaration_scope(lines: Sequence[str], decl: int, max_lines: int = 120) -> Tuple[int, int]:
  """``(start, end)`` 0-based end-exclusive body of the declaration on ``decl``.

  Brace languages: from the header forward to the line where the brace depth
  returns to the header's depth (the header may open its brace on a later
  line). Expression bodies (``fun f() = g()``) and abstract members are the
  header line plus any immediately following deeper-indented continuation
  lines. Bounded by ``max_lines`` from the header.
  """
  n = len(lines)
  if decl < 0 or decl >= n:
    return 0, 0
  profile = _depth_profile(lines)
  base = profile[decl]
  # Find where the body opens: the header line or one of the next two lines.
  opener = None
  for j in range(decl, min(n, decl + 3)):
    if profile[j + 1] > base:
      opener = j
      break
    if j > decl and lines[j].strip() and not lines[j].strip().startswith("{"):
      break
  if opener is None:
    end = decl + 1
    indent = len(lines[decl]) - len(lines[decl].lstrip())
    while end < n and end - decl < 8 and lines[end].strip() and \
        (len(lines[end]) - len(lines[end].lstrip())) > indent:
      end += 1
    return decl, end
  end = opener + 1
  while end < n and profile[end] > base and end - decl < max_lines:
    end += 1
  return decl, end


@dataclasses.dataclass
class FirstPartyIndex:
  """Per-app ``simple class name -> source file(s)`` index (WP6).

  Built once per run by :func:`build_first_party_index` from the shipped
  source under ``app_dir`` (build outputs, vendored trees and test source sets
  excluded). Deterministic and read-only; nothing here decides what a class
  *does*.

  Attributes:
    app_dir: The app root the relative paths are anchored to.
    by_name: ``simple name -> sorted relpaths`` declaring a file of that name.
    package_by_file: ``relpath -> declared package`` (``""`` when the head of
      the file has no ``package``/``namespace`` line).
  """

  app_dir: str
  by_name: Dict[str, List[str]] = dataclasses.field(default_factory=dict)
  package_by_file: Dict[str, str] = dataclasses.field(default_factory=dict)

  def __len__(self) -> int:
    return len(self.by_name)

  @property
  def packages(self) -> Tuple[str, ...]:
    """Distinct declared packages of the indexed files (first-party by construction)."""
    return tuple(sorted({p for p in self.package_by_file.values() if p}))

  def resolve(self, symbol: str, caller: FileStructure) -> Optional[CalleeRef]:
    """Picks the file ``symbol`` refers to *from* ``caller``, or None.

    Resolution order, all deterministic:

    1. The caller imports ``<pkg>.<symbol>`` and an indexed file with that
       simple name declares ``<pkg>`` -> that file (``import``). If the caller
       imports a ``<symbol>`` from a package *no* indexed file declares, the
       name is a platform/third-party class that happens to share a name with
       an app class (``Log``) and is **not** resolved.
    2. An indexed file with that name in the caller's own package
       (``same_package``).
    3. Exactly one indexed file has the name (``unique``).
    4. Several do (the same helper in two flavours): the one sharing the
       longest leading directory path with the caller (``nearest``).

    The caller's own file is never a callee. Reference lines are filled in by
    :func:`callee_references`, not here.
    """
    files = [rp for rp in self.by_name.get(symbol, []) if rp != caller.relpath]
    if not files:
      return None
    imported_pkgs = [package_of(m) for m in caller.imports if simple_name(m) == symbol]
    if imported_pkgs:
      for rp in files:
        if self.package_by_file.get(rp, "") in imported_pkgs:
          return CalleeRef(symbol, rp, [], "import")
      log.debug("callee %s in %s is imported from %s which no first-party file declares; skipped",
                symbol, caller.relpath, imported_pkgs)
      return None
    if caller.package:
      same = [rp for rp in files if self.package_by_file.get(rp, "") == caller.package]
      if len(same) == 1:
        return CalleeRef(symbol, same[0], [], "same_package")
      if same:
        files = same
    if len(files) == 1:
      return CalleeRef(symbol, files[0], [], "unique")
    caller_parts = caller.relpath.split("/")[:-1]

    def _shared_prefix(rp: str) -> int:
      parts = rp.split("/")[:-1]
      n = 0
      for a, b in zip(caller_parts, parts):
        if a != b:
          break
        n += 1
      return n

    best = max(files, key=lambda rp: (_shared_prefix(rp), -len(rp), rp))
    log.debug("callee %s in %s is ambiguous across %s; chose nearest %s",
              symbol, caller.relpath, files, best)
    return CalleeRef(symbol, best, [], "nearest")


def build_first_party_index(app_dir: str, excluded_flavors: Iterable[str] = ()) -> FirstPartyIndex:
  """Walks the shipped source under ``app_dir`` into a :class:`FirstPartyIndex`.

  Only ``.kt`` / ``.java`` / ``.cs`` files are indexed (see
  ``_INDEXED_EXTENSIONS``); build outputs, vendored trees and test source sets
  are skipped, as is every ``/src/<flavor>/`` tree in ``excluded_flavors``
  (the engine passes the non-prioritised product flavours: a flavour that is
  not shipped may carry *stub* copies of a third-party SDK's classes -- an
  ``fdroid`` flavour stubbing a billing client, say -- and indexing them would
  make the real SDK look first-party in the shipped flavour). The ``package``
  declaration is read from the first ``constants.CALLEE_INDEX_HEAD_BYTES`` of
  each file. Never raises: an unreadable file simply has package ``""``.
  """
  index = FirstPartyIndex(app_dir=app_dir)
  if not app_dir or not os.path.isdir(app_dir):
    log.info("first-party index: no app dir (%r); empty index", app_dir)
    return index
  flavor_markers = tuple(f"/src/{fl}/" for fl in excluded_flavors if fl)
  scanned = 0
  skipped_flavor = 0
  for root, dirs, files in os.walk(app_dir):
    dirs[:] = [d for d in dirs if d not in IGNORED_DIR_NAMES]
    rel_root = "/" + os.path.relpath(root, app_dir).replace(os.sep, "/") + "/"
    if any(marker in rel_root for marker in _TEST_DIR_MARKERS):
      continue
    if any(marker in rel_root for marker in flavor_markers):
      skipped_flavor += sum(1 for n in files if os.path.splitext(n)[1] in _INDEXED_EXTENSIONS)
      continue
    for name in files:
      base, ext = os.path.splitext(name)
      if ext not in _INDEXED_EXTENSIONS or not re.match(r"^[A-Z]\w*$", base):
        continue
      full = os.path.join(root, name)
      relpath = os.path.relpath(full, app_dir).replace(os.sep, "/")
      scanned += 1
      try:
        with open(full, "r", encoding="utf-8", errors="ignore") as f:
          head = f.read(constants.CALLEE_INDEX_HEAD_BYTES)
      except OSError:
        head = ""
      index.by_name.setdefault(base, []).append(relpath)
      index.package_by_file[relpath] = declared_package(head)
  for rps in index.by_name.values():
    rps.sort()
  ambiguous = sum(1 for rps in index.by_name.values() if len(rps) > 1)
  log.info("first-party index: %d class files, %d distinct names (%d ambiguous), %d packages under %s"
           " (%d files in excluded flavours %s skipped)",
           scanned, len(index.by_name), ambiguous, len(index.packages), app_dir,
           skipped_flavor, sorted(excluded_flavors))
  return index


def callee_references(
    fs: FileStructure,
    index: FirstPartyIndex,
    within: Optional[Iterable[int]] = None,
    cap: Optional[int] = None,
) -> List[CalleeRef]:
  """First-party classes referenced from ``fs`` with their reference lines.

  Args:
    fs: The caller's structure.
    index: The app's first-party index.
    within: Optional 0-based line set; when given, only references on those
      lines count (the engine passes the union of the file's candidate
      scopes so hops are computed only where an anchor can land).
    cap: Maximum callees returned (``constants.MAX_CALLEE_FILES_PER_CALLER``
      when None), most-referenced first, then first reference line.

  Comment-only and import lines are skipped (a class named in a doc comment is
  not called). Names that resolve to no first-party file -- or that the caller
  imports from a non-first-party package -- are ignored; see
  :meth:`FirstPartyIndex.resolve`.
  """
  if cap is None:
    cap = constants.MAX_CALLEE_FILES_PER_CALLER
  allowed = set(within) if within is not None else None
  lines_by_symbol: Dict[str, List[int]] = {}
  members_by_symbol: Dict[str, Dict[int, List[str]]] = {}
  for i, line in enumerate(fs.lines):
    if allowed is not None and i not in allowed:
      continue
    stripped = line.lstrip()
    if stripped.startswith(_COMMENT_PREFIXES) or stripped.startswith(_IMPORT_PREFIXES):
      continue
    for m in _CLASS_REF_RE.finditer(line):
      name = m.group(1)
      if name in index.by_name:
        hits = lines_by_symbol.setdefault(name, [])
        if not hits or hits[-1] != i:
          hits.append(i)
          members = called_members(line, name)
          if members:
            members_by_symbol.setdefault(name, {})[i] = members
  refs: List[CalleeRef] = []
  for name, hits in lines_by_symbol.items():
    ref = index.resolve(name, fs)
    if ref is None:
      continue
    ref.lines = hits
    ref.members_by_line = members_by_symbol.get(name, {})
    refs.append(ref)
  refs.sort(key=lambda r: (-len(r.lines), r.lines[0] if r.lines else 1 << 30, r.symbol))
  if len(refs) > cap:
    log.info("callee references in %s: %d first-party classes, keeping the %d most referenced",
             fs.relpath, len(refs), cap)
    refs = refs[:cap]
  log.debug("callee references in %s: %s", fs.relpath,
            [(r.symbol, r.relpath, len(r.lines), r.resolution) for r in refs])
  return refs


# ---------------------------------------------------------------------------
# Deterministic destination hints (WP7)
# ---------------------------------------------------------------------------
#
# ``destination_class`` (questions.py) asks the model *where* a transfer goes.
# The structure layer can often see a strong prior without judgement:
#
# * the host / URL / server the sink talks to is read from a preference or a
#   UI field in the same scope -> the user chose the destination;
# * the scope hands data to a system chooser / picker intent -> the user picks
#   the receiving app;
# * the endpoint is a compile-time literal whose host sits under the domain
#   the app's own package name spells backwards -> the developer's backend;
# * the endpoint is some other compile-time literal -> a constant endpoint
#   (developer or third party; the model decides).
#
# Hints are *priors*: they ride in the state and in the decision trace and
# corroborate the model's Choice in ``evaluate``; they never decide alone.
# Only Android platform API names appear below (never a vendor or library).

#: Hint kinds. Names are stable: they appear in states, traces and labels.
USER_CHOSEN_DESTINATION = "USER_CHOSEN_DESTINATION"
DEVELOPER_BACKEND = "DEVELOPER_BACKEND"
CONSTANT_ENDPOINT = "CONSTANT_ENDPOINT"

# Identifier parts that name a destination (host, URL, server, ...). Parts are
# camelCase / snake_case segments so ``securityPrefs`` does not match ``uri``
# while ``serverUrl``, ``mHost``, ``remote_addr`` and ``URL`` do.
_DESTINATION_PARTS = ("host", "url", "uri", "server", "endpoint", "address", "addr",
                      "domain", "remote", "hostname")
_IDENT_RE = re.compile(r"\b[A-Za-z_]\w*\b")
_CAMEL_SPLIT_RE = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")


def _names_destination(identifier: str) -> bool:
  parts = [p.lower() for chunk in identifier.split("_") for p in _CAMEL_SPLIT_RE.findall(chunk)]
  return any(p.startswith(frag) for p in parts for frag in _DESTINATION_PARTS)


def _mentions_destination(line: str) -> bool:
  return any(_names_destination(m.group(0)) for m in _IDENT_RE.finditer(line))
# Reads of a preference, an intent extra, a UI field or a picked URI: the value
# came from the user (or from an app the user chose) at run time.
_USER_SOURCE_TOKENS = (
    "getString(", "getText(", ".text", "getStringExtra(", "getQueryParameter(",
    "getSelectedItem", "Preference", "prefs", "preferences", "settings",
    "getData(", ".data", "getExtras(", "extras", "arguments", "Bundle",
    "EditText", "TextView", "Spinner", "AutoComplete",
)
# The scope lets the user pick the receiving app or the target document.
_CHOOSER_TOKENS = (
    "createChooser(", "ACTION_SEND", "ACTION_SENDTO", "ACTION_VIEW", "ACTION_PICK",
    "ACTION_GET_CONTENT", "ACTION_OPEN_DOCUMENT", "ACTION_CREATE_DOCUMENT",
    "ACTION_OPEN_DOCUMENT_TREE", "ActivityResultContracts", "startActivityForResult(",
    "ShareCompat", "ShareSheet",
)
_URL_LITERAL_RE = re.compile(r"[\"'](?:https?|wss?|ftps?|sftp|smb)://([A-Za-z0-9.\-]+)")
_MAX_HINT_EVIDENCE_CHARS = 160


@dataclasses.dataclass
class DestinationHint:
  """One deterministic prior about where a transfer in a scope goes.

  Attributes:
    kind: One of :data:`USER_CHOSEN_DESTINATION`, :data:`DEVELOPER_BACKEND`,
      :data:`CONSTANT_ENDPOINT`.
    line: 0-based line the hint was read from.
    detail: Why -- ``preference_or_ui_field``, ``chooser``, or the literal
      host for endpoint hints.
    evidence: The stripped source line (bounded).
  """

  kind: str
  line: int
  detail: str
  evidence: str

  def to_state(self) -> Dict[str, object]:
    return {"hint": self.kind, "line": self.line + 1, "detail": self.detail,
            "evidence": self.evidence}


def developer_domains(package_name: str) -> List[str]:
  """Candidate developer domains spelt by an application id.

  ``com.example.app`` -> ``["example.com"]``; ``io.example.sub.app`` ->
  ``["example.io", "sub.example.io"]``. Generic hosting prefixes cannot be
  inverted, so an id with fewer than two labels yields nothing.
  """
  labels = [p for p in (package_name or "").lower().split(".") if p]
  if len(labels) < 2:
    return []
  out = [f"{labels[1]}.{labels[0]}"]
  if len(labels) >= 3:
    out.append(f"{labels[2]}.{labels[1]}.{labels[0]}")
  return out


def _host_under(host: str, domains: Sequence[str]) -> bool:
  h = host.lower()
  return any(h == d or h.endswith("." + d) for d in domains)


def destination_hints(
    lines: Sequence[str], scope: Tuple[int, int], dev_domains: Sequence[str] = ()
) -> List[DestinationHint]:
  """Deterministic destination priors for the lines in ``[scope[0], scope[1])``.

  Args:
    lines: The file's lines (0-based).
    scope: Half-open 0-based line range (an anchor's enclosing scope).
    dev_domains: :func:`developer_domains` of the app's package; a literal
      endpoint under one of them is a :data:`DEVELOPER_BACKEND` hint.

  Returns one hint per (kind, line), in line order; at most one
  ``USER_CHOSEN_DESTINATION`` per line. Comment and import lines are skipped.
  """
  out: List[DestinationHint] = []
  start, end = max(0, scope[0]), min(len(lines), scope[1])
  for i in range(start, end):
    line = lines[i]
    stripped = line.strip()
    if not stripped or stripped.startswith(_COMMENT_PREFIXES) or stripped.startswith(_IMPORT_PREFIXES):
      continue
    evidence = stripped[:_MAX_HINT_EVIDENCE_CHARS]
    if any(tok in line for tok in _USER_SOURCE_TOKENS) and _mentions_destination(line):
      out.append(DestinationHint(USER_CHOSEN_DESTINATION, i, "preference_or_ui_field", evidence))
    elif any(tok in line for tok in _CHOOSER_TOKENS):
      out.append(DestinationHint(USER_CHOSEN_DESTINATION, i, "chooser", evidence))
    for m in _URL_LITERAL_RE.finditer(line):
      host = m.group(1)
      kind = DEVELOPER_BACKEND if _host_under(host, dev_domains) else CONSTANT_ENDPOINT
      out.append(DestinationHint(kind, i, host, evidence))
  if out:
    log.debug("destination hints in lines %d-%d: %s", start + 1, end,
              [(h.kind, h.line + 1, h.detail) for h in out])
  return out


# ---------------------------------------------------------------------------
# Guard flags, declarations and string references (WP8).
#
# A transfer that runs only when a boolean is set is "opt-in" or "default-on"
# depending on that boolean's declared default. The default lives at the
# declaration (``var crashReports by booleanPref(true)``,
# ``private boolean upload = false;``, ``prefs.getBoolean("upload", true)``),
# often in another file. These helpers find the flags that guard a scope and
# their declarations deterministically; the model receives them as priors.
# ---------------------------------------------------------------------------

#: Condition heads whose parenthesised (or bare, Kotlin/Python) expression is a
#: boolean guard. ``when (subject)`` is a switch, not a boolean condition, and
#: is deliberately absent.
_CONDITION_HEAD_RE = re.compile(r"\b(?:if|else\s+if|elif|while)\b\s*(\(|)")
#: A statement that leaves the enclosing block: an ``if (x) { return }`` guard
#: gates the code *after* it, so the flag's effective sense is inverted.
_EARLY_EXIT_RE = re.compile(r"^(?:return|throw|break|continue)\b")
#: Member names of language / platform standard-library predicates that are
#: never a user-facing setting (emptiness, blankness, nullness, file-system
#: results, lifecycle state). Conditions on them are control flow, not
#: consent, and would otherwise crowd out real flags under the state cap.
_NON_SETTING_MEMBERS = frozenset({
    "isEmpty", "isNotEmpty", "isNullOrEmpty", "isNullOrBlank", "isBlank", "isNotBlank",
    "isNull", "isNotNull", "isPresent", "hasNext", "exists", "delete", "mkdir", "mkdirs",
    "createNewFile", "canRead", "canWrite", "isDirectory", "isFile", "isFinishing",
    "isDestroyed", "isCancelled", "isActive", "isCompleted", "isAlive", "isInterrupted",
})
#: Splits a condition into clauses at boolean operators.
_BOOL_OP_RE = re.compile(r"\s*(?:&&|\|\||\band\b|\bor\b)\s*")
#: A clause that is a bare (possibly negated, possibly dotted) identifier.
_FLAG_CLAUSE_RE = re.compile(r"^(?P<neg>!|not\s+)?\s*(?P<ident>[A-Za-z_][\w.]*)\s*$")
#: A clause that is a boolean-returning member call: ``x.isEnabled()``, ``settings.uploadAllowed()``.
_FLAG_CALL_RE = re.compile(r"^(?P<neg>!|not\s+)?\s*(?P<ident>[A-Za-z_][\w.]*)\(\s*\)\s*$")
#: A preference read with an inline default: ``prefs.getBoolean("k", true)``.
_PREF_BOOL_RE = re.compile(
    r"^(?P<neg>!|not\s+)?\s*(?P<recv>[A-Za-z_][\w.]*)\.getBoolean\(\s*(?P<key>[^,]+?)\s*,\s*(?P<default>true|false)\s*\)\s*$")
_GUARD_KEYWORDS = frozenset({"true", "false", "null", "this", "it", "self", "None", "True", "False"})
_DECL_KEYWORDS = ("val", "var", "boolean", "Boolean", "bool", "let", "const", "final", "private", "public",
                  "protected", "internal", "static", "lateinit", "open", "override")
_BOOL_LITERAL_RE = re.compile(r"\b(true|false|True|False)\b")


@dataclasses.dataclass
class GuardFlag:
  """One boolean flag that guards a scope.

  Attributes:
    identifier: The flag as written, dotted receiver included
      (``persistentState.crashReportsEnabled``, ``uploadEnabled``, or the
      preference key for a ``getBoolean`` read).
    line: 0-based line of the condition.
    negated: True when the *guarded transfer code* runs while the flag is
      false. Already folds in ``early_exit``: ``if (!enabled) return`` is
      recorded as ``negated=False`` because the code after the guard runs
      when ``enabled`` is true.
    inline_default: The literal default of an inline ``getBoolean(key,
      default)`` read (None otherwise).
    call: True when the flag is a no-argument member call (``isEnabled()``).
    early_exit: True when the condition's body leaves the block (``return`` /
      ``throw`` / ``break`` / ``continue``), i.e. the guard protects the code
      *after* it rather than the code inside it.
  """

  identifier: str
  line: int
  negated: bool = False
  inline_default: Optional[bool] = None
  call: bool = False
  early_exit: bool = False

  @property
  def name(self) -> str:
    """The last identifier segment (the member/property name)."""
    return self.identifier.rsplit(".", 1)[-1]

  @property
  def receiver(self) -> str:
    """The dotted receiver before the last segment ('' when none)."""
    return self.identifier.rsplit(".", 1)[0] if "." in self.identifier else ""


@dataclasses.dataclass
class Declaration:
  """Where a flag is declared and what it is initialised to.

  Attributes:
    relpath: File of the declaration (the caller's own file or a first-party
      callee reached in one hop).
    line: 0-based line.
    text: The declaration line, stripped and truncated.
    initialiser: The right-hand side (after ``=`` or ``by``), if any.
    default_on: True/False when exactly one boolean literal appears in the
      initialiser (``= true``, ``booleanPreference(false)``, ``getBoolean(k,
      true)``), else None.
    resolution: ``same_file`` / ``receiver_type`` (one first-party hop) /
      ``inline`` (a ``getBoolean`` default written at the guard) / ``local``
      (rewritten by ``context.anchor_guards`` when a same-file declaration
      lies inside the anchor's own scope: a local variable, not a setting).
  """

  relpath: str
  line: int
  text: str
  initialiser: str
  default_on: Optional[bool]
  resolution: str

  def to_state(self) -> Dict[str, Any]:
    return {"file": self.relpath, "line": self.line + 1, "text": self.text,
            "initialiser": self.initialiser, "default_on": self.default_on,
            "resolution": self.resolution}


def _condition_span(lines: Sequence[str], i: int) -> Tuple[str, str]:
  """``(condition, body_head)`` of a control-flow head on line ``i`` (``('', '')`` when none).

  A parenthesised condition is read to its matching ``)``, continuing onto
  following lines for multi-line conditions (bounded to 4 lines). A bare
  Kotlin/Python condition (``if x:``, ``if x {``) is the rest of the line up
  to ``:`` / ``{`` / ``->``. ``body_head`` is the source text that follows the
  condition on its last line (``{ return }``, ``return``, ``:``) -- what
  :func:`_is_early_exit` inspects.
  """
  line = lines[i]
  m = _CONDITION_HEAD_RE.search(line)
  if not m:
    return "", ""
  if m.group(1) == "(":
    depth, buf = 0, []
    text = line[m.end() - 1:]
    for k in range(i, min(len(lines), i + 4)):
      seg = text if k == i else lines[k]
      for pos, ch in enumerate(seg):
        if ch == "(":
          depth += 1
        elif ch == ")":
          depth -= 1
          if depth == 0:
            buf.append(ch)
            return "".join(buf)[1:-1], seg[pos + 1:]
        buf.append(ch)
      buf.append(" ")
    return "", ""
  rest = line[m.end():]
  body_head = ""
  cut = len(rest)
  for stop in (":", "{", "->"):
    idx = rest.find(stop)
    if 0 <= idx < cut:
      cut = idx
  if cut < len(rest):
    body_head = rest[cut:]
  return rest[:cut].strip(), body_head


def _condition_text(lines: Sequence[str], i: int) -> str:
  """The condition expression of a control-flow head on line ``i`` ('' when none)."""
  return _condition_span(lines, i)[0]


def _is_early_exit(lines: Sequence[str], i: int, body_head: str) -> bool:
  """True when the body of the condition on line ``i`` leaves the enclosing block.

  Reads the statements of the body -- the rest of the condition's line after
  ``)`` / ``:`` / ``{`` and, for a braced or indented block, up to 4 further
  lines until the block closes -- and reports whether one of them is a bare
  ``return`` / ``throw`` / ``break`` / ``continue``. A guard whose body exits
  gates the code *after* it, so the caller inverts the flag's sense.
  """
  head = body_head.strip()
  if head.startswith("{"):
    head = head[1:]
  elif head.startswith(":"):
    head = head[1:]
  statements: List[str] = []
  # Statements on the head line itself (``if (x) { return }`` / ``if (x) return``).
  for part in head.split("}")[0].split(";"):
    part = part.strip()
    if part:
      statements.append(part)
  # Following lines of the block, bounded; the block is over at its closing
  # brace or at a dedent back to the head's indentation (Python, brace-less
  # Kotlin). An Allman-style ``{`` on its own line is skipped.
  head_indent = len(lines[i]) - len(lines[i].lstrip())
  for k in range(i + 1, min(len(lines), i + 5)):
    raw = lines[k]
    stripped = raw.strip()
    if not stripped or stripped == "{" or stripped.startswith(_COMMENT_PREFIXES):
      continue
    if stripped.startswith("}") or len(raw) - len(raw.lstrip()) <= head_indent:
      break
    for part in stripped.split("}")[0].split(";"):
      part = part.strip()
      if part:
        statements.append(part)
    if "}" in stripped:
      break
  return any(_EARLY_EXIT_RE.match(s) for s in statements)


def guard_flags(lines: Sequence[str], scope: Tuple[int, int]) -> List[GuardFlag]:
  """Boolean flags guarding the lines in ``[scope[0], scope[1])``.

  Reads every control-flow condition inside the scope (``if`` / ``else if`` /
  ``elif`` / ``while``, single- or multi-line), splits it at ``&&`` / ``||``
  / ``and`` / ``or``, and keeps the clauses that are a bare identifier
  (``!enabled``, ``prefs.uploadOn``), a no-argument member call
  (``settings.isEnabled()``) or an inline preference read with a literal
  default (``prefs.getBoolean("k", true)``). Comparisons, arithmetic, calls
  with arguments and literals are not guards (they are not a boolean
  *flag*); neither are standard-library predicates on collections, strings,
  nullness, files or lifecycle (``isEmpty()``, ``isNullOrBlank()``,
  ``exists()``, ``isFinishing`` -- :data:`_NON_SETTING_MEMBERS`), which are
  control flow rather than a setting. ``when (subject)`` is a switch and is
  not read. A guard whose body leaves the block (``if (!enabled) return``)
  protects the code *after* it, so its sense is inverted (``early_exit``).
  Comments and imports are skipped. Deduplicated by identifier, first
  occurrence wins, at most ``MAX_GUARDS_IN_STATE`` (nearest to the scope
  start first, i.e. the outermost guards).
  """
  out: List[GuardFlag] = []
  seen: set = set()
  start, end = max(0, scope[0]), min(len(lines), scope[1])
  for i in range(start, end):
    stripped = lines[i].strip()
    if not stripped or stripped.startswith(_COMMENT_PREFIXES) or stripped.startswith(_IMPORT_PREFIXES):
      continue
    cond, body_head = _condition_span(lines, i)
    if not cond:
      continue
    early_exit = _is_early_exit(lines, i, body_head)
    for clause in _BOOL_OP_RE.split(cond):
      clause = clause.strip()
      while clause.startswith("(") and clause.endswith(")"):
        clause = clause[1:-1].strip()
      if not clause:
        continue
      pm = _PREF_BOOL_RE.match(clause)
      fm = _FLAG_CLAUSE_RE.match(clause) or _FLAG_CALL_RE.match(clause)
      if pm:
        key = pm.group("key").strip().strip("\"'")
        flag = GuardFlag(f"{pm.group('recv')}.getBoolean({key})", i, bool(pm.group("neg")),
                         inline_default=(pm.group("default") == "true"))
      elif fm:
        ident = fm.group("ident")
        member = ident.rsplit(".", 1)[-1]
        if ident in _GUARD_KEYWORDS or member in _GUARD_KEYWORDS or member in _NON_SETTING_MEMBERS:
          continue
        if not any(ch.isalpha() for ch in member):
          continue
        flag = GuardFlag(ident, i, bool(fm.group("neg")), call=bool(_FLAG_CALL_RE.match(clause)))
      else:
        continue
      if early_exit:
        flag.negated = not flag.negated
        flag.early_exit = True
      if flag.identifier in seen:
        continue
      seen.add(flag.identifier)
      out.append(flag)
      if len(out) >= constants.MAX_GUARDS_IN_STATE:
        log.debug("guard_flags: cap %d reached in lines %d-%d", constants.MAX_GUARDS_IN_STATE, start + 1, end)
        return out
  if out:
    log.debug("guard_flags in lines %d-%d: %s", start + 1, end,
              [(g.identifier, g.line + 1, g.negated, g.inline_default, g.early_exit) for g in out])
  return out


def _default_from_initialiser(initialiser: str) -> Optional[bool]:
  literals = _BOOL_LITERAL_RE.findall(initialiser)
  if len(literals) != 1:
    return None
  return literals[0].lower() == "true"


def _declaration_in_lines(lines: Sequence[str], name: str) -> Optional[Tuple[int, str, str]]:
  """``(line, text, initialiser)`` of the first declaration of ``name`` in ``lines``.

  A declaration line starts (after modifiers) with a declaration keyword or a
  boolean type, names ``name`` at an identifier boundary before any ``=`` /
  ``by``, and is not a control-flow line. Kotlin ``val``/``var`` (with ``by``
  delegates), Java/C# ``boolean``/``bool``/``Boolean`` fields, Python
  assignments at class/module level (``NAME = True``) are recognised.
  """
  name_re = re.compile(rf"(?<![\w.]){re.escape(name)}(?!\w)")
  for i, raw in enumerate(lines):
    line = raw.strip()
    if not line or line.startswith(_COMMENT_PREFIXES) or line.startswith(_IMPORT_PREFIXES):
      continue
    if _CONDITION_HEAD_RE.search(line):
      continue
    head, sep, tail = line.partition("=")
    if not sep:
      m = re.match(r"^(.*?)\bby\b(.*)$", line)
      if not m:
        continue
      head, tail = m.group(1), m.group(2)
    if "==" in line[:len(head) + 2] or head.rstrip().endswith(("!", "<", ">")):
      continue
    if not name_re.search(head):
      continue
    first = head.strip().split()
    if not first:
      continue
    has_kw = any(tok in _DECL_KEYWORDS for tok in first) or first[0] == name
    if not has_kw:
      continue
    initialiser = tail.strip().rstrip(";").strip()
    return i, line[:160], initialiser
  return None


def _receiver_type(lines: Sequence[str], receiver: str) -> Optional[str]:
  """The declared type name of a receiver variable in ``lines`` (``val ps: PersistentState``,
  ``private val ps by inject<PersistentState>()``, ``PersistentState ps = ...``,
  ``val ps = PersistentState(...)``). A capitalised receiver is its own type.
  Returns None when not found."""
  base = receiver.split(".")[0]
  if base[:1].isupper():
    return base
  pats = [
      rf"\b{re.escape(base)}\s*:\s*([A-Z]\w*)",
      rf"\b{re.escape(base)}\b[^=\n]*\binject<([A-Z]\w*)>",
      rf"\b([A-Z]\w*)\s+{re.escape(base)}\s*[=;]",
      rf"\b{re.escape(base)}\s*=\s*([A-Z]\w*)\s*\(",
  ]
  for raw in lines:
    line = raw.strip()
    if not line or line.startswith(_COMMENT_PREFIXES):
      continue
    for pat in pats:
      m = re.search(pat, line)
      if m:
        return m.group(1)
  return None


def declaration_of(
    flag: GuardFlag, fs: FileStructure, index: Optional["FirstPartyIndex"] = None, app_dir: str = "",
) -> Optional[Declaration]:
  """Finds where a guard flag is declared and its initialiser.

  Order: an inline ``getBoolean`` default is the declaration
  (``resolution: inline``); then the flag's own file (``same_file``); then,
  when the flag has a receiver, the receiver's declared type is resolved
  through the first-party ``index`` (``FirstPartyIndex.resolve``) and that
  file is searched (``receiver_type``; one hop, bounded by
  ``MAX_GUARD_DECLARATION_HOPS``). A member call (``isEnabled()``) is looked
  up by its member name. Returns None when nothing is found -- the model then
  sees the flag without a default, which is exactly the uncertainty.
  """
  if flag.inline_default is not None:
    return Declaration(fs.relpath, flag.line, fs.lines[flag.line].strip()[:160],
                       f"getBoolean(default={str(flag.inline_default).lower()})", flag.inline_default, "inline")
  found = _declaration_in_lines(fs.lines, flag.name)
  if found:
    i, text, init = found
    return Declaration(fs.relpath, i, text, init, _default_from_initialiser(init), "same_file")
  if not flag.receiver or index is None or not app_dir or constants.MAX_GUARD_DECLARATION_HOPS < 1:
    return None
  type_name = _receiver_type(fs.lines, flag.receiver)
  if not type_name:
    log.debug("declaration_of %s: receiver type of %r not found in %s", flag.identifier, flag.receiver, fs.relpath)
    return None
  ref = index.resolve(type_name, fs)
  if ref is None:
    log.debug("declaration_of %s: type %s not first-party", flag.identifier, type_name)
    return None
  try:
    callee_lines = _read(os.path.join(app_dir, ref.relpath)).splitlines()
  except OSError as exc:
    log.warning("declaration_of %s: cannot read %s: %s", flag.identifier, ref.relpath, exc)
    return None
  found = _declaration_in_lines(callee_lines, flag.name)
  if not found:
    log.debug("declaration_of %s: no declaration of %s in %s", flag.identifier, flag.name, ref.relpath)
    return None
  i, text, init = found
  return Declaration(ref.relpath, i, text, init, _default_from_initialiser(init), "receiver_type")


_R_STRING_REF_RE = re.compile(r"\bR\.string\.(\w+)")


def string_references(lines: Sequence[str], line_numbers: Sequence[int]) -> List[str]:
  """Distinct ``R.string.<name>`` names on the given 0-based lines, in order of appearance."""
  out: List[str] = []
  for i in line_numbers:
    if 0 <= i < len(lines):
      for name in _R_STRING_REF_RE.findall(lines[i]):
        if name not in out:
          out.append(name)
  return out


# ---------------------------------------------------------------------------
# Storage-path and media-access hints (WP9).
#
# Two wave-2 policies need a code fact the manifest cannot give:
#
# * files_and_docs_policy: does the app create its own folder at the *root* of
#   external storage (``Environment.getExternalStorageDirectory() + "/my"``)
#   rather than in an app-specific or SAF-scoped location? The structure layer
#   finds every line that names the storage root (or a public collection
#   directory) and looks a few lines ahead for a path composed from it and a
#   write / create call. The Noul ``creates_root_level_external_folder`` is
#   asked only for files with such a hint, and the hint's strength (a write on
#   a root-composed path) is the deterministic half of the double gate in
#   ``evaluate.compose_files_and_docs_finding``.
# * photo_video_access_policy: does a code site enumerate the media library
#   (a ``MediaStore`` collection query) or let the user pick one item (a
#   picker intent)? These are priors for the Noul ``accesses_full_media_library``
#   and corroborate or contradict its answer in the trace; they never decide.
#
# Only Android platform API names and path literals appear below.

#: Hint kinds. Names are stable: they appear in states, traces and labels.
STORAGE_ROOT = "STORAGE_ROOT"
PUBLIC_DIRECTORY = "PUBLIC_DIRECTORY"
LIBRARY_QUERY = "LIBRARY_QUERY"
USER_PICK = "USER_PICK"

# The shared-storage root: the platform accessor and the literal mount points.
_STORAGE_ROOT_TOKENS = ("getExternalStorageDirectory(", "\"/sdcard", "'/sdcard",
                        "\"/storage/emulated/0", "\"/mnt/sdcard")
# A standard public collection (Downloads, Pictures, ...): a sub-folder there
# is not "root-level" but is still shared storage the model should weigh.
_PUBLIC_DIRECTORY_TOKENS = ("getExternalStoragePublicDirectory(",)
# A path built from the root on the same or a following line.
_PATH_COMPOSE_TOKENS = ("File(", "+ \"", "+ '", ".resolve(", "Paths.get(", "separator", "\"/")
# The composed path is created or written.
_PATH_WRITE_TOKENS = ("mkdir(", "mkdirs(", "createNewFile(", "createDirectory(", "createDirectories(",
                      "FileOutputStream(", "FileWriter(", "PrintWriter(", "RandomAccessFile(",
                      "ZipOutputStream(", "renameTo(", "copyTo(", "writeText(", "writeBytes(",
                      "outputStream(", "openFileOutput(", "Files.write(", "Files.copy(", "Files.move(")
# MediaStore collections and the calls that enumerate them.
_MEDIA_COLLECTION_TOKENS = ("EXTERNAL_CONTENT_URI", "MediaStore.Images", "MediaStore.Video",
                            "MediaStore.Files", "MediaStore.Downloads", "getContentUri(")
_MEDIA_QUERY_TOKENS = ("query(", "ContentResolver", "contentResolver", "Cursor", "loadInBackground(",
                       "CursorLoader(")
# The user selects the item: the Photo Picker or a document / content picker.
_MEDIA_PICK_TOKENS = ("ACTION_PICK_IMAGES", "PickVisualMedia", "PickMultipleVisualMedia", "ACTION_PICK",
                      "ACTION_GET_CONTENT", "ACTION_OPEN_DOCUMENT", "OpenDocument", "GetContent",
                      "registerForActivityResult(", "onActivityResult(")


@dataclasses.dataclass
class StorageHint:
  """One place a file composes a path from shared external storage.

  Attributes:
    kind: :data:`STORAGE_ROOT` or :data:`PUBLIC_DIRECTORY`.
    line: 0-based line naming the root.
    composes: A path is built from the root within ``STORAGE_HINT_WINDOW`` lines.
    writes: That window creates or writes a file / directory.
    evidence: The root line and, when present, the first write line (bounded).
  """

  kind: str
  line: int
  composes: bool
  writes: bool
  evidence: str

  @property
  def strength(self) -> str:
    """``writes`` > ``composes`` > ``references``."""
    if self.writes:
      return "writes"
    return "composes" if self.composes else "references"

  def to_state(self) -> Dict[str, object]:
    return {"hint": self.kind, "line": self.line + 1, "composes": self.composes,
            "writes": self.writes, "strength": self.strength, "evidence": self.evidence}


@dataclasses.dataclass
class MediaHint:
  """One deterministic prior about how a scope reaches the user's media.

  Attributes:
    kind: :data:`LIBRARY_QUERY` (a MediaStore collection is queried) or
      :data:`USER_PICK` (the user selects an item through a picker).
    line: 0-based line.
    detail: The token that produced the hint.
    evidence: The stripped source line (bounded).
  """

  kind: str
  line: int
  detail: str
  evidence: str

  def to_state(self) -> Dict[str, object]:
    return {"hint": self.kind, "line": self.line + 1, "detail": self.detail, "evidence": self.evidence}


def _code_line(line: str) -> bool:
  stripped = line.strip()
  return bool(stripped) and not stripped.startswith(_COMMENT_PREFIXES) and not stripped.startswith(_IMPORT_PREFIXES)


def external_storage_paths(lines: Sequence[str], scope: Optional[Tuple[int, int]] = None) -> List[StorageHint]:
  """Lines that name the shared-storage root and what the following lines do with it.

  Args:
    lines: The file's lines (0-based).
    scope: Optional half-open 0-based line range; None scans the whole file
      (the policy question is per file, not per anchor scope).

  Each hit is followed for ``constants.STORAGE_HINT_WINDOW`` lines (stopping
  at a line that is only ``}``, the end of the enclosing block) to see whether
  a path is composed from the root and whether that path is created or
  written. ``getExternalFilesDir`` / ``getExternalCacheDir`` (app-specific
  directories) are never hints: scoped storage is exactly what they are for.
  Comment and import lines are skipped. Returns hints in line order.
  """
  start, end = (0, len(lines)) if scope is None else (max(0, scope[0]), min(len(lines), scope[1]))
  out: List[StorageHint] = []
  for i in range(start, end):
    line = lines[i]
    if not _code_line(line):
      continue
    kind = None
    if any(tok in line for tok in _STORAGE_ROOT_TOKENS):
      kind = STORAGE_ROOT
    elif any(tok in line for tok in _PUBLIC_DIRECTORY_TOKENS):
      kind = PUBLIC_DIRECTORY
    if kind is None:
      continue
    composes = False
    writes = False
    write_line: Optional[str] = None
    for j in range(i, min(len(lines), i + 1 + constants.STORAGE_HINT_WINDOW)):
      text = lines[j]
      if j > i and text.strip() in ("}", "};"):
        break
      if not _code_line(text):
        continue
      if any(tok in text for tok in _PATH_COMPOSE_TOKENS):
        composes = True
      if any(tok in text for tok in _PATH_WRITE_TOKENS):
        writes = True
        if write_line is None and j != i:
          write_line = text.strip()[:_MAX_HINT_EVIDENCE_CHARS]
    evidence = line.strip()[:_MAX_HINT_EVIDENCE_CHARS]
    if write_line:
      evidence += f" … {write_line}"
    out.append(StorageHint(kind, i, composes, writes, evidence))
  if out:
    log.debug("external storage hints in lines %d-%d: %s", start + 1, end,
              [(h.kind, h.line + 1, h.strength) for h in out])
  return out


def media_access_hints(lines: Sequence[str], scope: Tuple[int, int]) -> List[MediaHint]:
  """Deterministic media-access priors for the lines in ``[scope[0], scope[1])``.

  A :data:`LIBRARY_QUERY` hint needs a MediaStore collection token *and* a
  query token on the same line or within ``constants.STORAGE_HINT_WINDOW``
  following lines (``resolver.query(MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
  ...)``). A :data:`USER_PICK` hint is any picker token. One hint per
  (kind, line); comment and import lines are skipped.
  """
  out: List[MediaHint] = []
  start, end = max(0, scope[0]), min(len(lines), scope[1])
  for i in range(start, end):
    line = lines[i]
    if not _code_line(line):
      continue
    evidence = line.strip()[:_MAX_HINT_EVIDENCE_CHARS]
    collection = next((tok for tok in _MEDIA_COLLECTION_TOKENS if tok in line), None)
    if collection is not None:
      window = [lines[j] for j in range(i, min(len(lines), i + 1 + constants.STORAGE_HINT_WINDOW))]
      if any(tok in text for text in window for tok in _MEDIA_QUERY_TOKENS):
        out.append(MediaHint(LIBRARY_QUERY, i, collection, evidence))
    pick = next((tok for tok in _MEDIA_PICK_TOKENS if tok in line), None)
    if pick is not None:
      out.append(MediaHint(USER_PICK, i, pick, evidence))
  if out:
    log.debug("media access hints in lines %d-%d: %s", start + 1, end,
              [(h.kind, h.line + 1, h.detail) for h in out])
  return out


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

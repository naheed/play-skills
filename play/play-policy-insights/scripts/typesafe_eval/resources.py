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

"""Default-locale Android resource index (structure layer).

Disclosure wording, app labels and several manifest attributes are resource
references (``@string/location_disclosure``, ``R.string.app_name``,
``getString(R.string.x)``) rather than literal text. The legacy agent skill
resolved these by opening ``strings.xml`` by hand; this module does it once per
app, deterministically, so the policy layer can ask questions about the *text*
instead of a symbol name.

Scope is deliberately narrow:

- Only the **default locale** (``res/values/``) is indexed. Localised catalogs
  (``res/values-xx/``) are translations of the same strings and are excluded
  from candidate *anchors* elsewhere (``constants.EXCLUDED_PATH_SUBSTRINGS``);
  they are not needed for resolution either.
- ``<string>`` and ``<string-array>`` items are indexed. Plurals are skipped.
- ``res/xml/<name>.xml`` paths are located (for accessibility-service and
  other configuration resources) but not interpreted here; callers parse them.

Everything is pure and standard-library only. Parse failures are logged at
WARNING and leave the index partial rather than raising.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import re
import xml.etree.ElementTree as ET
from typing import Dict
from typing import List
from typing import Optional

from typesafe_eval import structure

log = logging.getLogger("typesafe_eval.resources")

_STRING_REF_RE = re.compile(r"^@(?:\*?[\w.]+:)?string/(?P<name>[\w.]+)$")
_R_STRING_RE = re.compile(r"\bR\.string\.(?P<name>\w+)")


@dataclasses.dataclass
class ResourceIndex:
  """Default-locale strings and xml resource paths for one module or app.

  Attributes:
    strings: ``name -> text`` from every ``res/values/*.xml`` file found.
    xml_resources: ``name -> relpath`` for ``res/xml/<name>.xml`` files.
    sources: The ``strings`` files that were parsed (relative paths).
  """

  strings: Dict[str, str] = dataclasses.field(default_factory=dict)
  xml_resources: Dict[str, str] = dataclasses.field(default_factory=dict)
  sources: List[str] = dataclasses.field(default_factory=list)

  def resolve(self, ref: Optional[str]) -> Optional[str]:
    """Resolves ``@string/name`` to its text; returns ``ref`` unchanged if literal.

    Returns ``None`` when the reference is a string resource that is not in the
    index (so callers can distinguish "literal text" from "unresolvable").
    """
    if ref is None:
      return None
    m = _STRING_REF_RE.match(ref.strip())
    if not m:
      return ref
    return self.strings.get(m.group("name"))

  def strings_referenced_in(self, text: str, cap: int = 8) -> Dict[str, str]:
    """``R.string.<name>`` references in a code snippet, resolved to text."""
    out: Dict[str, str] = {}
    for m in _R_STRING_RE.finditer(text):
      name = m.group("name")
      if name in self.strings and name not in out:
        out[name] = self.strings[name]
        if len(out) >= cap:
          break
    return out


def _is_default_values_dir(dirname: str) -> bool:
  # ``values`` only; ``values-xx``, ``values-night``, ``values-sw600dp`` are
  # qualifiers and are not the default locale / configuration.
  return dirname == "values"


def _flatten_text(elem: ET.Element) -> str:
  """Text of a ``<string>`` including inline markup children (``<b>``, ``<xliff:g>``)."""
  parts: List[str] = [elem.text or ""]
  for child in elem:
    parts.append(_flatten_text(child))
    parts.append(child.tail or "")
  text = "".join(parts)
  # Android unescapes \' \" \n in resources; keep the visible form.
  text = text.replace("\\'", "'").replace('\\"', '"').replace("\\n", " ")
  return re.sub(r"\s+", " ", text).strip()


def build_index(app_dir: str, module_root: str = "") -> ResourceIndex:
  """Indexes default-locale strings and xml resources under ``module_root``.

  Args:
    app_dir: The application root.
    module_root: Relative path of the module to index (``""`` for the whole
      tree). Restricting to the primary module keeps library or benchmark
      modules from shadowing the app's own strings.
  """
  index = ResourceIndex()
  base = os.path.join(app_dir, module_root) if module_root else app_dir
  if not os.path.isdir(base):
    log.warning("resources: module root %s not found under %s", module_root, app_dir)
    return index
  for root, dirs, files in os.walk(base):
    dirs[:] = [d for d in dirs if d not in structure.IGNORED_DIR_NAMES]
    rel_root = os.path.relpath(root, app_dir)
    if any(frag in "/" + rel_root + "/" for frag in ("/src/test/", "/src/androidTest/")):
      continue
    parent = os.path.basename(os.path.dirname(root))
    name = os.path.basename(root)
    if parent == "res" and _is_default_values_dir(name):
      for fn in sorted(files):
        if fn.endswith(".xml"):
          _parse_values_file(os.path.join(root, fn), os.path.relpath(os.path.join(root, fn), app_dir), index)
    elif parent == "res" and name == "xml":
      for fn in sorted(files):
        if fn.endswith(".xml"):
          index.xml_resources.setdefault(fn[:-4], os.path.relpath(os.path.join(root, fn), app_dir))
  log.info("resources: %d strings from %d files, %d xml resources (module_root=%r)",
           len(index.strings), len(index.sources), len(index.xml_resources), module_root)
  return index


def _parse_values_file(path: str, relpath: str, index: ResourceIndex) -> None:
  try:
    with open(path, "r", encoding="utf-8-sig") as f:
      content = f.read()
    root = ET.fromstring(content)
  except (OSError, ET.ParseError) as exc:
    log.warning("resources: could not parse %s: %s", relpath, exc)
    return
  found = 0
  for elem in root.iter():
    tag = elem.tag.split("}")[-1]
    if tag == "string" and elem.get("name"):
      index.strings.setdefault(elem.get("name"), _flatten_text(elem))
      found += 1
    elif tag == "string-array" and elem.get("name"):
      items = [_flatten_text(i) for i in elem if i.tag.split("}")[-1] == "item"]
      index.strings.setdefault(elem.get("name"), " | ".join(items))
      found += 1
  if found:
    index.sources.append(relpath)

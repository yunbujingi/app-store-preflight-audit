from __future__ import annotations

import re
import unittest
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


class DocumentationTests(unittest.TestCase):
    def test_local_markdown_links_resolve(self) -> None:
        documents = [*ROOT.glob("*.md"), *(ROOT / "docs").rglob("*.md")]
        missing: list[str] = []
        for document in documents:
            content = document.read_text(encoding="utf-8")
            for raw_target in LINK.findall(content):
                target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
                if not target or target.startswith(("#", "http://", "https://", "mailto:")):
                    continue
                path_text = unquote(target.split("#", 1)[0])
                if not path_text:
                    continue
                resolved = (document.parent / path_text).resolve()
                try:
                    resolved.relative_to(ROOT)
                except ValueError:
                    missing.append(f"{document.relative_to(ROOT)} -> {target} (outside repository)")
                    continue
                if not resolved.exists():
                    missing.append(f"{document.relative_to(ROOT)} -> {target}")
        self.assertEqual(missing, [], "broken local Markdown links:\n" + "\n".join(missing))


if __name__ == "__main__":
    unittest.main()

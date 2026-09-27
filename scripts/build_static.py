"""Generate a no-runtime sample gallery from the Python scanner."""

from pathlib import Path
from shutil import copyfile

from agentshield.web import SAMPLES, WEB, render

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "dist"
DEST.mkdir(exist_ok=True)
copyfile(WEB / "style.css", DEST / "style.css")
for name, text in SAMPLES.items():
    (DEST / f"{name}.html").write_text(render(text, example=name, static=True), encoding="utf-8")
(DEST / "index.html").write_text(render(SAMPLES["email"], example="email", static=True), encoding="utf-8")
print("Generated static Python scan examples in dist/")

from pathlib import Path

from setuptools import setup

ROOT = Path(__file__).parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
REQUIREMENTS = [
    line.strip()
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.strip().startswith("#")
]

setup(
    name="oneseam",
    version="3.1.0",
    description="ONESEAM dark-pool non-custodial coordination node",
    long_description=README,
    long_description_content_type="text/markdown",
    py_modules=["oneseam", "oneseam_blind_matching", "oneseam_simple_cli"],
    python_requires=">=3.12",
    install_requires=REQUIREMENTS,
    license="GNU Affero General Public License v3",
    url="https://github.com/dudu-lopes/oneseam",
)

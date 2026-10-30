"""Make the PA30 test fixtures with the Windows msdelta.dll.

Each case has a source and a target that a fixed-seed generator makes. The tests in
tests/fixtures.rs make the same bytes with the same generator, so the repository keeps only the
deltas and a manifest. Run this script on Windows with PowerShell 7 (pwsh):

    python scripts/make-fixtures.py
"""

import hashlib
import json
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
ORACLE = ROOT / "scripts" / "msdelta-oracle.ps1"
MASK = (1 << 64) - 1

WORDS = [
    b"the", b"delta", b"patch", b"source", b"target", b"window", b"huffman", b"rift",
    b"table", b"block", b"length", b"offset", b"match", b"literal", b"stream", b"buffer",
]


class Rng:
    """SplitMix64. tests/common/mod.rs has the same generator."""

    def __init__(self, seed):
        self.state = seed & MASK

    def next(self):
        self.state = (self.state + 0x9E3779B97F4A7C15) & MASK
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK
        return z ^ (z >> 31)

    def below(self, n):
        return self.next() % n


def random_bytes(seed, n):
    rng = Rng(seed)
    return bytes(rng.next() & 0xFF for _ in range(n))


def text(seed, n):
    rng = Rng(seed)
    out = bytearray()
    while len(out) < n:
        out += WORDS[rng.below(len(WORDS))]
        out += b" " if rng.below(8) else b"\n"
    return bytes(out[:n])


def edit(seed, base, edits):
    """Apply `edits` random replacements, insertions, deletions and block moves."""
    rng = Rng(seed)
    data = bytearray(base)
    for _ in range(edits):
        kind = rng.below(4)
        if not data:
            kind = 1
        pos = rng.below(len(data) + 1)
        span = 1 + rng.below(64)
        if kind == 0:
            for i in range(pos, min(pos + span, len(data))):
                data[i] = rng.next() & 0xFF
        elif kind == 1:
            data[pos:pos] = bytes(rng.next() & 0xFF for _ in range(span))
        elif kind == 2:
            del data[pos:pos + span]
        else:
            span = 1 + rng.below(4096)
            block = bytes(data[pos:pos + span])
            del data[pos:pos + span]
            dest = rng.below(len(data) + 1)
            data[dest:dest] = block
    return bytes(data)


def repeat(pattern, n):
    return (pattern * (n // len(pattern) + 1))[:n]


# name -> (source, target, options). Keep tests/common/mod.rs in sync.
def cases():
    big = text(7, 1 << 20)
    rnd = random_bytes(3, 4096)
    far = random_bytes(11, 400_000)
    return {
        "empty-source-text": (b"", text(1, 3000), {}),
        "empty-source-random": (b"", random_bytes(2, 65536), {}),
        "empty-source-repeat": (b"", repeat(b"abcdefgh", 300_000), {}),
        "empty-target": (rnd, b"", {}),
        "both-empty": (b"", b"", {}),
        "identical": (rnd, rnd, {}),
        "small-edits": (rnd, edit(4, rnd, 8), {}),
        "text-edits": (text(5, 20000), edit(6, text(5, 20000), 40), {}),
        "large-moves": (big, edit(8, big, 200), {}),
        "far-matches": (far, far[200_000:] + random_bytes(12, 1000) + far[:200_000], {}),
        "sha1-hash": (rnd, edit(9, rnd, 4), {"hash": 0x8004}),
        "no-hash": (rnd, edit(10, rnd, 4), {"hash": 0}),
        "file-time": (b"", text(13, 500), {"time": 0x01D9_0000_1234_5678}),
        "executable-set-raw-data": (rnd, edit(14, rnd, 4), {"types": 0x0F}),
    }


def oracle(*args):
    result = subprocess.run(["pwsh", "-NoProfile", "-File", str(ORACLE), *map(str, args)],
                            check=True, capture_output=True, text=True)
    return result.stdout


def main():
    FIXTURES.mkdir(parents=True, exist_ok=True)
    manifest = {}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        for name, (source, target, options) in cases().items():
            src, tgt, out = tmp / "s", tmp / "t", FIXTURES / f"{name}.delta"
            src.write_bytes(source)
            tgt.write_bytes(target)
            oracle("create", "-Source", src, "-Target", tgt, "-Out", out,
                   "-FileTypeSet", options.get("types", 1),
                   "-HashAlgId", options.get("hash", 0x8003),
                   "-TargetFileTime", options.get("time", 0))
            check = tmp / "check"
            oracle("apply", "-Source", src, "-Delta", out, "-Out", check)
            assert check.read_bytes() == target, name
            manifest[name] = {
                "source_sha256": hashlib.sha256(source).hexdigest(),
                "target_sha256": hashlib.sha256(target).hexdigest(),
                "delta_bytes": out.stat().st_size,
                "info": json.loads(oracle("info", "-Delta", out)),
            }
            print(f"{name}: {out.stat().st_size} bytes")
    (FIXTURES / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()

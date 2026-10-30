"""Build the small PE images that the PE fixtures use, with the MSVC tools.

The sources are in tests/fixtures/pe/src. Each image has two versions (VERSION=1 and 2). The
repository keeps the built images: they are our own files, not Microsoft files. Run this
script on Windows with Visual Studio 2022 (C++ tools for x64 and x86):

    python scripts/build-pe-fixtures.py
"""

import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
PE = ROOT / "tests" / "fixtures" / "pe"
SRC = PE / "src"
VCVARS = pathlib.Path(
    r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build")

CFLAGS = "/nologo /c /O1 /GS- /Gy- /Zl /Brepro /W3"
LFLAGS = "/nologo /DLL /Brepro /NODEFAULTLIB /INCREMENTAL:NO /OPT:REF"

# name -> (source, rc, extra link flags, libraries)
IMAGES = {
    "sample": ("sample.c", "sample.rc", "/ENTRY:DllMain", "kernel32.lib user32.lib"),
    "apiset": ("apiset.c", "apiset.rc", "/NOENTRY", ""),
}

# architecture -> (vcvars script, link machine, list of images)
ARCHES = {
    "x64": ("vcvars64.bat", "X64", ["sample", "apiset"]),
    "x86": ("vcvars32.bat", "X86", ["sample"]),
}


def run(vcvars, commands, cwd):
    # cmd.exe does not accept the quoting of a command line from subprocess: use a batch file.
    batch = pathlib.Path(cwd) / "build.cmd"
    lines = ["@echo off", f'call "{VCVARS / vcvars}" >nul || exit /b 1']
    lines += [f"{command} || exit /b 1" for command in commands]
    batch.write_text("\r\n".join(lines) + "\r\n")
    subprocess.run(["cmd", "/d", "/c", str(batch)], cwd=cwd, check=True)


def main():
    for arch, (vcvars, machine, names) in ARCHES.items():
        for name in names:
            source, rc, extra, libs = IMAGES[name]
            for version in (1, 2):
                # A compiler helper process can keep the directory open after the build.
                with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                    out = PE / f"{name}-{arch}-v{version}.dll"
                    entry = "/ENTRY:DllMain@12" if arch == "x86" and "DllMain" in extra else extra
                    run(vcvars, [
                        f'cl {CFLAGS} /DVERSION={version} /Fo"{tmp}\\{name}.obj" "{SRC / source}"',
                        f'rc /nologo /DVERSION={version} /fo"{tmp}\\{name}.res" "{SRC / rc}"',
                        f'link {LFLAGS} /MACHINE:{machine} {entry} /OUT:"{out}" '
                        f'/IMPLIB:"{tmp}\\{name}.lib" "{tmp}\\{name}.obj" "{tmp}\\{name}.res" {libs}',
                    ], cwd=tmp)
                    print(f"{out.name}: {out.stat().st_size} bytes")


if __name__ == "__main__":
    main()

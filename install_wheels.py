"""Manual wheel installer using stdlib only (pip is hanging in this env).
Downloads pure-python wheels from PyPI and extracts them into site-packages.
Run with: PYTHON_BIN install_wheels.py
"""
import json
import os
import shutil
import sys
import tempfile
import urllib.request
import zipfile

PY = f"cp{sys.version_info.major}{sys.version_info.minor}"
WORKSPACE = os.path.dirname(os.path.abspath(__file__))
SP = os.path.join(WORKSPACE, "libs")  # workspace-local lib dir (site-packages is read-only)
os.makedirs(SP, exist_ok=True)
if SP not in sys.path:
    sys.path.insert(0, SP)

WANTS = {
    # package -> (version, build-tag fragment to prefer)
    "beautifulsoup4": ("4.14.3", "py3-none-any"),
    "soupsieve": ("2.8", "py3-none-any"),
    "customtkinter": ("5.2.2", "py3-none-any"),
    "darkdetect": ("0.8.0", "py3-none-any"),
    "dnspython": ("2.8.0", "py3-none-any"),
    "reportlab": ("4.4.7", "py3-none-any"),
}


def already(name):
    mod = {"beautifulsoup4": "bs4", "soupsieve": "soupsieve",
           "customtkinter": "customtkinter", "darkdetect": "darkdetect",
           "dnspython": "dns", "reportlab": "reportlab"}.get(name, name)
    try:
        __import__(mod)
        print(f"SKIP {name}: already importable")
        return True
    except ImportError:
        return False


def pick_url(meta, version, tagfrag):
    rels = meta.get("urls") or []
    if not rels:  # fallback: project JSON has "releases"
        rels = meta.get("releases", {}).get(version, [])
    for rel in rels:
        if rel["packagetype"] == "bdist_wheel" and tagfrag in rel["filename"]:
            return rel["url"], rel["filename"]
    # fallback: any wheel
    for rel in rels:
        if rel["packagetype"] == "bdist_wheel":
            return rel["url"], rel["filename"]
    raise RuntimeError(f"no wheel for {version}")


def install(name, version, tagfrag):
    if already(name):
        return
    print(f"FETCH {name}=={version} ...")
    with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json",
                                timeout=30) as r:
        meta = json.load(r)
    url, fn = pick_url(meta, version, tagfrag)
    print(f"  -> {fn}")
    tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".wheels_tmp")
    os.makedirs(tmp, exist_ok=True)
    whl = os.path.join(tmp, fn)
    with urllib.request.urlopen(url, timeout=120) as r, open(whl, "wb") as fh:
        shutil.copyfileobj(r, fh)
    with zipfile.ZipFile(whl) as z:
        # refuse path traversal inside wheels
        for m in z.namelist():
            if m.startswith("/") or ".." in m:
                raise RuntimeError(f"unsafe path in wheel: {m}")
        z.extractall(SP)
    try:
        os.remove(whl)
    except OSError:
        pass
    # verify
    mod = {"beautifulsoup4": "bs4", "dnspython": "dns"}.get(name, name)
    try:
        __import__(mod)
        print(f"OK {name}")
    except ImportError as e:
        print(f"VERIFY-FAIL {name}: {e}")


if __name__ == "__main__":
    print("target site-packages:", SP)
    for name, (ver, tag) in WANTS.items():
        try:
            install(name, ver, tag)
        except Exception as e:
            print(f"FAIL {name}: {e}")
    print("done")

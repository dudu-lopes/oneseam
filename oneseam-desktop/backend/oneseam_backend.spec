# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_submodules, collect_data_files, collect_dynamic_libs


def safe_collect_submodules(name):
    try:
        return collect_submodules(name)
    except Exception:
        return []


def safe_collect_data(name):
    try:
        return collect_data_files(name)
    except Exception:
        return []


def safe_collect_libs(name):
    try:
        return collect_dynamic_libs(name)
    except Exception:
        return []


hiddenimports = ['oneseam_blind_matching']
hiddenimports += safe_collect_submodules('aiohttp')
hiddenimports += safe_collect_submodules('cryptography')
hiddenimports += safe_collect_submodules('Crypto')
hiddenimports += safe_collect_submodules('pydantic')
hiddenimports += safe_collect_submodules('yaml')
hiddenimports += safe_collect_submodules('jwt')
hiddenimports += safe_collect_submodules('miniupnpc')

datas = []
datas += safe_collect_data('cryptography')
datas += safe_collect_data('aiohttp')

binaries = []
binaries += safe_collect_libs('cryptography')

a = Analysis(
    ['oneseam.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='oneseam_backend',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

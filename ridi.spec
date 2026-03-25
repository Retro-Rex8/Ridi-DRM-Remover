# -*- mode: python ; coding: utf-8 -*-
# Ridibooks Decryptor v2.0.0 — PyInstaller spec

a = Analysis(
    ['ridi_books_gui.py'],
    pathex=[],
    binaries=[],
    datas=[('icon.ico', '.'), ('icon.png', '.')],
    hiddenimports=[
        # Core decryption
        'cryptography',
        'cryptography.hazmat.primitives.ciphers',
        'cryptography.hazmat.primitives.ciphers.algorithms',
        'cryptography.hazmat.primitives.ciphers.modes',
        'cryptography.hazmat.backends',
        'cryptography.hazmat.backends.openssl',
        'cryptography.hazmat.backends.openssl.backend',
        'cryptography.hazmat.primitives.padding',
        # Standard library
        'xml.etree.ElementTree',
        'pathlib',
        'zipfile',
        'json',
        'io',
        'os',
        're',
        'sys',
        'sqlite3',
        'shutil',
        'tempfile',
        # GUI
        'tkinter',
        'tkinter.ttk',
        'tkinter.scrolledtext',
        'tkinter.messagebox',
        'tkinter.filedialog',
        # Auto-extraction module
        'ridi_auto_extract',
        # Optional: PDF support
        'PyPDF2',
        # Optional: API fallback (gracefully fails if not installed)
        'browser_cookie3',
        'requests',
        'requests.adapters',
        'requests.auth',
        'urllib3',
        'certifi',
        'charset_normalizer',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='RidibooksDecryptor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,           # No console window — GUI only
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico',
    version_info=None,
)

# macOS app bundle (only used on macOS)
app = BUNDLE(
    exe,
    name='RidibooksDecryptor.app',
    icon='icon.ico',
    bundle_identifier='com.ridibooks.decryptor',
    info_plist={
        'CFBundleShortVersionString': '2.0.0',
        'NSHighResolutionCapable': 'True',
        'LSMinimumSystemVersion': '10.13.0',
    },
)
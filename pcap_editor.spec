# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['pcap_editor_gui.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['scapy.layers.all'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='PCAP编辑器',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='PCAP编辑器'
)

app = BUNDLE(
    coll,
    name='PCAP编辑器.app',
    bundle_identifier='com.pcapeditor.app',
    info_plist={
        'NSHighResolutionCapable': 'True',
        'LSBackgroundOnly': 'False',
        'CFBundleShortVersionString': '1.0.0',
    },
)
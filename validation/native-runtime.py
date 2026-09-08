"""Fork-only acceptance: native Python, ARM64 PE files, and LCMS DLL operations."""

import ctypes
import os
from pathlib import Path
import platform
import re
import struct
import sys

assert platform.machine().lower() in {"arm64", "aarch64"}, platform.machine()
prefix = Path(sys.prefix)
bindir = prefix / "Library" / "bin"
for filename in ("lcms2.dll", "jpgicc.exe", "tificc.exe", "linkicc.exe", "transicc.exe", "psicc.exe"):
    data = (bindir / filename).read_bytes()
    assert data[:2] == b"MZ", filename
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[offset:offset + 4] == b"PE\0\0", filename
    machine = struct.unpack_from("<H", data, offset + 4)[0]
    assert machine == 0xAA64, (filename, hex(machine))
    print(f"ARM64 PE: {filename}")

with os.add_dll_directory(str(bindir)):
    lcms = ctypes.CDLL(str(bindir / "lcms2.dll"))
    lcms.cmsGetEncodedCMMversion.restype = ctypes.c_int
    header = (prefix / "Library" / "include" / "lcms2.h").read_text()
    version = int(re.search(r"#define\s+LCMS_VERSION\s+(\d+)", header)[1])
    assert lcms.cmsGetEncodedCMMversion() == version
    lcms.cmsCreate_sRGBProfile.restype = ctypes.c_void_p
    lcms.cmsSaveProfileToMem.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    lcms.cmsSaveProfileToMem.restype = ctypes.c_int
    lcms.cmsCloseProfile.argtypes = [ctypes.c_void_p]
    lcms.cmsCloseProfile.restype = ctypes.c_int
    profile = lcms.cmsCreate_sRGBProfile()
    assert profile
    try:
        size = ctypes.c_uint32()
        assert lcms.cmsSaveProfileToMem(profile, None, ctypes.byref(size))
        assert size.value >= 128
        buffer = ctypes.create_string_buffer(size.value)
        assert lcms.cmsSaveProfileToMem(profile, buffer, ctypes.byref(size))
        assert buffer.raw[36:40] == b"acsp"
    finally:
        assert lcms.cmsCloseProfile(profile)
    print(f"Native ARM64 LCMS {version}: sRGB profile creation and ICC serialization passed")

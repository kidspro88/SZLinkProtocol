"""ctypes wrapper of c/sim/szfw_sim.c (the ESC update code with a RAM flash)."""

from __future__ import annotations

import ctypes
import os
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
C_DIR = os.path.join(HERE, "..", "c")
MONOCYPHER = os.path.join(HERE, "..", "..", "szlink", "c", "third_party", "monocypher")


def build(out_dir: str | None = None) -> str:
    out_dir = out_dir or tempfile.mkdtemp(prefix="szfw_sim")
    lib = os.path.join(out_dir, "libszfw_sim.so")
    subprocess.run(["cc", "-shared", "-fPIC", "-O1", "-Wall", "-Werror", f"-I{MONOCYPHER}",
                    os.path.join(C_DIR, "sim", "szfw_sim.c"), os.path.join(MONOCYPHER, "monocypher.c"),
                    "-o", lib], check=True)
    return lib


class SimFlash:
    def __init__(self, board_id: int, keys: list[bytes], installed_version: int = 0,
                 lib_path: str | None = None) -> None:
        self.lib = ctypes.CDLL(lib_path or build())
        u32p = ctypes.POINTER(ctypes.c_uint32)
        self.lib.sim_boot_command.argtypes = [ctypes.c_uint8, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_int,
                                              u32p, u32p]
        self.lib.sim_chunk.argtypes = [ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32, u32p]
        self.lib.sim_boot_command.restype = ctypes.c_uint8
        self.lib.sim_chunk.restype = ctypes.c_uint8
        self.lib.sim_installed_version.restype = ctypes.c_uint32
        self.lib.sim_app.restype = ctypes.c_uint32
        if self.lib.sim_init(board_id, b"".join(keys), len(keys), installed_version) != 0:
            raise ValueError("too many keys")

    def boot_command(self, command: int, header: bytes, busy: bool = False) -> tuple[int, int, int]:
        nxt, size = ctypes.c_uint32(), ctypes.c_uint32()
        st = self.lib.sim_boot_command(command, bytes(header), len(header), int(busy),
                                       ctypes.byref(nxt), ctypes.byref(size))
        return st, nxt.value, size.value

    def chunk(self, offset: int, data: bytes) -> tuple[int, int]:
        nxt = ctypes.c_uint32()
        st = self.lib.sim_chunk(offset, bytes(data), len(data), ctypes.byref(nxt))
        return st, nxt.value

    @property
    def installs(self) -> int:
        return self.lib.sim_installs()

    @property
    def installed_version(self) -> int:
        return self.lib.sim_installed_version()

    def app(self) -> bytes:
        buf = ctypes.create_string_buffer(512 * 1024)
        n = self.lib.sim_app(buf, len(buf))
        return buf.raw[:n]

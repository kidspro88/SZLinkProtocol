"""SZ-Link reference implementation for ground stations (Python).

Modules:
  crypto  - HMAC/HKDF-BLAKE2b, ChaCha20-Poly1305, Noise_IK handshake
  session - SecureLink: 30 s key ratchet, rekey, per-channel keys, anti-replay
  frame   - FrameCodec: SZ-Link frames with SEC/tag and optional video FEC
  ecc     - Reed-Solomon FEC envelope
  pairing - Ed25519 identities, SZ_PAIR_REQUEST/RESPONSE
"""

from .frame import Frame, FrameCodec  # noqa: F401
from .session import SecureLink  # noqa: F401
from . import pairing  # noqa: F401

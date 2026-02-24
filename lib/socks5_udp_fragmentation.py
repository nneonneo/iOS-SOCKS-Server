# lib/socks5_udp_fragmentation.py
"""SOCKS5 UDP fragmentation reassembly (client -> server).

This project historically rejected FRAG!=0 in SOCKS5 UDP datagrams. Some clients
may emit SOCKS-level fragmentation (RFC 1928). This module implements the
minimal, interoperable piece: reassembly of fragmented UDP datagrams arriving
from the client.

Notes:
- Only client->server reassembly is implemented.
- Server->client responses remain unfragmented at the SOCKS layer.
- A reassembly timer (>= 5s) is enforced, and state is reset when a new
  fragment arrives with FRAG less than the highest FRAG processed for the
  current sequence, per RFC 1928.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple


ReassemblyKey = Tuple[str, int, int, str, int]  # (client_ip, client_port, atyp, dst_host, dst_port)


@dataclass
class _ReassemblyState:
    start_ts: float
    highest_idx: int = 0
    last_idx: Optional[int] = None
    frags: Dict[int, bytes] = field(default_factory=dict)
    total_size: int = 0


class Socks5UdpFragmentReassembler:
    """Reassembles SOCKS5 UDP fragments (RFC 1928).

    FRAG field:
    - 0x00: not fragmented
    - 0x01..0x7F: fragment number within sequence
    - high-order bit (0x80): end-of-sequence marker
    """

    def __init__(
        self,
        *,
        timeout_seconds: float = 5.0,
        max_fragments: int = 127,
        max_total_size: int = 256 * 1024,
    ) -> None:
        # RFC 1928: timer MUST be no less than 5 seconds
        self._timeout = max(timeout_seconds, 5.0)
        self._max_frags = max_fragments
        self._max_total = max_total_size
        self._states: Dict[ReassemblyKey, _ReassemblyState] = {}

    @staticmethod
    def _parse_frag(frag: int) -> tuple[int, bool]:
        is_last = bool(frag & 0x80)
        idx = frag & 0x7F
        return idx, is_last

    def _expired(self, st: _ReassemblyState, now: float) -> bool:
        return (now - st.start_ts) > self._timeout

    def _reset(self, key: ReassemblyKey, now: float) -> _ReassemblyState:
        st = _ReassemblyState(start_ts=now)
        self._states[key] = st
        return st

    def cleanup(self) -> None:
        """Best-effort cleanup of expired states."""
        now = time.monotonic()
        dead = [k for k, st in self._states.items() if self._expired(st, now)]
        for k in dead:
            del self._states[k]

    def push_fragment(self, *, key: ReassemblyKey, frag: int, payload: bytes) -> Optional[bytes]:
        """Push one fragment and return reassembled payload when complete.

        payload is the DATA part of the SOCKS5 UDP datagram (header already consumed).
        """
        if frag == 0:
            return payload

        now = time.monotonic()
        idx, is_last = self._parse_frag(frag)

        # idx must be 1..127 for fragmented datagrams
        if idx <= 0 or idx > 127:
            return None

        st = self._states.get(key)
        if st is None or self._expired(st, now):
            st = self._reset(key, now)

        # RFC 1928: If a new datagram arrives with FRAG less than highest processed,
        # the queue is reset.
        if idx < st.highest_idx:
            st = self._reset(key, now)

        st.highest_idx = max(st.highest_idx, idx)

        # Abuse protection
        if len(st.frags) >= self._max_frags:
            self._reset(key, now)
            return None

        if idx not in st.frags:
            st.frags[idx] = payload
            st.total_size += len(payload)

        if st.total_size > self._max_total:
            self._reset(key, now)
            return None

        if is_last:
            st.last_idx = idx

        if st.last_idx is None:
            return None

        # Complete only when we have all fragments 1..last_idx
        last = st.last_idx
        for i in range(1, last + 1):
            if i not in st.frags:
                return None

        data = b"".join(st.frags[i] for i in range(1, last + 1))
        del self._states[key]
        return data

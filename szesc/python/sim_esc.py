#!/usr/bin/env python3
"""Simulated SpaceZet ESC on a DroneCAN bus, for ArduPilot simulation.

Answers spacezet.fw.BootCommand / FirmwareChunk with the real update code
(c/szfw.h through szfw_sim) on a RAM flash, so the flight controller's
firmware upload can be tested end to end:

  sim_esc.py --node 10 --board 1 --pubkey <hex> [--port mcast:0]

CAN bus 1 of the ArduPilot simulator is "mcast:0".
"""

from __future__ import annotations

import argparse
import os
import sys
import time

import dronecan

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import szfw  # noqa: E402
import szfw_sim  # noqa: E402

DSDL = os.path.join(HERE, "..", "dsdl", "spacezet")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--port", default="mcast:0")
    parser.add_argument("--node", type=int, default=10)
    parser.add_argument("--board", type=int, default=1)
    parser.add_argument("--pubkey", action="append", default=[], help="trusted key (hex), key_id order")
    parser.add_argument("--version", type=lambda v: int(v, 0), default=0, help="installed firmware version")
    parser.add_argument("--busy", action="store_true", help="behave as if the motor is running")
    parser.add_argument("--duration", type=float, default=0, help="exit after this many seconds")
    args = parser.parse_args()

    esc = szfw_sim.SimFlash(args.board, [bytes.fromhex(k) for k in args.pubkey], args.version)
    dronecan.load_dsdl(DSDL)
    info = dronecan.uavcan.protocol.GetNodeInfo.Response()
    info.name = "com.spacezet.esc.sim"
    info.software_version.major = (esc.installed_version >> 16) & 0xFF
    node = dronecan.make_node(args.port, node_id=args.node, bitrate=1000000, node_info=info)
    node.health = dronecan.uavcan.protocol.NodeStatus().HEALTH_OK
    node.mode = dronecan.uavcan.protocol.NodeStatus().MODE_OPERATIONAL
    fw = dronecan.thirdparty.spacezet.fw  # codespell:ignore thirdparty

    def on_boot(event):
        req = event.request
        st, nxt, size = esc.boot_command(req.command, bytes(req.header), args.busy)
        print(f"BootCommand {req.command} -> {szfw.STATUS_NAMES[st]} next {nxt}/{size}", flush=True)
        if req.command == szfw.COMMAND_COMMIT and st == szfw.STATUS_OK:
            print(f"INSTALLED version 0x{esc.installed_version:08x} size {len(esc.app())} "
                  f"installs {esc.installs}", flush=True)
        return fw.BootCommand.Response(status=st, next_offset=nxt, body_size=size)

    def on_chunk(event):
        req = event.request
        st, nxt = esc.chunk(req.offset, bytes(req.data))
        if st != szfw.STATUS_OK:
            print(f"FirmwareChunk {req.offset}+{len(req.data)} -> {szfw.STATUS_NAMES[st]}", flush=True)
        return fw.FirmwareChunk.Response(status=st, next_offset=nxt)

    node.add_handler(fw.BootCommand, on_boot)
    node.add_handler(fw.FirmwareChunk, on_chunk)
    print(f"sim ESC node {args.node} board {args.board} on {args.port}", flush=True)
    t_end = time.time() + args.duration if args.duration else None
    while t_end is None or time.time() < t_end:
        try:
            node.spin(0.1)
        except dronecan.transport.TransferError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())

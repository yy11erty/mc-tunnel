"""
MC Tunnel - 服务端
==================
公网服务器，等待内网客户端连接并转发玩家流量。

用法:
  python server.py                # 从 config.json 加载
  python server.py --key <密钥>   # 首次运行指定密钥
"""

import asyncio
import argparse
import os
import sys
import time
import uuid
from typing import Optional, Tuple

from protocol import (
    CMD_NEW_CONN, CMD_DATA, CMD_CLOSE, READ_CHUNK,
    setup_logging, read_frame, write_frame,
    generate_rsa_keypair, save_rsa_key, load_rsa_key, pubkey_to_str,
    server_authenticate, derive_crypto,
    load_config, save_config,
)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(SCRIPT_DIR, "config.json")
DEFAULT_KEY_FILE = os.path.join(SCRIPT_DIR, "server_key.json")


class TunnelState:
    def __init__(self):
        self.ready = asyncio.Event()
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.backend_port: Optional[int] = None
        self.tunnel_id: str = uuid.uuid4().hex[:12]
        self.created_at: float = 0.0
        self.active_players: int = 0
        self.total_players: int = 0
        self.next_conn_id: int = 1
        self.sessions: dict = {}
        self.crypto = None
        self.write_lock = asyncio.Lock()


class Server:
    def __init__(self, control_port, player_port,
                 control_host="0.0.0.0", player_host="0.0.0.0",
                 key_file=DEFAULT_KEY_FILE):
        self.control_port = control_port
        self.player_port = player_port
        self.control_host = control_host
        self.player_host = player_host
        self.key_file = key_file
        self.log = setup_logging("server", os.path.join(SCRIPT_DIR, "server.log"))
        self.tunnel = TunnelState()

    def _load_or_generate_key(self):
        if os.path.exists(self.key_file):
            self.pubkey, self.privkey = load_rsa_key(self.key_file)
            self.log.info("Loaded RSA key from %s", self.key_file)
        else:
            self.log.info("Generating RSA key pair ...")
            self.pubkey, self.privkey = generate_rsa_keypair()
            save_rsa_key(self.key_file, self.pubkey, self.privkey)
            self.log.info("RSA key saved to %s", self.key_file)
        print()
        print("  服务器公钥 (复制到客户端 config.json 的 server_pubkey):")
        print(f"  {pubkey_to_str(self.pubkey)}")
        print()

    async def _handle_control(self, reader, writer):
        peer = writer.get_extra_info("peername")
        self.log.info("Control connection from %s:%s", peer[0], peer[1])
        try:
            session_key = await server_authenticate(reader, writer, self.privkey, self.pubkey)
        except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
            self.log.warning("Client disconnected during auth")
            writer.close()
            return
        if session_key is None:
            self.log.warning("Auth FAILED from %s:%s", peer[0], peer[1])
            writer.close()
            return
        self.log.info("Auth success from %s:%s", peer[0], peer[1])

        crypto = derive_crypto(session_key, is_server=True)
        try:
            cmd, _, port_bytes = await asyncio.wait_for(read_frame(reader, crypto), timeout=10)
        except asyncio.TimeoutError:
            writer.close()
            return
        if cmd != CMD_DATA:
            writer.close()
            return
        try:
            backend_port = int(port_bytes.decode().strip())
        except (ValueError, UnicodeDecodeError):
            writer.close()
            return

        self.tunnel.reader = reader
        self.tunnel.writer = writer
        self.tunnel.backend_port = backend_port
        self.tunnel.created_at = time.time()
        self.tunnel.crypto = crypto
        self.tunnel.sessions.clear()
        self.tunnel.next_conn_id = 1
        self.tunnel.ready.set()
        self.log.info("Tunnel %s registered for port %d (encrypted)", self.tunnel.tunnel_id, backend_port)

        try:
            await self._frame_loop(reader, crypto)
        finally:
            self.log.info("Tunnel %s closed (served %d players)", self.tunnel.tunnel_id, self.tunnel.total_players)
            for s in self.tunnel.sessions.values():
                s["out_queue"].put_nowait(None)
                if s["writer"] and not s["writer"].is_closing():
                    s["writer"].close()
            self.tunnel.sessions.clear()
            self.tunnel.ready.clear()
            self.tunnel.reader = None
            self.tunnel.writer = None
            self.tunnel.crypto = None
            writer.close()

    async def _frame_loop(self, reader, crypto):
        try:
            while True:
                cmd, conn_id, payload = await read_frame(reader, crypto)
                if cmd == CMD_DATA:
                    s = self.tunnel.sessions.get(conn_id)
                    if s:
                        s["rx_bytes"] += len(payload)
                        s["out_queue"].put_nowait(payload)
                elif cmd == CMD_CLOSE:
                    s = self.tunnel.sessions.get(conn_id)
                    if s:
                        self.log.info("Tunnel CLOSE conn_id=%d", conn_id)
                        s["out_queue"].put_nowait(None)
                        del self.tunnel.sessions[conn_id]
        except (asyncio.IncompleteReadError, ConnectionResetError):
            self.log.info("Tunnel disconnected")

    async def _handle_player(self, reader, writer):
        peer = writer.get_extra_info("peername")
        self.log.info("Player from %s:%s", peer[0], peer[1])
        if not self.tunnel.ready.is_set():
            writer.close()
            return
        tw = self.tunnel.writer
        crypto = self.tunnel.crypto
        if tw is None or tw.is_closing() or crypto is None:
            writer.close()
            return

        conn_id = self.tunnel.next_conn_id
        self.tunnel.next_conn_id += 1
        self.tunnel.active_players += 1
        self.tunnel.total_players += 1
        session = {"writer": writer, "tx_bytes": 0, "rx_bytes": 0,
                   "out_queue": asyncio.Queue(), "start_time": time.time()}
        self.tunnel.sessions[conn_id] = session
        self.log.info("Player %s:%s -> conn_id=%d", peer[0], peer[1], conn_id)

        try:
            await write_frame(tw, CMD_NEW_CONN, conn_id, crypto=crypto, lock=self.tunnel.write_lock)
        except (ConnectionResetError, OSError):
            writer.close()
            self.tunnel.active_players -= 1
            del self.tunnel.sessions[conn_id]
            return

        t1 = asyncio.create_task(self._p2t(reader, tw, conn_id, session, crypto))
        t2 = asyncio.create_task(self._t2p(writer, session))
        done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
            try: await t
            except asyncio.CancelledError: pass

        try:
            await write_frame(tw, CMD_CLOSE, conn_id, crypto=crypto, lock=self.tunnel.write_lock)
        except (ConnectionResetError, OSError): pass
        if not writer.is_closing(): writer.close()
        self.tunnel.active_players -= 1
        if conn_id in self.tunnel.sessions: del self.tunnel.sessions[conn_id]
        elapsed = time.time() - session["start_time"]
        self.log.info("Player conn_id=%d done, rx=%d tx=%d %.1fs", conn_id, session["rx_bytes"], session["tx_bytes"], elapsed)

    async def _p2t(self, reader, tw, conn_id, session, crypto):
        try:
            while True:
                data = await reader.read(READ_CHUNK)
                if not data: break
                session["tx_bytes"] += len(data)
                await write_frame(tw, CMD_DATA, conn_id, data, crypto=crypto, lock=self.tunnel.write_lock)
        except (asyncio.IncompleteReadError, ConnectionResetError, OSError): pass

    async def _t2p(self, writer, session):
        try:
            while True:
                data = await session["out_queue"].get()
                if data is None: break
                writer.write(data)
                await writer.drain()
        except (ConnectionResetError, OSError): pass

    async def run(self):
        self._load_or_generate_key()
        ctrl = await asyncio.start_server(self._handle_control, self.control_host, self.control_port)
        player = await asyncio.start_server(self._handle_player, self.player_host, self.player_port)
        self.log.info("Control on %s:%d", self.control_host, self.control_port)
        self.log.info("Player  on %s:%d", self.player_host, self.player_port)
        async with ctrl, player:
            await asyncio.gather(ctrl.serve_forever(), player.serve_forever())


def main():
    parser = argparse.ArgumentParser(description="MC Tunnel - 服务端")
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument("--key-file", default=DEFAULT_KEY_FILE)
    parser.add_argument("--control-port", type=int, default=None)
    parser.add_argument("--player-port", type=int, default=None)
    parser.add_argument("--control-host", default=None)
    parser.add_argument("--player-host", default=None)
    args = parser.parse_args()

    config = {}
    if os.path.exists(args.config):
        try:
            config = load_config(args.config)
        except (json.JSONDecodeError, OSError):
            pass

    if args.control_port: config["control_port"] = args.control_port
    if args.player_port: config["player_port"] = args.player_port
    if args.control_host: config["control_host"] = args.control_host
    if args.player_host: config["player_host"] = args.player_host

    config.setdefault("control_port", 9000)
    config.setdefault("player_port", 25565)
    config.setdefault("control_host", "0.0.0.0")
    config.setdefault("player_host", "0.0.0.0")

    if not os.path.exists(args.config):
        save_config(args.config, config)
        print(f"  [i] 配置已保存到 {args.config}")

    server = Server(
        control_port=config["control_port"],
        player_port=config["player_port"],
        control_host=config["control_host"],
        player_host=config["player_host"],
        key_file=args.key_file,
    )
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        print("\nServer stopped.")


if __name__ == "__main__":
    main()

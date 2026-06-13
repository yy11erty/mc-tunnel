"""
MC Tunnel - 客户端
==================
内网客户端，连接公网服务器，将本地 MC 服务暴露到公网。

用法:
  python client.py              # 从 config.json 加载
  python client.py --key <密钥> --server-host <IP> --target-port <端口>
"""

import asyncio
import argparse
import os
import sys
import time
from typing import Optional

from protocol import (
    CMD_NEW_CONN, CMD_DATA, CMD_CLOSE, READ_CHUNK,
    setup_logging, read_frame, write_frame,
    load_rsa_pubkey, client_authenticate, derive_crypto,
    load_config, save_config,
)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(SCRIPT_DIR, "config.json")


class Client:
    def __init__(self, server_host, control_port, target_port,
                 server_pubkey, auto_reconnect=True, max_reconnect_delay=60):
        self.server_host = server_host
        self.control_port = control_port
        self.target_port = target_port
        self.server_pubkey = server_pubkey
        self.auto_reconnect = auto_reconnect
        self.max_reconnect_delay = max_reconnect_delay
        self.log = setup_logging("client", os.path.join(SCRIPT_DIR, "client.log"))
        self.sessions: dict = {}
        self._running = True
        self._write_lock = asyncio.Lock()

    async def _fwd_l2t(self, reader, conn_id, tw, counter, crypto):
        try:
            while True:
                data = await reader.read(READ_CHUNK)
                if not data: break
                counter["tx"] += len(data)
                await write_frame(tw, CMD_DATA, conn_id, data, crypto=crypto, lock=self._write_lock)
        except (asyncio.IncompleteReadError, ConnectionResetError, OSError): pass

    async def _drain(self, writer, queue, counter):
        try:
            while True:
                data = await queue.get()
                if data is None: break
                counter["rx"] += len(data)
                writer.write(data)
                await writer.drain()
        except (ConnectionResetError, OSError): pass

    async def _handle_conn(self, conn_id, tw, crypto):
        self.log.info("[conn:%d] NEW -> 127.0.0.1:%d", conn_id, self.target_port)
        queue = asyncio.Queue()
        self.sessions[conn_id] = {"out_queue": queue, "writer": None}
        try:
            lr, lw = await asyncio.open_connection("127.0.0.1", self.target_port)
        except OSError as e:
            self.log.error("[conn:%d] Cannot connect to MC port %d: %s", conn_id, self.target_port, e)
            del self.sessions[conn_id]
            try: await write_frame(tw, CMD_CLOSE, conn_id, crypto=crypto, lock=self._write_lock)
            except: pass
            return
        self.sessions[conn_id]["writer"] = lw
        counter = {"rx": 0, "tx": 0}
        t0 = time.time()

        t1 = asyncio.create_task(self._fwd_l2t(lr, conn_id, tw, counter, crypto))
        t2 = asyncio.create_task(self._drain(lw, queue, counter))
        done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
            try: await t
            except asyncio.CancelledError: pass
        if not lw.is_closing(): lw.close()
        if conn_id in self.sessions: del self.sessions[conn_id]
        self.log.info("[conn:%d] Closed rx=%d tx=%d %.1fs", conn_id, counter["rx"], counter["tx"], time.time() - t0)
        try: await write_frame(tw, CMD_CLOSE, conn_id, crypto=crypto, lock=self._write_lock)
        except: pass

    async def _dispatch(self, reader, writer, crypto):
        try:
            while True:
                cmd, conn_id, payload = await read_frame(reader, crypto)
                if cmd == CMD_NEW_CONN:
                    asyncio.create_task(self._handle_conn(conn_id, writer, crypto))
                elif cmd == CMD_DATA:
                    s = self.sessions.get(conn_id)
                    if s: s["out_queue"].put_nowait(payload)
                elif cmd == CMD_CLOSE:
                    s = self.sessions.get(conn_id)
                    if s: s["out_queue"].put_nowait(None)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            self.log.info("Tunnel disconnected")

    async def _connect(self):
        self.log.info("Connecting to %s:%d ...", self.server_host, self.control_port)
        try:
            reader, writer = await asyncio.open_connection(self.server_host, self.control_port)
        except OSError as e:
            self.log.error("Connection failed: %s", e)
            return None
        session_key = await client_authenticate(reader, writer, self.server_pubkey)
        if session_key is None:
            self.log.error("Auth failed (wrong key or server identity)")
            writer.close()
            return None
        self.log.info("Server identity verified, session key established")
        crypto = derive_crypto(session_key, is_server=False)
        await write_frame(writer, CMD_DATA, 0, str(self.target_port).encode(), crypto=crypto)
        return reader, writer, crypto

    async def run(self):
        delay = 1
        while self._running:
            result = await self._connect()
            if result is None:
                if not self.auto_reconnect:
                    self.log.error("Failed, auto-reconnect disabled.")
                    return
                self.log.info("Reconnecting in %ds ...", delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, self.max_reconnect_delay)
                continue
            reader, writer, crypto = result
            delay = 1
            self.sessions.clear()
            self.log.info("Tunnel active, waiting for players ...")
            try:
                await self._dispatch(reader, writer, crypto)
            except asyncio.CancelledError: pass
            finally:
                for s in self.sessions.values():
                    s["out_queue"].put_nowait(None)
                    if s["writer"] and not s["writer"].is_closing(): s["writer"].close()
                self.sessions.clear()
                writer.close()
            if not self.auto_reconnect:
                self.log.info("Session ended, auto-reconnect disabled.")
                return
            self.log.info("Disconnected, reconnecting in %ds ...", delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, self.max_reconnect_delay)


def interactive_setup():
    print()
    print("=" * 50)
    print("  MC Tunnel - 客户端配置向导")
    print("=" * 50)
    print()
    config = {}
    while True:
        h = input("公网服务器 IP: ").strip()
        if h:
            config["server_host"] = h
            break
        print("  [!] 不能为空")
    p = input("端口 [9000]: ").strip()
    config["control_port"] = int(p) if p else 9000
    while True:
        pk = input("服务器公钥 (e:n): ").strip()
        if pk and ":" in pk:
            config["server_pubkey"] = pk
            break
        print("  [!] 格式: e:n")
    save_config(DEFAULT_CONFIG, config)
    print(f"\n  已保存到 {DEFAULT_CONFIG}\n")
    return config


def main():
    parser = argparse.ArgumentParser(description="MC Tunnel - 客户端")
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument("--server-host", default=None)
    parser.add_argument("--control-port", type=int, default=None)
    parser.add_argument("--target-port", type=int, default=None)
    parser.add_argument("--no-reconnect", action="store_true")
    parser.add_argument("--no-interactive", action="store_true")
    args = parser.parse_args()

    config = {}
    if os.path.exists(args.config):
        try:
            config = load_config(args.config)
            print(f"  [i] 已加载: {args.config}")
        except: pass

    if args.server_host: config["server_host"] = args.server_host
    if args.control_port: config["control_port"] = args.control_port
    config.setdefault("control_port", 9000)

    need_interactive = (
        not args.no_interactive
        and any(k not in config for k in ("server_host", "server_pubkey"))
    )
    if need_interactive:
        config.update(interactive_setup())

    missing = [k for k in ("server_host", "server_pubkey") if k not in config]
    if missing:
        print(f"  [!] 缺少: {', '.join(missing)}")
        sys.exit(1)

    # 每次启动询问本地 MC 端口
    if args.target_port:
        config["target_port"] = args.target_port
    else:
        while True:
            p = input("本地 MC 端口: ").strip()
            try:
                config["target_port"] = int(p)
                if 1 <= config["target_port"] <= 65535: break
                print("  [!] 1-65535")
            except ValueError:
                print("  [!] 数字")

    try:
        server_pubkey = load_rsa_pubkey(config["server_pubkey"])
    except:
        print("  [!] server_pubkey 格式错误")
        sys.exit(1)

    print()
    print("=" * 50)
    print("  MC Tunnel - 客户端")
    print("=" * 50)
    print(f"  服务器  : {config['server_host']}:{config['control_port']}")
    print(f"  本地 MC : {config['target_port']}")
    print("=" * 50)
    print()

    client = Client(
        server_host=config["server_host"],
        control_port=config["control_port"],
        target_port=config["target_port"],
        server_pubkey=server_pubkey,
        auto_reconnect=not args.no_reconnect,
    )
    try:
        asyncio.run(client.run())
    except KeyboardInterrupt:
        print("\nClient stopped.")


if __name__ == "__main__":
    main()

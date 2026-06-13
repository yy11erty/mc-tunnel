"""
MC Tunnel - 共享协议模块
帧协议、RSA、加密、认证
"""

import asyncio
import hashlib
import hmac as hmac_mod
import json
import logging
import secrets
import struct
import sys
import time
from typing import Optional, Tuple

# 帧协议
CMD_NEW_CONN = 0x01
CMD_DATA     = 0x02
CMD_CLOSE    = 0x03
FRAME_HEADER_FMT = "!BII"
FRAME_HEADER_SIZE = struct.calcsize(FRAME_HEADER_FMT)
READ_CHUNK = 65536
NONCE_SIZE = 16


def setup_logging(name: str, log_file: Optional[str] = None) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


async def read_frame(reader: asyncio.StreamReader, crypto=None):
    header = await reader.readexactly(FRAME_HEADER_SIZE)
    cmd, conn_id, length = struct.unpack(FRAME_HEADER_FMT, header)
    payload = b""
    if length > 0:
        payload = await reader.readexactly(length)
        if crypto is not None:
            payload = crypto.decrypt(payload)
    return cmd, conn_id, payload


async def write_frame(writer: asyncio.StreamWriter, cmd: int, conn_id: int,
                      payload: bytes = b"", crypto=None, lock: asyncio.Lock = None):
    raw_payload = payload
    if lock is not None:
        async with lock:
            if crypto is not None and raw_payload:
                encrypted = crypto.encrypt(raw_payload)
            else:
                encrypted = raw_payload
            header = struct.pack(FRAME_HEADER_FMT, cmd, conn_id, len(encrypted))
            writer.write(header + encrypted)
            await writer.drain()
    else:
        if crypto is not None and payload:
            payload = crypto.encrypt(payload)
        header = struct.pack(FRAME_HEADER_FMT, cmd, conn_id, len(payload))
        writer.write(header + payload)
        await writer.drain()


# ===========================================================================
# RSA
# ===========================================================================

RSA_BITS = 2048
RSA_E = 65537


def _is_probable_prime(n: int, rounds: int = 20) -> bool:
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1: continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    while True:
        n = secrets.randbits(bits)
        n |= (1 << (bits - 1)) | 1
        if _is_probable_prime(n):
            return n


def _mod_inverse(e: int, phi: int) -> int:
    g, x, _ = _extended_gcd(e, phi)
    if g != 1: raise ValueError("No modular inverse")
    return x % phi


def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0: return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def generate_rsa_keypair():
    half = RSA_BITS // 2
    while True:
        p = _generate_prime(half)
        q = _generate_prime(half)
        if p == q: continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % RSA_E == 0: continue
        d = _mod_inverse(RSA_E, phi)
        return (RSA_E, n), (d, n)


def rsa_sign(privkey, data: bytes) -> int:
    d, n = privkey
    h = int.from_bytes(hashlib.sha256(data).digest(), "big")
    return pow(h, d, n)


def rsa_verify(pubkey, data: bytes, signature: int) -> bool:
    e, n = pubkey
    h = int.from_bytes(hashlib.sha256(data).digest(), "big")
    return pow(signature, e, n) == h


def rsa_encrypt(pubkey, data: bytes) -> bytes:
    e, n = pubkey
    m = int.from_bytes(data, "big")
    c = pow(m, e, n)
    return c.to_bytes((n.bit_length() + 7) // 8, "big")


def rsa_decrypt(privkey, data: bytes) -> bytes:
    d, n = privkey
    c = int.from_bytes(data, "big")
    m = pow(c, d, n)
    return m.to_bytes(32, "big")


def save_rsa_key(path: str, pubkey, privkey):
    with open(path, "w") as f:
        json.dump({"e": str(pubkey[0]), "n": str(pubkey[1]), "d": str(privkey[0])}, f)


def load_rsa_key(path: str):
    with open(path, "r") as f:
        data = json.load(f)
    e, n, d = int(data["e"]), int(data["n"]), int(data["d"])
    return (e, n), (d, n)


def load_rsa_pubkey(pubkey_str: str):
    parts = pubkey_str.split(":")
    return int(parts[0]), int(parts[1])


def pubkey_to_str(pubkey) -> str:
    return f"{pubkey[0]}:{pubkey[1]}"


# ===========================================================================
# 加密
# ===========================================================================

class StreamCipher:
    def __init__(self, key: bytes, nonce: bytes):
        self.key = key
        self.nonce = nonce
        self.counter = 0

    def _keystream_block(self, counter: int) -> bytes:
        return hashlib.sha256(self.key + self.nonce + counter.to_bytes(8, "big")).digest()

    def encrypt(self, plaintext: bytes) -> bytes:
        if not plaintext: return b""
        result = bytearray()
        offset = 0
        while offset < len(plaintext):
            block = self._keystream_block(self.counter)
            chunk = plaintext[offset:offset + 32]
            result.extend(a ^ b for a, b in zip(chunk, block))
            offset += 32
            self.counter += 1
        return bytes(result)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.encrypt(ciphertext)


class TunnelCrypto:
    def __init__(self, send_cipher: StreamCipher, recv_cipher: StreamCipher):
        self.send_cipher = send_cipher
        self.recv_cipher = recv_cipher

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.send_cipher.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.recv_cipher.decrypt(ciphertext)


def derive_crypto(session_key: bytes, is_server: bool) -> TunnelCrypto:
    prk = hmac_mod.new(b"mc_tunnel_kdf", session_key, hashlib.sha256).digest()
    key_s = hmac_mod.new(prk, b"server_send_key", hashlib.sha256).digest()
    nonce_s = hmac_mod.new(prk, b"server_send_nonce", hashlib.sha256).digest()[:16]
    key_c = hmac_mod.new(prk, b"client_send_key", hashlib.sha256).digest()
    nonce_c = hmac_mod.new(prk, b"client_send_nonce", hashlib.sha256).digest()[:16]
    if is_server:
        return TunnelCrypto(StreamCipher(key_s, nonce_s), StreamCipher(key_c, nonce_c))
    else:
        return TunnelCrypto(StreamCipher(key_c, nonce_c), StreamCipher(key_s, nonce_s))


# ===========================================================================
# 认证 + 密钥交换
# ===========================================================================

async def server_authenticate(reader, writer, privkey, pubkey):
    """
    服务端认证 + 接收会话密钥。
    返回会话密钥(bytes) 或 None。
    """
    nonce = secrets.token_bytes(NONCE_SIZE)
    sig = rsa_sign(privkey, nonce)
    writer.write(f"nonce:{nonce.hex()}\n".encode())
    writer.write(f"sig:{sig}\n".encode())
    await writer.drain()

    try:
        line = await asyncio.wait_for(reader.readline(), timeout=15)
    except asyncio.TimeoutError:
        return None
    line = line.decode().strip()
    if not line.startswith("key:"):
        return None

    # 客户端用公钥加密的会话密钥
    enc_key = bytes.fromhex(line[4:])
    session_key = rsa_decrypt(privkey, enc_key)
    writer.write(b"ok\n")
    await writer.drain()
    return session_key


async def client_authenticate(reader, writer, pubkey):
    """
    客户端验证服务端身份 + 发送会话密钥。
    返回会话密钥(bytes) 或 None。
    """
    try:
        nonce_line = await asyncio.wait_for(reader.readline(), timeout=15)
        sig_line = await asyncio.wait_for(reader.readline(), timeout=5)
    except asyncio.TimeoutError:
        return None

    nonce_line = nonce_line.decode().strip()
    sig_line = sig_line.decode().strip()
    if not nonce_line.startswith("nonce:") or not sig_line.startswith("sig:"):
        return None

    nonce_hex = nonce_line[6:]
    sig = int(sig_line[4:])
    if not rsa_verify(pubkey, bytes.fromhex(nonce_hex), sig):
        return None

    # 生成随机会话密钥，用服务端公钥加密
    session_key = secrets.token_bytes(32)
    enc_key = rsa_encrypt(pubkey, session_key)
    writer.write(f"key:{enc_key.hex()}\n".encode())
    await writer.drain()

    try:
        resp = await asyncio.wait_for(reader.readline(), timeout=10)
    except asyncio.TimeoutError:
        return None
    if resp.decode().strip() != "ok":
        return None

    return session_key


# ===========================================================================
# 配置
# ===========================================================================

def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(path: str, config: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

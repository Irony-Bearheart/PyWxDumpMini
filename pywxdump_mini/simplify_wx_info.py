# -*- coding: utf-8 -*-#
# -------------------------------------------------------------------------------
# Name:         simplify_wx_info.py
# Description:  
# Author:       xaoyaoo
# Date:         2023/12/07
# -------------------------------------------------------------------------------
from os import path
import hmac
import hashlib
from collections import Counter
import logging
from dataclasses import dataclass
from functools import cache
from sys import platform
from enum import StrEnum, auto, verify, UNIQUE
from json import JSONEncoder

from pymem import Pymem
from pymem.exception import ProcessNotFound, MemoryReadError

assert platform == 'win32', 'Run on Windows only'

ZERO_BYTE: bytes = b"\x00"


@verify(UNIQUE)
class PhoneTypes(StrEnum):
    ANDROID = auto()
    IPHONE = auto()
    IPAD = auto()


@dataclass
class WeChatDBKeyAndPath:
    key: str
    db_path: str

    def __hash__(self):
        return hash(self.db_path)


class WeChatDBJSONEncoder(JSONEncoder):
    def default(self, o):
        if isinstance(o, WeChatDBKeyAndPath):
            return dict(key=o.key, db_path=o.db_path)


def lookfor_db_path(process: Pymem, pattern: bytes, range_: int = 128) -> Counter[bytes, int] | Counter:
    counter = Counter()

    pattern_addresses: list[int] | None = process.pattern_scan_all(pattern, return_multiple=True)
    if pattern_addresses is None:
        raise RuntimeError(f"Can't find pattern {pattern} in process {process.process_base.name}")

    for pattern_start_address in pattern_addresses:
        pattern_end_address = \
            (
                    pattern_start_address
                    + (
                            len(pattern) - int(pattern.count(b"\\") / 2)
                        # real length for pattern, as \ must be "\\" in bytes object `pattern`, whose length == 2
                    )
            )

        array = process.read_bytes(pattern_end_address - range_, range_)
        try:
            start: int = array.rindex(ZERO_BYTE)
        except ValueError:
            continue

        db_dir: bytes = array[start + len(ZERO_BYTE):]
        if path.isdir(db_dir):  # sometimes we will find some pieces of memory that matches with pattern, but they
            # may be wrongly cut or other pieces that does not contain path
            counter[db_dir] += 1

    return counter


def get_key(process: Pymem, db_path: str, arch: int, user_space_limit: int) -> str:
    def read_key_bytes(process_: Pymem, address: int, key_len: int = 32) -> bytes | None:
        try:
            key = process_.read_bytes(
                int.from_bytes(
                    process_.read_bytes(
                        address, int(arch / 8)
                    ),
                    byteorder='little', signed=False
                ),  # get key address from memory
                key_len
            )
        except MemoryReadError:
            return None
        return key

    @cache
    def _load_digest(wx_db_path, page_size=4096):
        with open(wx_db_path, "rb") as file:
            blist = file.read(5000)
        salt = blist[:16]
        first = blist[16:page_size]
        mac_salt = bytes([(byte ^ 0b111010) for byte in salt])
        return first, mac_salt, salt

    def verify_key(key, wx_db_path, key_size: int = 32, iteration: int = 64000):
        first, mac_salt, salt = _load_digest(wx_db_path)
        byte_key = hashlib.pbkdf2_hmac("sha1", key, salt, iteration, key_size)
        mac_key = hashlib.pbkdf2_hmac("sha1", byte_key, mac_salt, 2, key_size)
        hash_mac = hmac.new(mac_key, first[:-32], hashlib.sha1)
        hash_mac.update(b'\x01\x00\x00\x00')
        return hash_mac.digest() == first[-32:-12]

    assert arch in {32, 64}, "arch must be 32 or 64"

    message_log_path = path.join(db_path, "MicroMsg.db")

    for phone_type in PhoneTypes:
        memory_address_for_phone: list[int] | None \
            = process.pattern_scan_module(str(phone_type + "\x00").encode(),
                                          "WeChatWin.dll",
                                          return_multiple=True)
        if len(memory_address_for_phone) >= 1:
            addr = memory_address_for_phone[1]
            while 0 < addr < user_space_limit:
                key_bytes: bytes | None = read_key_bytes(process, addr)
                if key_bytes is None or verify_key(key_bytes, message_log_path) is False:
                    addr -= int(arch / 8)
                else:
                    return key_bytes.hex()

    raise RuntimeError


def read_db_dir_and_key():
    try:
        wechat = Pymem("WeChat.exe", exact_match=True)
    except ProcessNotFound:
        logging.exception("WeChat.exe not found")
        raise RuntimeError("WeChat.exe not found")

    else:
        try:
            WX_ARCH = 64 if wechat.is_64_bit else 32  # noqa N806
            logging.info(
                f"Got WeChat process: {wechat.process_base.name} "
                f"(Process {wechat.process_id} with handle {wechat.process_handle}, {WX_ARCH} bits)"
            )

            USER_SPACE_LIMIT: int = 0x7FFFFFFF0000 if wechat.is_64_bit else 0x7FFF0000

            db_dir_str: str = lookfor_db_path(wechat, br"\\Msg\\").most_common(1)[0][0].decode()
            key: str = get_key(wechat, db_dir_str, WX_ARCH, USER_SPACE_LIMIT)
            db_dir_and_key = WeChatDBKeyAndPath(key=key, db_path=path.join(db_dir_str, "MicroMsg.db"))
        finally:
            wechat.close_process()

        return db_dir_and_key


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    info: WeChatDBKeyAndPath = read_db_dir_and_key()
    print(WeChatDBJSONEncoder().encode(info))

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HarmonyOS HAP 签名工具（纯 Python 实现）。

子命令：
  login       DevEco IDE OAuth：本地 8888 端口接 tempToken → authrouter 换 jwtToken
  init        生成密钥/CSR → 华为 API 注册设备、签发调试证书、申请调试 Profile
  sign        本地完成 sign-app（HAP 签名方案 v3 + code sign block + permission sign block）
  install     hdc 安装签名产物到设备
  signinstall 签名后直接安装，产物固定写 data/signed.hap（重复执行覆盖，磁盘只留一份）
  status      查看凭证与材料状态

目录约定：
  res/   预置二进制（hdc、libusb_shared.so），随仓库分发，只读
  data/  运行期产生的全部数据（密钥、证书、Profile、凭证、缓存）

依赖：Python3 标准库 + openssl 命令行。签名算法不依赖 java / jar。
签名实现与 developtools_hapsigner（Apache-2.0）的 sign-app -mode localSign 字节等价。
"""

import argparse
import base64
import datetime
import gzip
import hashlib
import http.server
import json
import os
import re
import secrets
import shutil
import ssl
import string
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# ============================================================ 路径与常量

ROOT = Path(__file__).resolve().parent
RES_DIR = ROOT / "res"  # 预置材料（随仓库分发）
DATA_DIR = Path(os.environ.get("HAP_SIGN_DATA") or (ROOT / "data"))  # 运行期数据

AUTH_FILE = DATA_DIR / "auth.json"
CONF_FILE = DATA_DIR / "config.json"
KEY_FILE = DATA_DIR / "hinstall.key"
CSR_FILE = DATA_DIR / "hinstall.csr"
CER_FILE = DATA_DIR / "hinstall-debug.cer"
P12_FILE = DATA_DIR / "hinstall.p12"
P7B_FILE = DATA_DIR / "debug-profile.p7b"

# DevEco IDE 客户端标识（与官方 IDE 一致，服务端按此识别）
AUTH_ROUTER = "https://cn.devecostudio.huawei.com/authrouter/auth/api"
APPLY_URL = (
    "https://cn.devecostudio.huawei.com/console/DevEcoIDE/apply"
    "?port=8888&appid=1007&code=20698961dd4f420c8b44f49010c6f0cc"
)
CONNECT_API = "https://connect-api.cloud.huawei.com/api"
CALLBACK_PORT = 8888
KEY_ALIAS = "hinstall"
CERT_NAME = "quantum-debug"
SIGN_ALG = "SHA256withECDSA"

# 签名方案常量（与 SignHap / ParamConstants 对齐）
HAP_SIGNATURE_SCHEME_V1_BLOCK_ID = 0x20000000
HAP_PROOF_OF_ROTATION_BLOCK_ID = 0x20000001
HAP_PROFILE_BLOCK_ID = 0x20000002
HAP_PROPERTY_BLOCK_ID = 0x20000003
ENTERPRISE_RE_SIGN_BLOCK_ID = 0x20000004
ENTERPRISE_CODE_RE_SIGN_BLOCK_ID = 0x20000005
HAP_CODE_SIGN_BLOCK_ID = 0x30000001
HAP_PERMISSION_SIGN_BLOCK_ID = 0x30000002

HAP_SIGN_BLOCK_MAGIC_V2 = b"HAP Sig Block 42"
HAP_SIGN_BLOCK_MAGIC_V3 = b"<hap sign block>"

CONTENT_DIGESTED_CHUNK_MAX_SIZE = 1024 * 1024  # 1MB
CONTENT_VERSION = 2
BLOCK_NUMBER = 1
DIGEST_PRIFIX_LENGTH = 5
DEFAULT_ALIGNMENT = 4
DEFAULT_COMPATIBLE_VERSION = 9

# 摘要/签名算法表：名称 → (JCA 摘要, OID, blockId, 内容摘要名)
SIGN_ALG_TABLE = {
    "SHA256withECDSA": ("sha256", "1.2.840.10045.4.3.2", 0x201, "SHA-256"),
    "SHA384withECDSA": ("sha384", "1.2.840.10045.4.3.3", 0x202, "SHA-384"),
    "SHA512withECDSA": ("sha512", "1.2.840.10045.4.3.4", 0x203, "SHA-512"),
    "SHA256withRSA": ("sha256", "1.2.840.113549.1.1.11", 0x104, "SHA-256"),
}

DIGEST_OID = {
    "SHA-256": "2.16.840.1.101.3.4.2.1",
    "SHA-384": "2.16.840.1.101.3.4.2.2",
    "SHA-512": "2.16.840.1.101.3.4.2.3",
}
DIGEST_FUNC = {
    "SHA-256": hashlib.sha256,
    "SHA-384": hashlib.sha384,
    "SHA-512": hashlib.sha512,
}

# ASN.1 OID
OID_DATA = "1.2.840.113549.1.7.1"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_OWNER_ID = "1.3.6.1.4.1.2011.2.376.1.4.1"
OID_PLUGIN_ID = "1.3.6.1.4.1.2011.2.376.1.4.2"

# 代码签名常量
CODE_SIGN_MAGIC = 0xE046C8C65389FCCD
FSVERITY_INFO_MAGIC = 0x1E3831AB
HAP_INFO_MAGIC = 0xC1B5CC66
NATIVE_LIB_INFO_MAGIC = 0x0ED2E720
PERMISSION_BLOCK_MAGIC = 0x28E2450F93036A7D

CSB_FSVERITY_INFO_SEG = 0x1
CSB_HAP_META_SEG = 0x2
CSB_NATIVE_LIB_INFO_SEG = 0x3

FLAG_MERKLE_TREE_INLINED = 0x1
FLAG_NATIVE_LIB_INCLUDED = 0x2

FSV_MERKLE_TREE_INLINED = 0x1
FSV_PAGE_INFO_INLINED = 0x2

FS_VERITY_HASH_ALG_SHA256 = 1
FS_VERITY_LOG_BLOCK_SIZE = 12  # 4096
FS_VERITY_DESCRIPTOR_SIZE = 256
FS_VERITY_VERSION = 1
FS_VERITY_SALT_SIZE = 32
CODE_SIGN_VERSION = 1
CODE_SIGN_VERSION_V2 = 2
DEFAULT_UNIT_SIZE = 4

DEBUG_LIB_ID = "DEBUG_LIB_ID"
SHARED_LIB_ID = "SHARED_LIB_ID"

# 权限签名内容类型
PERMISSION_TYPE_PROFILE = 0x01
PERMISSION_TYPE_MODULE_JSON = 0x02
PERMISSION_TYPE_CODE_SIGN = 0x03
PERMISSION_TYPE_SHARE_FILES = 0x04

# ZIP 结构常量
ZIP_EOCD_SIG = 0x06054B50
ZIP_CD_SIG = 0x02014B50
ZIP_LOCAL_SIG = 0x04034B50
ZIP_DD_SIG = 0x08074B50
ZIP_EOCD_LENGTH = 22
ZIP_CD_LENGTH = 46
ZIP_LOCAL_LENGTH = 30
ZIP_DD_LENGTH = 16

# entry 分类（ZipEntryData.EntryType）
TYPE_RUNNABLE_FILE = 0
TYPE_BIT_MAP = 1
TYPE_RESOURCE_FILE = 2

BIT_MAP_FILENAME = ".pages.info"
LIBS_PATH_PREFIX = "libs/"
ABC_FILE_SUFFIX = ".abc"
NATIVE_LIB_AN_SUFFIX = ".an"
RESFILE_PATH_PREFIX = "resources/resfile/"

HDC_NAME = "hdc"


# ============================================================ 基础工具


def die(msg: str, code: int = 1):
    """显式报错退出，不做静默回退。"""
    print(f"错误: {msg}", file=sys.stderr)
    sys.exit(code)


def info(msg: str):
    print(msg)


def run(cmd: list, capture=True, stdin_data=None) -> subprocess.CompletedProcess:
    p = subprocess.run(cmd, capture_output=capture, text=True, input=stdin_data)
    if p.returncode != 0:
        out = ((p.stderr or "") + (p.stdout or "")) if capture else ""
        die(f"命令失败({' '.join(cmd)}):\n{out}")
    return p


def http_json(url: str, method="GET", headers=None, body=None, raw_dump=None):
    text = http_text(url, method, headers, body, raw_dump)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        die(f"响应非 JSON: {url}\n{text[:2000]}")


def http_text(url: str, method="GET", headers=None, body=None, raw_dump=None) -> str:
    """发起 HTTP 请求；raw_dump 非空时把原始响应体写入该路径（协议校准用）。"""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", "Dart/3.6 (dart:io)")
    req.add_header("Accept-Encoding", "gzip")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(
            req, timeout=30, context=ssl.create_default_context()
        ) as resp:
            raw = resp.read()
            if resp.headers.get("Content-Encoding") == "gzip":
                raw = gzip.decompress(raw)
            text = raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        die(f"HTTP {e.code} {url}\n{e.read().decode('utf-8', 'replace')[:2000]}")
    except urllib.error.URLError as e:
        die(f"网络失败 {url}: {e.reason}")
    if raw_dump:
        Path(raw_dump).write_text(text)
    return text


def require(d, key, ctx=""):
    """严格取字段，缺失即报错并打印整个对象——不猜结构。"""
    if not isinstance(d, dict) or key not in d:
        die(
            f"响应缺少字段 {key} {ctx}:\n"
            f"{json.dumps(d, ensure_ascii=False, indent=1)[:3000]}"
        )
    return d[key]


def gen_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(16))


def u32(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF)


def u64(v: int) -> bytes:
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def read_u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def read_u64(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


# ============================================================ DER / ASN.1 编码


def der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = b""
    while n:
        body = bytes([n & 0xFF]) + body
        n >>= 8
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + der_length(len(content)) + content


def der_seq(*items) -> bytes:
    return tlv(0x30, b"".join(items))


def der_set(*items) -> bytes:
    return tlv(0x31, b"".join(items))


def der_octet(data: bytes) -> bytes:
    return tlv(0x04, data)


def der_null() -> bytes:
    return b"\x05\x00"


def der_int(value: int) -> bytes:
    """DER INTEGER（正数，最高位为 1 时补前导 0x00）。"""
    if value == 0:
        body = b"\x00"
    elif value > 0:
        body = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if body[0] & 0x80:
            body = b"\x00" + body
    else:
        die("DER INTEGER 仅支持非负值")
    return tlv(0x02, body)


def der_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p < 0x80:
            body += bytes([p])
        else:
            chunk = []
            while p:
                chunk.insert(0, (p & 0x7F) | 0x80)
                p >>= 7
            chunk[-1] &= 0x7F
            body += bytes(chunk)
    return tlv(0x06, body)


def der_utf8(text: str) -> bytes:
    return tlv(0x0C, text.encode("utf-8"))


def der_utctime(dt: datetime.datetime) -> bytes:
    """DER UTCTime：YYMMDDHHMMSSZ（GMT）。"""
    return tlv(0x17, dt.strftime("%y%m%d%H%M%S").encode("ascii") + b"Z")


def der_ctx(number: int, content: bytes, constructed: bool = True) -> bytes:
    tag = (0xA0 if constructed else 0x80) | number
    return tlv(tag, content)


def der_algorithm_identifier(oid: str, with_null: bool = True) -> bytes:
    if with_null:
        return der_seq(der_oid(oid), der_null())
    return der_seq(der_oid(oid))


# ---- DER 解析 ----


def der_read(data: bytes, pos: int):
    """读取一个 TLV，返回 (tag, content, next_pos, start_pos)。"""
    start = pos
    tag = data[pos]
    pos += 1
    first = data[pos]
    pos += 1
    if first & 0x80:
        n = first & 0x7F
        if n == 0:
            die("不支持不定长 BER 编码")
        length = int.from_bytes(data[pos : pos + n], "big")
        pos += n
    else:
        length = first
    content = data[pos : pos + length]
    if len(content) != length:
        die("DER 数据截断")
    return tag, content, pos + length, start


def der_read_raw(data: bytes, pos: int):
    """读取一个 TLV 并返回其原始编码（含 tag/length）。"""
    tag, content, nxt, start = der_read(data, pos)
    return data[start:nxt], nxt


def der_iter(data: bytes):
    pos = 0
    while pos < len(data):
        tag, content, pos, _ = der_read(data, pos)
        yield tag, content


# ============================================================ X.509 证书


class Certificate:
    """最小化 X.509 视图：只保留签名需要的字段。"""

    def __init__(self, der: bytes):
        self.der = der
        self.issuer_raw = b""
        self.subject_raw = b""
        self.serial = 0
        self.subject_cn = ""
        self._parse()

    def _parse(self):
        tag, cert_body, _, _ = der_read(self.der, 0)
        if tag != 0x30:
            die("证书不是 SEQUENCE")
        # tbsCertificate
        tag, tbs, _, tbs_start = der_read(cert_body, 0)
        if tag != 0x30:
            die("tbsCertificate 不是 SEQUENCE")
        p = 0
        tag, content, p, _ = der_read(tbs, p)
        if tag == 0xA0:  # 显式 [0] version
            tag, content, p, _ = der_read(tbs, p)
        if tag != 0x02:
            die("证书缺少 serialNumber")
        self.serial = int.from_bytes(content, "big")
        # signatureAlgorithm
        tag, _, p, _ = der_read(tbs, p)
        # issuer（保留原始编码）
        self.issuer_raw, p = der_read_raw(tbs, p)
        # validity
        tag, _, p, _ = der_read(tbs, p)
        # subject（保留原始编码）
        self.subject_raw, p = der_read_raw(tbs, p)
        self.subject_cn = self._find_cn(self.subject_raw)

    @staticmethod
    def _find_cn(name_der: bytes) -> str:
        """在 Name（RDNSequence）中查 OID 2.5.4.3 的字符串值。"""
        target = bytes([0x06, 0x03, 0x55, 0x04, 0x03])  # 2.5.4.3
        idx = name_der.find(target)
        if idx < 0:
            return ""
        p = idx + len(target)
        tag, content, _, _ = der_read(name_der, p)
        try:
            return content.decode("utf-8")
        except UnicodeDecodeError:
            return content.decode("latin-1")


def parse_pem_certificates(data: bytes) -> list:
    """解析 PEM（可含多张证书）或裸 DER 证书。"""
    text = data.decode("latin-1")
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.S
    )
    if blocks:
        return [
            Certificate(base64.b64decode(re.sub(r"\s+", "", b), validate=True))
            for b in blocks
        ]
    return [Certificate(data)]


def load_cert_chain(path: Path) -> list:
    """读取证书链并按 issuer/subject 关系排序（叶子在前、根在最后）。"""
    certs = parse_pem_certificates(path.read_bytes())
    if not certs:
        die(f"证书文件为空: {path}")
    return sort_cert_chain(certs)


def sort_cert_chain(certs: list) -> list:
    """按 issuer→subject 关系重建链序：叶子在前、根在最后。

    叶子判定：其 subject 没有被链中任何证书的 issuer 引用。
    链验证（信任锚）交由签名后的自检完成，此处只做排序。
    """
    if len(certs) == 1:
        return list(certs)
    issuers = {c.issuer_raw for c in certs}
    leaf = next((c for c in certs if c.subject_raw not in issuers), None)
    if leaf is None:
        leaf = certs[0]
    chain = [leaf]
    used = {id(leaf)}
    while True:
        cur = chain[-1]
        nxt = next(
            (c for c in certs if id(c) not in used and c.subject_raw == cur.issuer_raw),
            None,
        )
        if nxt is None:
            break
        chain.append(nxt)
        used.add(id(nxt))
    chain.extend(c for c in certs if id(c) not in used)
    return chain


# ============================================================ CMS / PKCS#7


def cms_extract_signed_content(der: bytes) -> bytes:
    """从 PKCS#7 SignedData 中取出 encapContentInfo 的内容（profile 的 JSON）。"""
    tag, ci, _, _ = der_read(der, 0)
    if tag != 0x30:
        die("PKCS#7 不是 SEQUENCE")
    p = 0
    tag, oid, p, _ = der_read(ci, p)
    tag, exp, p, _ = der_read(ci, p)
    if tag != 0xA0:
        die("ContentInfo 缺少 [0] EXPLICIT content")
    tag, sd, _, _ = der_read(exp, 0)
    q = 0
    tag, _, q, _ = der_read(sd, q)  # version
    tag, _, q, _ = der_read(sd, q)  # digestAlgorithms
    tag, eci, q, _ = der_read(sd, q)  # encapContentInfo
    r = 0
    tag, _, r, _ = der_read(eci, r)  # contentType
    tag, exp2, r, _ = der_read(eci, r)  # [0] EXPLICIT
    tag, content, _, _ = der_read(exp2, 0)
    return content


def _der_attr(oid: str, value_der: bytes) -> bytes:
    return der_seq(der_oid(oid), der_set(value_der))


def _der_sort_set(items: list) -> bytes:
    """DER SET OF：按元素编码字节序排序后拼接。"""
    return b"".join(sorted(items))


def _signing_time(now: datetime.datetime) -> datetime.datetime:
    """签名时间：默认当前 UTC 时间，可用 HAP_SIGN_TIME 固定以便复现。"""
    fixed = os.environ.get("HAP_SIGN_TIME")
    if fixed:
        return datetime.datetime.strptime(fixed, "%y%m%d%H%M%S").replace(
            tzinfo=datetime.timezone.utc
        )
    return now.astimezone(datetime.timezone.utc)


def generate_cms_signed_data(
    content: bytes,
    certs: list,
    key_path: Path,
    sign_alg: str,
    detached: bool,
    extra_attrs: list = None,
    sign_time: datetime.datetime = None,
) -> bytes:
    """生成 PKCS#7 SignedData（等价 BcPkcs7Generator / BcSignedDataGenerator）。

    detached=False：内容放入 encapContentInfo 的 OCTET STRING（HAP 签名路径）
    detached=True ：encapContentInfo 内容为空（代码签名路径）
    extra_attrs：附加属性 [(oid, DER 值)]，代码签名用 ownerID/pluginId
    """
    digest_name, sign_oid, _, content_digest = SIGN_ALG_TABLE[sign_alg]
    digest_oid = DIGEST_OID[content_digest]
    if not certs:
        die("签名需要至少一张证书")
    sign_time = sign_time or _signing_time(datetime.datetime.now(datetime.timezone.utc))

    # 签名属性：contentType / messageDigest / signingTime / 附加属性
    msg_digest = hashlib.new(digest_name, content).digest()
    attrs = [
        _der_attr(OID_CONTENT_TYPE, der_oid(OID_DATA)),
        _der_attr(OID_MESSAGE_DIGEST, der_octet(msg_digest)),
        _der_attr(OID_SIGNING_TIME, der_utctime(sign_time)),
    ]
    for oid, value in extra_attrs or []:
        attrs.append(_der_attr(oid, value))
    attrs_body = _der_sort_set(attrs)
    # 签名对象是 SET OF（0x31）的 DER 编码；文件中存储为 [0] IMPLICIT（0xA0）。
    # BC/OpenSSL 校验时会把 signedAttrs 重新按 SET 编码再验签，两者必须一致。
    signature = sign_bytes(key_path, tlv(0x31, attrs_body), sign_alg)
    signed_attrs = tlv(0xA0, attrs_body)

    leaf = certs[0]
    signer_info = der_seq(
        der_int(1),
        der_seq(leaf.issuer_raw, der_int(leaf.serial)),
        der_algorithm_identifier(digest_oid, False),
        signed_attrs,
        der_algorithm_identifier(sign_oid, False),
        der_octet(signature),
    )

    if detached:
        eci = der_seq(der_oid(OID_DATA))
    else:
        eci = der_seq(der_oid(OID_DATA), der_ctx(0, der_octet(content)))

    # 证书集合：[0] IMPLICIT SET，按 DER 编码排序
    cert_set = _der_sort_set([c.der for c in certs])
    certs_field = der_ctx(0, cert_set)

    signed_data = der_seq(
        der_int(1),
        der_set(der_algorithm_identifier(digest_oid, False)),
        eci,
        certs_field,
        der_set(signer_info),
    )
    return der_seq(der_oid(OID_SIGNED_DATA), der_ctx(0, signed_data))


# ============================================================ 签名器（openssl）


def sign_bytes(key_path: Path, data: bytes, sign_alg: str) -> bytes:
    """用 openssl 对数据做原始签名（ECDSA 输出 DER 编码的 r,s）。"""
    entry = SIGN_ALG_TABLE.get(sign_alg)
    if not entry:
        die(f"不支持的签名算法: {sign_alg}")
    digest = entry[0]
    p = subprocess.run(
        ["openssl", "dgst", f"-{digest}", "-sign", str(key_path)],
        input=data,
        capture_output=True,
    )
    if p.returncode != 0:
        die(f"openssl 签名失败: {p.stderr.decode('utf-8', 'replace')}")
    return p.stdout


def verify_bytes(cert_path: Path, data: bytes, signature: bytes, sign_alg: str) -> bool:
    """用证书公钥验证签名（自检，避免产出坏签名）。"""
    digest = SIGN_ALG_TABLE[sign_alg][0]
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(signature)
        sig_file = f.name
    try:
        p = subprocess.run(
            [
                "openssl",
                "dgst",
                f"-{digest}",
                "-verify",
                str(cert_path),
                "-signature",
                sig_file,
            ],
            input=data,
            capture_output=True,
        )
        return p.returncode == 0
    finally:
        os.unlink(sig_file)


# ==== END PART 1 ====


# ============================================================ ZIP 层


def is_runnable_file(name: str) -> bool:
    """可执行文件判定（与 FileUtils.isRunnableFile 一致）。"""
    if not name:
        return False
    return (
        name.endswith(NATIVE_LIB_AN_SUFFIX)
        or name.endswith(ABC_FILE_SUFFIX)
        or name.startswith(LIBS_PATH_PREFIX)
    )


def entry_type_of(name: str) -> int:
    if is_runnable_file(name):
        return TYPE_RUNNABLE_FILE
    if name == BIT_MAP_FILENAME:
        return TYPE_BIT_MAP
    return TYPE_RESOURCE_FILE


class ZipEntryHeader:
    """ZIP 本地文件头（30 字节 + 文件名 + extra）。"""

    def __init__(self):
        self.version = 0
        self.flag = 0
        self.method = 0
        self.last_time = 0
        self.last_date = 0
        self.crc32 = 0
        self.compressed_size = 0
        self.uncompressed_size = 0
        self.file_name = b""
        self.extra_data = b""

    @classmethod
    def parse(cls, data: bytes, off: int) -> "ZipEntryHeader":
        h = cls()
        (
            sig,
            h.version,
            h.flag,
            h.method,
            h.last_time,
            h.last_date,
            h.crc32,
            h.compressed_size,
            h.uncompressed_size,
            name_len,
            extra_len,
        ) = struct.unpack_from("<IHHHHHIIIHH", data, off)
        if sig != ZIP_LOCAL_SIG:
            die(f"本地文件头签名错误: 0x{sig:08x} @ {off}")
        p = off + ZIP_LOCAL_LENGTH
        h.file_name = data[p : p + name_len]
        p += name_len
        h.extra_data = data[p : p + extra_len]
        return h

    @property
    def length(self) -> int:
        return ZIP_LOCAL_LENGTH + len(self.file_name) + len(self.extra_data)

    def to_bytes(self) -> bytes:
        head = struct.pack(
            "<IHHHHHIIIHH",
            ZIP_LOCAL_SIG,
            self.version,
            self.flag,
            self.method,
            self.last_time,
            self.last_date,
            self.crc32,
            self.compressed_size,
            self.uncompressed_size,
            len(self.file_name),
            len(self.extra_data),
        )
        return head + self.file_name + self.extra_data


class CentralDirectory:
    """ZIP 中央目录项（46 字节 + 文件名 + extra + comment）。"""

    def __init__(self):
        self.version = 0
        self.version_extra = 0
        self.flag = 0
        self.method = 0
        self.last_time = 0
        self.last_date = 0
        self.crc32 = 0
        self.compressed_size = 0
        self.uncompressed_size = 0
        self.disk_num_start = 0
        self.internal_file = 0
        self.external_file = 0
        self.offset = 0
        self.file_name = b""
        self.extra_data = b""
        self.comment = b""

    @classmethod
    def parse(cls, data: bytes, off: int):
        cd = cls()
        (
            sig,
            cd.version,
            cd.version_extra,
            cd.flag,
            cd.method,
            cd.last_time,
            cd.last_date,
            cd.crc32,
            cd.compressed_size,
            cd.uncompressed_size,
            name_len,
            extra_len,
            comment_len,
            cd.disk_num_start,
            cd.internal_file,
            cd.external_file,
            cd.offset,
        ) = struct.unpack_from("<IHHHHHHIIIHHHHHII", data, off)
        if sig != ZIP_CD_SIG:
            die(f"中央目录签名错误: 0x{sig:08x} @ {off}")
        p = off + ZIP_CD_LENGTH
        cd.file_name = data[p : p + name_len]
        p += name_len
        cd.extra_data = data[p : p + extra_len]
        p += extra_len
        cd.comment = data[p : p + comment_len]
        return cd, p + comment_len

    @property
    def length(self) -> int:
        return (
            ZIP_CD_LENGTH
            + len(self.file_name)
            + len(self.extra_data)
            + len(self.comment)
        )

    def to_bytes(self) -> bytes:
        head = struct.pack(
            "<IHHHHHHIIIHHHHHII",
            ZIP_CD_SIG,
            self.version,
            self.version_extra,
            self.flag,
            self.method,
            self.last_time,
            self.last_date,
            self.crc32,
            self.compressed_size,
            self.uncompressed_size,
            len(self.file_name),
            len(self.extra_data),
            len(self.comment),
            self.disk_num_start,
            self.internal_file,
            self.external_file,
            self.offset,
        )
        # 与官方实现一致：commentLength > 0 时写入 extraData（实际无 comment）
        tail = self.file_name + self.extra_data
        if self.comment:
            tail += self.extra_data
        return head + tail


class EndOfCentralDirectory:
    """EOCD（22 字节 + 注释）。"""

    def __init__(self):
        self.disk_num = 0
        self.cd_start_disk_num = 0
        self.this_disk_cd_num = 0
        self.cd_total = 0
        self.cd_size = 0
        self.offset = 0
        self.comment = b""

    @classmethod
    def parse(cls, data: bytes, off: int):
        e = cls()
        (
            sig,
            e.disk_num,
            e.cd_start_disk_num,
            e.this_disk_cd_num,
            e.cd_total,
            e.cd_size,
            e.offset,
            comment_len,
        ) = struct.unpack_from("<IHHHHIIH", data, off)
        if sig != ZIP_EOCD_SIG:
            die(f"EOCD 签名错误: 0x{sig:08x} @ {off}")
        e.comment = data[off + ZIP_EOCD_LENGTH : off + ZIP_EOCD_LENGTH + comment_len]
        return e

    @property
    def length(self) -> int:
        return ZIP_EOCD_LENGTH + len(self.comment)

    def to_bytes(self) -> bytes:
        head = struct.pack(
            "<IHHHHIIH",
            ZIP_EOCD_SIG,
            self.disk_num,
            self.cd_start_disk_num,
            self.this_disk_cd_num,
            self.cd_total,
            self.cd_size,
            self.offset,
            len(self.comment),
        )
        return head + self.comment


class DataDescriptor:
    """数据描述符（16 字节）。"""

    def __init__(self, crc32=0, compressed_size=0, uncompressed_size=0):
        self.crc32 = crc32
        self.compressed_size = compressed_size
        self.uncompressed_size = uncompressed_size

    @classmethod
    def parse(cls, data: bytes, off: int):
        sig, crc, csize, usize = struct.unpack_from("<IIII", data, off)
        if sig != ZIP_DD_SIG:
            die(f"数据描述符签名错误: 0x{sig:08x}")
        return cls(crc, csize, usize)

    def to_bytes(self) -> bytes:
        return struct.pack(
            "<IIII",
            ZIP_DD_SIG,
            self.crc32,
            self.compressed_size,
            self.uncompressed_size,
        )


class ZipEntry:
    """一个 ZIP 条目：本地头 + 数据 + （可选）描述符 + 中央目录项。"""

    def __init__(self):
        self.header = ZipEntryHeader()
        self.cd = CentralDirectory()
        self.data = None  # 新增条目时携带数据，解析得到的条目为 None
        self.file_offset = 0
        self.file_size = 0
        self.descriptor = None
        self.length = 0
        self.entry_type = TYPE_RESOURCE_FILE

    @property
    def name(self) -> str:
        return self.header.file_name.decode("utf-8", "replace")

    def update_length(self):
        body = len(self.data) if self.data is not None else self.file_size
        self.length = (
            self.header.length
            + body
            + (ZIP_DD_LENGTH if self.descriptor is not None else 0)
        )

    def alignment(self, align_num: int) -> int:
        """对齐本条目的数据区：返回新增字节数（0 表示无需对齐）。"""
        padding = self._cal_zero_padding()
        remainder = (self.header.length + self.cd.offset) % align_num
        if remainder == 0:
            return padding
        add = align_num - remainder
        new_extra_len = len(self.header.extra_data) + add
        if new_extra_len > 0xFFFF:
            die(f"条目 {self.name} 无法对齐：extra 字段超长")
        self._set_new_extra_length(new_extra_len)
        return add

    def _cal_zero_padding(self) -> int:
        entry_extra = len(self.header.extra_data)
        cd_extra = len(self.cd.extra_data)
        if cd_extra > entry_extra:
            self._set_header_extra(cd_extra)
            return cd_extra - entry_extra
        if cd_extra < entry_extra:
            self._set_cd_extra(entry_extra)
            return entry_extra - cd_extra
        return 0

    def _set_header_extra(self, new_len: int):
        self.header.extra_data = self.header.extra_data.ljust(new_len, b"\x00")

    def _set_cd_extra(self, new_len: int):
        self.cd.extra_data = self.cd.extra_data.ljust(new_len, b"\x00")

    def _set_new_extra_length(self, new_len: int):
        if new_len < len(self.header.extra_data):
            die(f"条目 {self.name} 无法对齐：extra 长度回退")
        self._set_header_extra(new_len)
        self._set_cd_extra(new_len)
        self.update_length()


class Zip:
    """HAP/HSP 使用的 ZIP 容器（解析、对齐、重写）。"""

    def __init__(self, path):
        self.path = Path(path)
        if not self.path.exists():
            die(f"ZIP 文件不存在: {self.path}")
        self.raw = self.path.read_bytes()
        self.entries = []
        self.eocd = EndOfCentralDirectory()
        self.signing_block = b""
        self.cd_offset = 0
        self.signing_offset = 0
        self.eocd_offset = 0
        self._parse()

    # ---- 解析 ----

    def _find_eocd(self) -> int:
        size = len(self.raw)
        if size < ZIP_EOCD_LENGTH:
            die("文件过小，找不到 EOCD")
        off = size - ZIP_EOCD_LENGTH
        if read_u32(self.raw, off) == ZIP_EOCD_SIG:
            return off
        max_len = min(ZIP_EOCD_LENGTH + 0xFFFF, size)
        start = size - max_len
        for p in range(start, size - ZIP_EOCD_LENGTH + 1):
            if read_u32(self.raw, p) == ZIP_EOCD_SIG:
                return p
        die("未找到 EOCD")  # 显式失败，不做回退

    def _parse(self):
        self.eocd_offset = self._find_eocd()
        self.eocd = EndOfCentralDirectory.parse(self.raw, self.eocd_offset)
        self.cd_offset = self.eocd.offset
        pos = self.cd_offset
        for _ in range(self.eocd.cd_total):
            cd, pos = CentralDirectory.parse(self.raw, pos)
            e = ZipEntry()
            e.cd = cd
            self.entries.append(e)
        for e in self.entries:
            self._load_entry_data(e)
        if self.entries:
            last = self.entries[-1]
            self.signing_offset = last.cd.offset + last.length
        else:
            self.signing_offset = 0
        size = self.cd_offset - self.signing_offset
        if size < 0:
            die("签名块偏移位于条目数据之前")
        self.signing_block = self.raw[self.signing_offset : self.cd_offset]

    def _load_entry_data(self, e: ZipEntry):
        off = e.cd.offset
        e.header = ZipEntryHeader.parse(self.raw, off)
        p = off + e.header.length
        e.file_offset = p
        e.file_size = (
            e.cd.uncompressed_size if e.cd.method == 0 else e.cd.compressed_size
        )
        e.entry_type = entry_type_of(e.header.file_name.decode("utf-8", "replace"))
        if e.header.flag & 0x08:
            e.descriptor = DataDescriptor.parse(self.raw, p + e.file_size)
        e.update_length()
        if self.cd_offset - off < e.length:
            die(f"条目 {e.name} 越界")

    # ---- 变更 ----

    def remove_sign_block(self):
        self.signing_block = b""
        self.reset_offset()

    def add_bitmap(self, data: bytes):
        self.entries = [e for e in self.entries if e.entry_type != TYPE_BIT_MAP]
        e = ZipEntry()
        e.header.method = 0
        e.header.uncompressed_size = len(data)
        e.header.compressed_size = len(data)
        e.header.crc32 = 0
        e.header.file_name = BIT_MAP_FILENAME.encode("utf-8")
        e.cd.method = 0
        e.cd.uncompressed_size = len(data)
        e.cd.compressed_size = len(data)
        e.cd.file_name = e.header.file_name
        e.data = data
        e.entry_type = TYPE_BIT_MAP
        e.update_length()
        self.entries.append(e)

    def sort(self):
        """未压缩条目在前：可执行 → bitmap → 其他；同组按文件名。"""

        def key(e: ZipEntry):
            method = e.header.method
            name = e.name
            if method == 0:
                return (0, e.entry_type, name)
            return (1, 0, name)

        self.entries.sort(key=key)
        self.reset_offset()

    def reset_offset(self):
        off = 0
        cd_len = 0
        for e in self.entries:
            e.update_length()
            e.cd.offset = off
            off += e.length
            cd_len += e.cd.length
        if self.signing_block:
            off += len(self.signing_block)
        self.cd_offset = off
        self.eocd.offset = off
        self.eocd.cd_size = cd_len
        off += cd_len
        self.eocd_offset = off
        self.eocd.cd_total = len(self.entries)
        self.eocd.this_disk_cd_num = len(self.entries)

    def alignment(self, align_num: int = DEFAULT_ALIGNMENT):
        """未压缩条目与首个非可执行条目按 4096 对齐，其余按 align_num。"""
        self.sort()
        is_first_un_runnable = True
        for e in self.entries:
            method = e.header.method
            if method != 0 and not is_first_un_runnable:
                break
            if (e.entry_type == TYPE_RUNNABLE_FILE and method == 0) or (
                e.entry_type == TYPE_BIT_MAP
            ):
                align_bytes = 4096
            elif is_first_un_runnable:
                align_bytes = 4096
                is_first_un_runnable = False
            elif e.name.startswith(RESFILE_PATH_PREFIX) and e.file_size >= 1024 * 1024:
                align_bytes = 4096
            else:
                align_bytes = align_num
            add = e.alignment(align_bytes)
            if add > 0:
                self.reset_offset()

    # ---- 写出 ----

    def to_file(self, out_path):
        out = Path(out_path)
        with open(out, "wb") as f:
            for e in self.entries:
                f.write(e.header.to_bytes())
                if e.data is not None:
                    f.write(e.data)
                else:
                    f.write(self.raw[e.file_offset : e.file_offset + e.file_size])
                if e.descriptor is not None:
                    f.write(e.descriptor.to_bytes())
            if self.signing_block:
                f.write(self.signing_block)
            for e in self.entries:
                f.write(e.cd.to_bytes())
            f.write(self.eocd.to_bytes())
        return out

    # ---- 查询 ----

    def find_entry(self, name: str):
        return next((e for e in self.entries if e.name == name), None)

    def entry_content(self, name: str) -> bytes:
        e = self.find_entry(name)
        if e is None:
            return b""
        if e.data is not None:
            return e.data
        return self.raw[e.file_offset : e.file_offset + e.file_size]


# ==== END PART 2 ====


# ============================================================ HAP 摘要与签名块


def compute_content_digest(
    contents: list, optional_values: list, digest_name: str
) -> bytes:
    """HAP 内容摘要：分块二级摘要，末尾拼接可选块内容。

    一级：0x5A || u32(总块数) || 各块摘要
    每块：sha(0xA5 || u32(块长) || 块数据)
    最终：sha(一级内容 || 各可选块 value)
    """
    func = DIGEST_FUNC[digest_name]
    chunk_count = sum(
        (len(c) + CONTENT_DIGESTED_CHUNK_MAX_SIZE - 1)
        // CONTENT_DIGESTED_CHUNK_MAX_SIZE
        for c in contents
    )
    top = func()
    top.update(b"\x5a" + u32(chunk_count))
    for c in contents:
        for off in range(0, len(c), CONTENT_DIGESTED_CHUNK_MAX_SIZE):
            chunk = c[off : off + CONTENT_DIGESTED_CHUNK_MAX_SIZE]
            ch = func()
            ch.update(b"\xa5" + u32(len(chunk)))
            ch.update(chunk)
            top.update(ch.digest())
    for value in optional_values:
        top.update(value)
    return top.digest()


def encode_list_of_pairs(pairs: list) -> bytes:
    """摘要对列表编码：u32 版本 + u32 块号 + 各对 (u32 长度, u32 算法, u32 摘要长度, 摘要)。"""
    out = u32(CONTENT_VERSION) + u32(BLOCK_NUMBER)
    for alg_id, digest in pairs:
        out += u32(8 + len(digest)) + u32(alg_id) + u32(len(digest)) + digest
    return out


def generate_hap_signature_scheme_block(
    content_digests: list, certs: list, key_path: Path, sign_alg: str, sign_time
) -> bytes:
    """生成 HAP 签名方案块（CMS SignedData，内容为摘要对编码）。"""
    pairs = [(SIGN_ALG_TABLE[sign_alg][2], d) for d in content_digests]
    unsigned_digest = encode_list_of_pairs(pairs)
    return generate_cms_signed_data(
        unsigned_digest, certs, key_path, sign_alg, detached=False, sign_time=sign_time
    )


def generate_hap_signing_block(
    optional_blocks: list, signer_block: bytes, compatible_version: int
) -> bytes:
    """组装完整 HAP 签名块：头部区 + 值区 + 尾部。

    头部：每块 [u32 type][u32 length][u32 offset]（offset 基于值区起点）
    尾部：[u32 块数][u64 总长][16B magic][u32 版本]
    """
    blocks = list(optional_blocks) + [
        (HAP_SIGNATURE_SCHEME_V1_BLOCK_ID, signer_block)
    ]
    count = len(blocks)
    block_size = sum(len(v) for _, v in blocks)
    result_size = 12 * count + block_size + 4 + 8 + 16 + 4
    headers = b""
    values = b""
    offset = 12 * count
    for block_type, value in blocks:
        headers += u32(block_type) + u32(len(value)) + u32(offset)
        offset += len(value)
        values += value
    if compatible_version >= 8:
        magic = HAP_SIGN_BLOCK_MAGIC_V3
        version = 3
    else:
        magic = HAP_SIGN_BLOCK_MAGIC_V2
        version = 2
    return (
        headers
        + values
        + u32(count)
        + u64(result_size)
        + magic
        + u32(version)
    )


# ---- 权限签名块 ----


def generate_permission_signing_block(
    sign_alg: str,
    profile_content: bytes,
    code_sign_bytes: bytes,
    module_content: bytes,
    share_files_content: bytes,
    key_path: Path,
) -> bytes:
    """权限签名块：对非空内容分别摘要后整体签名（原始签名，非 CMS）。"""
    digest_name = SIGN_ALG_TABLE[sign_alg][3]
    func = DIGEST_FUNC[digest_name]
    items = []
    for item_type, content in (
        (PERMISSION_TYPE_PROFILE, profile_content),
        (PERMISSION_TYPE_MODULE_JSON, module_content),
        (PERMISSION_TYPE_CODE_SIGN, code_sign_bytes),
        (PERMISSION_TYPE_SHARE_FILES, share_files_content),
    ):
        if content:
            items.append((item_type, func(content).digest()))
    body = b"".join(u32(t) + d for t, d in items)
    unsign = (
        u64(PERMISSION_BLOCK_MAGIC)
        + u32(SIGN_ALG_TABLE[sign_alg][2])
        + u32(len(body))
        + struct.pack("<H", len(items))
        + body
    )
    signature = sign_bytes(key_path, unsign, sign_alg)
    return unsign + u32(len(signature)) + signature


def read_zip_entry_content(hap_path, name: str) -> bytes:
    """按名字读取 HAP 内部文件内容（自动解压）。"""
    import zipfile

    with zipfile.ZipFile(hap_path) as zf:
        try:
            return zf.read(name)
        except KeyError:
            return b""


def find_module_and_share_file(hap_path, zip_obj: "Zip"):
    """定位 module.json 与 shareFiles 内容（与 HapUtils 一致）。"""
    import zipfile

    if zip_obj.find_entry("module.json") is None:
        return None, None
    module_content = read_zip_entry_content(hap_path, "module.json")
    if not module_content:
        die("module.json 内容为空")
    try:
        obj = json.loads(module_content.decode("utf-8"))
    except json.JSONDecodeError as e:
        die(f"module.json 不是合法 JSON: {e}")
    module = obj.get("module")
    if not isinstance(module, dict):
        return module_content, None
    share_files = module.get("shareFiles")
    if not share_files:
        return module_content, None
    if not isinstance(share_files, str) or not share_files.startswith("$profile:"):
        return module_content, b""
    share_name = share_files[len("$profile:") :]
    full_name = "resources/base/profile/" + share_name
    target = None
    with zipfile.ZipFile(hap_path) as zf:
        for name in zf.namelist():
            if name == full_name or name.startswith(full_name + "."):
                target = name
                break
        if target is None:
            return module_content, b""
        return module_content, zf.read(target)


# ==== END PART 3 ====


# ============================================================ fs-verity


def ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b


def fsverity_build_tree(data: bytes):
    """构建 fs-verity Merkle 树，返回 (tree_bytes 或 None, root_hash)。

    叶子层：数据按 4096 分块取 SHA-256，末尾按 4096 对齐补零；
    上层：子层按 4096 分块取 SHA-256，同样对齐补零；
    数据 <= 4096 时无树，rootHash = 缓冲区前 32 字节。
    """
    data_size = len(data)
    digest_size = 32
    if data_size == 0:
        return None, b""
    level_size = []
    original = data_size
    while True:
        full_chunk = ceil_div(original, 4096) * digest_size
        level_size.append(ceil_div(full_chunk, 4096) * 4096)
        original = full_chunk
        if full_chunk <= 4096:
            break
    offsets = [0]
    for i in range(len(level_size)):
        offsets.append(offsets[-1] + level_size[len(level_size) - 1 - i])
    buf = bytearray(offsets[-1])
    # 叶子层
    hashes = b"".join(
        hashlib.sha256(data[i : i + 4096]).digest()
        for i in range(0, data_size, 4096)
    )
    leaf_begin = offsets[-2]
    buf[leaf_begin : leaf_begin + len(hashes)] = hashes
    _fsverity_pad(buf, leaf_begin, len(hashes), data_size)
    # 上层
    for i in range(len(offsets) - 3, -1, -1):
        src = bytes(buf[offsets[i + 1] : offsets[i + 2]])
        upper = b"".join(
            hashlib.sha256(src[j : j + 4096]).digest()
            for j in range(0, len(src), 4096)
        )
        dst = offsets[i]
        buf[dst : dst + len(upper)] = upper
        _fsverity_pad(buf, dst, len(upper), len(src))
    if data_size <= 4096:
        return None, bytes(buf[:digest_size])
    return bytes(buf), hashlib.sha256(bytes(buf[:4096])).digest()


def _fsverity_pad(buf: bytearray, dst: int, written: int, original_size: int):
    """将层级缓冲区按 4096 对齐补零。"""
    full_chunk = ceil_div(original_size, 4096) * 32
    diff = full_chunk % 4096
    if diff > 0:
        pad = 4096 - diff
        buf[dst + written : dst + written + pad] = b"\x00" * pad


def fsverity_disc_byte(
    file_size: int, root_hash: bytes, flags: int, merkle_tree_offset: int
) -> bytes:
    """getDiscByte：生成摘要用的描述符（首字节 CODE_SIGN_VERSION，尾部全零）。"""
    buf = bytearray(FS_VERITY_DESCRIPTOR_SIZE)
    buf[0] = CODE_SIGN_VERSION
    buf[1] = FS_VERITY_HASH_ALG_SHA256
    buf[2] = FS_VERITY_LOG_BLOCK_SIZE
    buf[3] = 0  # saltSize
    struct.pack_into("<I", buf, 4, 0)  # signSize
    struct.pack_into("<Q", buf, 8, file_size)
    buf[16 : 16 + len(root_hash)] = root_hash[:64]
    struct.pack_into("<I", buf, 112, flags)
    struct.pack_into("<I", buf, 116, 0)
    struct.pack_into("<Q", buf, 120, merkle_tree_offset)
    return bytes(buf)


def fsverity_disc_byte_csv2(
    file_size: int,
    root_hash: bytes,
    flags: int,
    merkle_tree_offset: int,
    map_offset: int,
    map_size: int,
    unit_size: int,
) -> bytes:
    """getDiscByteCsv2：带 bitmap 描述的描述符（末字节 CODE_SIGN_VERSION_V2）。"""
    buf = bytearray(FS_VERITY_DESCRIPTOR_SIZE)
    buf[0] = FS_VERITY_VERSION
    buf[1] = FS_VERITY_HASH_ALG_SHA256
    buf[2] = FS_VERITY_LOG_BLOCK_SIZE
    buf[3] = 0
    struct.pack_into("<I", buf, 4, 0)
    struct.pack_into("<Q", buf, 8, file_size)
    buf[16 : 16 + len(root_hash)] = root_hash[:64]
    struct.pack_into("<I", buf, 112, (unit_size << 1) | flags)
    struct.pack_into("<I", buf, 116, map_size)
    struct.pack_into("<Q", buf, 120, merkle_tree_offset)
    struct.pack_into("<Q", buf, 128, map_offset)
    buf[255] = CODE_SIGN_VERSION_V2
    return bytes(buf)


def fsverity_digest(algo_id: int, digest: bytes) -> bytes:
    return b"FSVerity" + struct.pack("<HH", algo_id, len(digest)) + digest


# ============================================================ ELF 解析


def elf_exec_segments(data: bytes) -> list:
    """返回 ELF 中可执行程序段的 [(pOffset, pFilesz)]；非 ELF 返回空列表。"""
    if len(data) < 64 or data[0:4] != b"\x7fELF":
        return []
    ei_class = data[4]
    ei_data = data[5]
    bo = "<" if ei_data == 1 else ">"
    try:
        if ei_class == 2:
            phoff = struct.unpack_from(bo + "Q", data, 32)[0]
            phentsize = struct.unpack_from(bo + "H", data, 54)[0]
            phnum = struct.unpack_from(bo + "H", data, 56)[0]
        elif ei_class == 1:
            phoff = struct.unpack_from(bo + "I", data, 28)[0]
            phentsize = struct.unpack_from(bo + "H", data, 42)[0]
            phnum = struct.unpack_from(bo + "H", data, 44)[0]
        else:
            return []
    except struct.error:
        return []
    result = []
    for i in range(phnum):
        off = phoff + i * phentsize
        if off + phentsize > len(data):
            break
        try:
            if ei_class == 2:
                _, p_flags, p_offset, _, _, p_filesz, _, _ = struct.unpack_from(
                    bo + "IIQQQQQQ", data, off
                )
            else:
                _, p_offset, _, _, p_filesz, _, p_flags, _ = struct.unpack_from(
                    bo + "IIIIIIII", data, off
                )
        except struct.error:
            break
        if p_flags & 1:
            result.append((p_offset, p_filesz))
    return result


# ============================================================ 页面信息 bitmap

ABC_M_CODE = 2
ELF_M_CODE = 1


def generate_bitmap(segments: list, max_entry_data_offset: int) -> bytes:
    """生成 pages 信息 bitmap；segments 为 [(类型, 起始, 结束)]。

    ELF 段置位 i，ABC 段置位 i+1，单位 4 字节。返回小端 long 序列。
    容量按 java BitSet(len) 语义预留（len = 数据区 4K 页数 * 4）。
    """
    if not segments:
        return b""
    capacity_bits = max_entry_data_offset // 4096 * DEFAULT_UNIT_SIZE
    words = [0] * ((capacity_bits + 63) // 64)

    def set_bit(index: int):
        need = index // 64 + 1
        if need > len(words):
            words.extend([0] * (need - len(words)))
        words[index // 64] |= 1 << (index % 64)

    for seg_type, start, end in segments:
        begin = (start >> 12) * DEFAULT_UNIT_SIZE
        if end % 4096 == 0:
            finish = (end >> 12) * DEFAULT_UNIT_SIZE
        else:
            finish = ((end >> 12) + 1) * DEFAULT_UNIT_SIZE
        for i in range(begin, finish, DEFAULT_UNIT_SIZE):
            if seg_type == ELF_M_CODE:
                set_bit(i)
            else:
                set_bit(i + 1)
    return b"".join(struct.pack("<Q", w) for w in words)


# ============================================================ 代码签名数据结构


class MerkleTreeExtension:
    TYPE = FSV_MERKLE_TREE_INLINED
    DATA_SIZE = 80

    def __init__(self, merkle_tree_size: int, merkle_tree_offset: int, root_hash):
        self.merkle_tree_size = merkle_tree_size
        self.merkle_tree_offset = merkle_tree_offset
        self.root_hash = (root_hash or b"").ljust(64, b"\x00")[:64]

    def size(self) -> int:
        return 8 + self.DATA_SIZE

    def to_bytes(self) -> bytes:
        return (
            u32(self.TYPE)
            + u32(self.DATA_SIZE)
            + u64(self.merkle_tree_size)
            + u64(self.merkle_tree_offset)
            + self.root_hash
        )


class PageInfoExtension:
    TYPE = FSV_PAGE_INFO_INLINED
    DATA_SIZE_WITHOUT_SIGN = 24

    def __init__(self, map_offset: int, map_size: int):
        self.map_offset = map_offset
        self.map_size = map_size
        self.unit_size = DEFAULT_UNIT_SIZE
        self.signature = b""
        self.zero_padding = b""

    def set_signature(self, signature: bytes):
        self.signature = signature
        self.zero_padding = b"\x00" * ((4 - (len(signature) % 4)) % 4)

    def size(self) -> int:
        return (
            8 + self.DATA_SIZE_WITHOUT_SIGN + len(self.signature) + len(self.zero_padding)
        )

    def to_bytes(self) -> bytes:
        data_size = self.DATA_SIZE_WITHOUT_SIGN + len(self.signature) + len(
            self.zero_padding
        )
        return (
            u32(self.TYPE)
            + u32(data_size)
            + u64(self.map_offset)
            + u64(self.map_size)
            + bytes([self.unit_size])
            + b"\x00" * 3
            + u32(len(self.signature))
            + self.signature
            + self.zero_padding
        )


class SignInfo:
    """代码签名信息块（60 字节固定区 + 签名 + 扩展）。"""

    FLAG_MERKLE_TREE_INCLUDED = 0x1
    SIZE_WITHOUT_SIGNATURE = 60
    SALT_BUFFER_LENGTH = 32

    def __init__(self, salt_size: int, flags: int, data_size: int, salt, signature):
        self.salt_size = salt_size
        self.flags = flags
        self.data_size = data_size
        self.salt = salt if salt else b"\x00" * self.SALT_BUFFER_LENGTH
        self.signature = signature or b""
        self.sig_size = len(self.signature)
        self.zero_padding = b"\x00" * ((4 - (self.sig_size % 4)) % 4)
        self.extension_num = 0
        self.extension_offset = (
            self.SIZE_WITHOUT_SIGNATURE + self.sig_size + len(self.zero_padding)
        )
        self.extensions = []

    def add_extension(self, ext):
        self.extensions.append(ext)
        self.extension_num = len(self.extensions)

    def size(self) -> int:
        return (
            self.SIZE_WITHOUT_SIGNATURE
            + len(self.signature)
            + len(self.zero_padding)
            + sum(e.size() for e in self.extensions)
        )

    def to_bytes(self) -> bytes:
        out = (
            u32(self.salt_size)
            + u32(self.sig_size)
            + u32(self.flags)
            + u64(self.data_size)
            + self.salt
            + u32(self.extension_num)
            + u32(self.extension_offset)
            + self.signature
            + self.zero_padding
        )
        for ext in self.extensions:
            out += ext.to_bytes()
        return out


class FsVerityInfoSegment:
    MAGIC = FSVERITY_INFO_MAGIC
    SIZE = 64

    def __init__(self, version: int, hash_algorithm: int, log2_block_size: int):
        self.version = version
        self.hash_algorithm = hash_algorithm
        self.log2_block_size = log2_block_size

    def size(self) -> int:
        return self.SIZE

    def to_bytes(self) -> bytes:
        return (
            u32(self.MAGIC)
            + bytes([self.version, self.hash_algorithm, self.log2_block_size])
            + b"\x00" * 57
        )


class HapInfoSegment:
    MAGIC = HAP_INFO_MAGIC

    def __init__(self):
        self.sign_info = SignInfo(0, 0, 0, None, None)

    def size(self) -> int:
        return 4 + self.sign_info.size()

    def to_bytes(self) -> bytes:
        return u32(self.MAGIC) + self.sign_info.to_bytes()


class NativeLibInfoSegment:
    MAGIC = NATIVE_LIB_INFO_MAGIC
    SIGNED_FILE_POS_SIZE = 16

    def __init__(self):
        self.file_names = []
        self.sign_infos = []
        self.zero_padding = b""
        self.segment_size = 0
        self.file_name_list_block_size = 0
        self.sign_info_list_block_size = 0

    def set_list(self, pairs: list):
        """pairs 为 [(文件名, SignInfo)]，按插入顺序。"""
        self.file_names = [n for n, _ in pairs]
        self.sign_infos = [s for _, s in pairs]
        name_block = b"".join(n.encode("utf-8") for n in self.file_names)
        self.file_name_list_block_size = len(name_block)
        self.sign_info_list_block_size = sum(s.size() for s in self.sign_infos)
        self.zero_padding = b"\x00" * ((4 - (self.file_name_list_block_size % 4)) % 4)
        self.segment_size = self.size()

    def section_num(self) -> int:
        return len(self.sign_infos)

    def size(self) -> int:
        return (
            12
            + len(self.sign_infos) * self.SIGNED_FILE_POS_SIZE
            + self.file_name_list_block_size
            + len(self.zero_padding)
            + self.sign_info_list_block_size
        )

    def to_bytes(self) -> bytes:
        base = 12 + len(self.sign_infos) * self.SIGNED_FILE_POS_SIZE
        name_base = base
        sign_base = name_base + self.file_name_list_block_size + len(self.zero_padding)
        out = u32(self.MAGIC) + u32(self.segment_size) + u32(len(self.sign_infos))
        name_offset = 0
        sign_offset = 0
        for name, sign_info in zip(self.file_names, self.sign_infos):
            name_size = len(name.encode("utf-8"))
            sign_size = sign_info.size()
            out += (
                u32(name_base + name_offset)
                + u32(name_size)
                + u32(sign_base + sign_offset)
                + u32(sign_size)
            )
            name_offset += name_size
            sign_offset += sign_size
        out += b"".join(n.encode("utf-8") for n in self.file_names)
        out += self.zero_padding
        for sign_info in self.sign_infos:
            out += sign_info.to_bytes()
        return out


class CodeSignBlockHeader:
    MAGIC = CODE_SIGN_MAGIC
    SIZE = 32

    def __init__(self):
        self.block_size = 0
        self.segment_num = 0
        self.flags = 0

    def to_bytes(self) -> bytes:
        return (
            u64(self.MAGIC)
            + u32(1)  # version
            + u32(self.block_size)
            + u32(self.segment_num)
            + u32(self.flags)
            + b"\x00" * 8
        )


class SegmentHeader:
    SIZE = 12

    def __init__(self, seg_type: int, segment_size: int):
        self.type = seg_type
        self.segment_offset = 0
        self.segment_size = segment_size

    def to_bytes(self) -> bytes:
        return u32(self.type) + u32(self.segment_offset) + u32(self.segment_size)


class CodeSignBlock:
    PAGE_SIZE_4K = 4096
    SEGMENT_HEADER_COUNT = 3

    def __init__(self):
        self.header = CodeSignBlockHeader()
        self.segment_headers = []
        self.fs_verity_info_segment = None
        self.hap_info_segment = HapInfoSegment()
        self.native_lib_info_segment = NativeLibInfoSegment()
        self.zero_padding = b""
        self.merkle_tree_map = {}

    def add_merkle_tree(self, key: str, tree: bytes):
        self.merkle_tree_map[key] = tree or b""

    def hap_merkle_tree(self) -> bytes:
        return self.merkle_tree_map.get("Hap", b"")

    def set_code_sign_block_flag(self):
        flags = FLAG_MERKLE_TREE_INLINED
        if self.native_lib_info_segment.section_num() != 0:
            flags += FLAG_NATIVE_LIB_INCLUDED
        self.header.flags = flags

    def set_segment_headers(self):
        self.segment_headers = [
            SegmentHeader(CSB_FSVERITY_INFO_SEG, self.fs_verity_info_segment.size()),
            SegmentHeader(CSB_HAP_META_SEG, self.hap_info_segment.size()),
            SegmentHeader(CSB_NATIVE_LIB_INFO_SEG, self.native_lib_info_segment.size()),
        ]

    def compute_segment_offset(self):
        offset = (
            CodeSignBlockHeader.SIZE
            + len(self.segment_headers) * SegmentHeader.SIZE
            + len(self.zero_padding)
            + len(self.hap_merkle_tree())
        )
        for sh in self.segment_headers:
            sh.segment_offset = offset
            offset += sh.segment_size

    def compute_merkle_tree_offset(self, code_sign_block_offset: int) -> int:
        size_without_tree = (
            CodeSignBlockHeader.SIZE + self.SEGMENT_HEADER_COUNT * SegmentHeader.SIZE
        )
        residual = (code_sign_block_offset + size_without_tree) % self.PAGE_SIZE_4K
        if residual == 0:
            self.zero_padding = b""
        else:
            self.zero_padding = b"\x00" * (self.PAGE_SIZE_4K - residual)
        return code_sign_block_offset + size_without_tree + len(self.zero_padding)

    def to_bytes(self) -> bytes:
        out = self.header.to_bytes()
        for sh in self.segment_headers:
            out += sh.to_bytes()
        out += self.zero_padding
        if any(
            isinstance(e, MerkleTreeExtension)
            for e in self.hap_info_segment.sign_info.extensions
        ):
            out += self.hap_merkle_tree()
        out += self.fs_verity_info_segment.to_bytes()
        out += self.hap_info_segment.to_bytes()
        out += self.native_lib_info_segment.to_bytes()
        return out

    def generate_bytes(self, fsv_tree_offset: int) -> bytes:
        size = (
            CodeSignBlockHeader.SIZE
            + len(self.segment_headers) * SegmentHeader.SIZE
            + len(self.zero_padding)
            + len(self.hap_merkle_tree())
            + self.fs_verity_info_segment.size()
            + self.hap_info_segment.size()
            + self.native_lib_info_segment.size()
        )
        for ext in self.hap_info_segment.sign_info.extensions:
            if isinstance(ext, MerkleTreeExtension):
                ext.merkle_tree_offset = fsv_tree_offset
        self.header.block_size = size
        return self.to_bytes()


# ==== END PART 4 ====


# ============================================================ 代码签名流程


def get_module_content(hap_path) -> str:
    """module.json 内容（去掉换行，与官方实现一致）。"""
    content = read_zip_entry_content(hap_path, "module.json")
    if not content:
        return ""
    return "".join(content.decode("utf-8").splitlines())


def get_bundle_type(module_content: str) -> str:
    if not module_content:
        return ""
    obj = json.loads(module_content)
    app = obj.get("app")
    if not isinstance(app, dict):
        return ""
    value = app.get("bundleType")
    return value if isinstance(value, str) else ""


def parse_plugin_id(profile_content: str) -> str:
    obj = json.loads(profile_content)
    caps = obj.get("app-services-capabilities")
    if not isinstance(caps, dict):
        die("profile 缺少 app-services-capabilities，无法取得 pluginId")
    perm = caps.get("ohos.permission.kernel.SUPPORT_PLUGIN")
    if not isinstance(perm, dict) or "pluginDistributionIDs" not in perm:
        die("profile 缺少 pluginDistributionIDs")
    return perm["pluginDistributionIDs"]


def get_app_identifier(profile_content: str) -> str:
    """按 profile 类型返回 ownerID：debug → DEBUG_LIB_ID，release → app-identifier。"""
    obj = json.loads(profile_content)
    profile_type = obj.get("type")
    if profile_type == "debug":
        return DEBUG_LIB_ID
    if profile_type == "release":
        bundle_info = obj.get("bundle-info")
        if not isinstance(bundle_info, dict) or "app-identifier" not in bundle_info:
            die("profile 缺少 bundle-info.app-identifier")
        return bundle_info["app-identifier"]
    die(f"不支持的 profile type: {profile_type}")


def cms_sign_code(
    data: bytes,
    owner_id: str,
    plugin_id,
    certs: list,
    key_path: Path,
    sign_alg: str,
    sign_time,
) -> bytes:
    """代码签名用 CMS：detached + ownerID（可选 pluginId）属性。"""
    extra = [(OID_OWNER_ID, der_utf8(owner_id))]
    if plugin_id:
        extra.append((OID_PLUGIN_ID, der_utf8(plugin_id)))
    return generate_cms_signed_data(
        data, certs, key_path, sign_alg, True, extra, sign_time
    )


def sign_file_content(
    data: bytes,
    store_tree: bool,
    fsv_tree_offset: int,
    owner_id: str,
    plugin_id,
    page_info_ext,
    certs: list,
    key_path: Path,
    sign_alg: str,
    sign_time,
):
    """对一段内容做 fs-verity 签名，返回 (SignInfo, tree_bytes)。"""
    file_size = len(data)
    tree_bytes, root_hash = fsverity_build_tree(data)
    flags = 0 if fsv_tree_offset == 0 else 1
    disc = fsverity_disc_byte(file_size, root_hash, flags, fsv_tree_offset)
    signature = cms_sign_code(
        fsverity_digest(FS_VERITY_HASH_ALG_SHA256, hashlib.sha256(disc).digest()),
        owner_id,
        plugin_id,
        certs,
        key_path,
        sign_alg,
        sign_time,
    )
    sign_flags = SignInfo.FLAG_MERKLE_TREE_INCLUDED if store_tree else 0
    sign_info = SignInfo(0, sign_flags, file_size, None, signature)
    if store_tree:
        sign_info.add_extension(
            MerkleTreeExtension(len(tree_bytes or b""), fsv_tree_offset, root_hash)
        )
        if page_info_ext is not None and flags != 0:
            disc2 = fsverity_disc_byte_csv2(
                file_size,
                root_hash,
                flags,
                fsv_tree_offset,
                page_info_ext.map_offset,
                page_info_ext.map_size,
                page_info_ext.unit_size,
            )
            signature2 = cms_sign_code(
                fsverity_digest(
                    FS_VERITY_HASH_ALG_SHA256, hashlib.sha256(disc2).digest()
                ),
                owner_id,
                plugin_id,
                certs,
                key_path,
                sign_alg,
                sign_time,
            )
            page_info_ext.set_signature(signature2)
            sign_info.add_extension(page_info_ext)
    return sign_info, tree_bytes


def compute_data_size_and_page_info(zip_obj: "Zip"):
    """代码签名覆盖的数据区大小与 bitmap 扩展（与 computeDataSize 一致）。"""
    data_size = 0
    page_info = None
    for e in zip_obj.entries:
        method = e.header.method
        if e.entry_type == TYPE_RUNNABLE_FILE and method == 0:
            continue
        if e.entry_type == TYPE_BIT_MAP:
            bitmap_off = (
                e.cd.offset
                + ZIP_LOCAL_LENGTH
                + len(e.header.file_name)
                + len(e.header.extra_data)
            )
            page_info = PageInfoExtension(
                bitmap_off, bitmap_off // 4096 * DEFAULT_UNIT_SIZE
            )
            continue
        if e.cd.offset == 0:
            break
        data_size = (
            e.cd.offset
            + ZIP_LOCAL_LENGTH
            + len(e.header.file_name)
            + len(e.header.extra_data)
        )
        break
    if data_size % 4096 != 0:
        die(f"HAP 数据区未按 4K 对齐: {data_size}")
    return data_size, page_info


def build_page_bitmap(hap_path, zip_obj: "Zip") -> bytes:
    """构造 pages 信息 bitmap：可执行条目（.abc/.so/.an）的段范围。"""
    import zipfile

    segments = []
    runnable = []
    max_offset = 0
    for e in zip_obj.entries:
        data_offset = (
            e.cd.offset
            + ZIP_LOCAL_LENGTH
            + len(e.header.file_name)
            + len(e.header.extra_data)
        )
        if data_offset % 4096 != 0:
            die(f"条目 {e.name} 数据区未按 4K 对齐: {data_offset}")
        if e.entry_type == TYPE_RUNNABLE_FILE and e.header.method == 0:
            runnable.append((e.name, data_offset))
            continue
        max_offset = data_offset
        break
    if not runnable:
        return b""
    with zipfile.ZipFile(hap_path) as zf:
        for name, data_offset in runnable:
            if name.endswith(ABC_FILE_SUFFIX):
                size = len(zf.read(name))
                segments.append((ABC_M_CODE, data_offset, data_offset + size))
                continue
            content = zf.read(name)
            for p_offset, p_filesz in elf_exec_segments(content):
                begin = data_offset + p_offset
                segments.append((ELF_M_CODE, begin, begin + p_filesz))
    return generate_bitmap(segments, max_offset)


def sign_native_libs(
    hap_path, owner_id: str, plugin_id, certs: list, key_path: Path, sign_alg: str, sign_time
) -> list:
    """对 HAP 内的原生库（libs/ 前缀或 .an 后缀）逐个签名。"""
    import zipfile

    result = []
    with zipfile.ZipFile(hap_path) as zf:
        names = [
            n
            for n in zf.namelist()
            if not n.endswith("/")
            and (n.endswith(NATIVE_LIB_AN_SUFFIX) or n.startswith(LIBS_PATH_PREFIX))
        ]
        for name in names:
            if name.lower().startswith("hnp/") and name.lower().endswith(".hnp"):
                die(f"暂不支持含 hnp 的 HAP 代码签名: {name}")
            data = zf.read(name)
            sign_info, _ = sign_file_content(
                data, False, 0, owner_id, plugin_id, None, certs, key_path, sign_alg, sign_time
            )
            result.append((name, sign_info))
    return result


def build_code_sign_block(
    hap_path,
    code_sign_offset: int,
    profile_content: str,
    zip_obj: "Zip",
    certs: list,
    key_path: Path,
    sign_alg: str,
    sign_time,
) -> bytes:
    """组装 code sign block 字节。"""
    data_size, page_info_ext = compute_data_size_and_page_info(zip_obj)
    csb = CodeSignBlock()
    fsv_tree_offset = csb.compute_merkle_tree_offset(code_sign_offset)
    csb.fs_verity_info_segment = FsVerityInfoSegment(
        FS_VERITY_VERSION, FS_VERITY_HASH_ALG_SHA256, FS_VERITY_LOG_BLOCK_SIZE
    )
    module_content = get_module_content(hap_path)
    bundle_type = get_bundle_type(module_content)
    plugin_id = parse_plugin_id(profile_content) if bundle_type == "appPlugin" else None
    owner_id = get_app_identifier(profile_content)
    hap_data = Path(hap_path).read_bytes()[:data_size]
    sign_info, tree_bytes = sign_file_content(
        hap_data,
        True,
        fsv_tree_offset,
        owner_id,
        plugin_id,
        page_info_ext,
        certs,
        key_path,
        sign_alg,
        sign_time,
    )
    csb.hap_info_segment.sign_info = sign_info
    csb.add_merkle_tree("Hap", tree_bytes)
    csb.native_lib_info_segment.set_list(
        sign_native_libs(hap_path, owner_id, plugin_id, certs, key_path, sign_alg, sign_time)
    )
    csb.set_segment_headers()
    csb.header.segment_num = len(csb.segment_headers)
    csb.set_code_sign_block_flag()
    csb.compute_segment_offset()
    return csb.generate_bytes(fsv_tree_offset)


# ============================================================ 主签名流程


def check_profile(profile_content: str, certs: list):
    """校验 profile 与签名证书的匹配关系（与 checkProfileInfo 一致）。"""
    obj = json.loads(profile_content)
    profile_type = obj.get("type")
    if profile_type == "release":
        cert_key = "distribution-certificate"
    elif profile_type == "debug":
        cert_key = "development-certificate"
    else:
        die(f"不支持的 profile type: {profile_type}")
    bundle_info = obj.get("bundle-info")
    if not isinstance(bundle_info, dict) or cert_key not in bundle_info:
        die(f"profile 缺少 bundle-info.{cert_key}")
    profile_cert = parse_pem_certificates(bundle_info[cert_key].encode("utf-8"))[0]
    if not profile_cert.subject_cn:
        die("profile 中的证书缺少 CN")
    if profile_cert.subject_cn != certs[0].subject_cn:
        die(
            "profile 证书与签名证书不匹配: "
            f"profile CN={profile_cert.subject_cn} 签名 CN={certs[0].subject_cn}"
        )


def sign_hap_file(
    hap_path,
    out_path,
    certs: list,
    key_path: Path,
    profile_der: bytes,
    sign_alg: str,
    compatible_version: int,
    sign_code: bool,
    permission_sign: bool,
    sign_time,
) -> Path:
    """完整签名流程：重排 ZIP → 代码签名 → 权限签名 → HAP 签名块 → 写出。"""
    hap = Path(hap_path)
    if not hap.exists():
        die(f"hap 文件不存在: {hap}")
    suffix = hap.suffix.lstrip(".").lower()
    support_form = suffix in ("hap", "hsp", "hqf")
    profile_content = cms_extract_signed_content(profile_der).decode("utf-8")
    check_profile(profile_content, certs)

    # 1) 重排对齐并清除旧签名块
    zip_obj = Zip(hap)
    zip_obj.alignment(DEFAULT_ALIGNMENT)
    if sign_code and support_form:
        bitmap = build_page_bitmap(hap, zip_obj)
        if bitmap:
            zip_obj.add_bitmap(bitmap)
            zip_obj.alignment(DEFAULT_ALIGNMENT)
    zip_obj.remove_sign_block()
    fd, tmp_name = tempfile.mkstemp(suffix=".hap")
    os.close(fd)
    tmp_path = Path(tmp_name)
    zip_obj.to_file(tmp_path)

    # 2) 重新解析临时文件，取三段内容
    zip2 = Zip(tmp_path)
    cd_offset = zip2.cd_offset
    raw = tmp_path.read_bytes()
    before_cd = raw[:cd_offset]
    cd_bytes = raw[cd_offset : cd_offset + zip2.eocd.cd_size]
    eocd_bytes = bytearray(raw[zip2.eocd_offset :])

    optional_blocks = [(HAP_PROFILE_BLOCK_ID, profile_der)]

    # 3) 代码签名块
    if sign_code and support_form:
        code_sign_offset = cd_offset + 12 * (len(optional_blocks) + 2) + 12
        code_sign_array = build_code_sign_block(
            tmp_path,
            code_sign_offset,
            profile_content,
            zip2,
            certs,
            key_path,
            sign_alg,
            sign_time,
        )
        value = (
            u32(HAP_CODE_SIGN_BLOCK_ID)
            + u32(len(code_sign_array))
            + u32(code_sign_offset)
            + code_sign_array
        )
        optional_blocks.insert(0, (HAP_PROPERTY_BLOCK_ID, value))

    # 4) 权限签名块
    if permission_sign and sign_code and support_form:
        index = next(
            (
                i
                for i, (t, _) in enumerate(optional_blocks)
                if t == HAP_PROPERTY_BLOCK_ID
            ),
            None,
        )
        if index is None:
            die("权限签名需要先存在 code sign 块")
        module_content, share_files = find_module_and_share_file(tmp_path, zip2)
        if module_content:
            code_sign_value = optional_blocks[index][1]
            permission_bytes = generate_permission_signing_block(
                sign_alg,
                profile_content.encode("utf-8"),
                code_sign_value[12:],
                module_content,
                share_files or b"",
                key_path,
            )
            permission_block = (
                u32(HAP_PERMISSION_SIGN_BLOCK_ID)
                + u32(len(permission_bytes))
                + u32(12 + len(code_sign_value))
                + permission_bytes
            )
            optional_blocks[index] = (
                HAP_PROPERTY_BLOCK_ID,
                code_sign_value + permission_block,
            )

    # 5) 计算内容摘要并生成 HAP 签名块
    contents = [before_cd, cd_bytes, bytes(eocd_bytes)]
    digest = compute_content_digest(
        contents, [v for _, v in optional_blocks], "SHA-256"
    )
    signer_block = generate_hap_signature_scheme_block(
        [digest], certs, key_path, sign_alg, sign_time
    )
    signing_block = generate_hap_signing_block(
        optional_blocks, signer_block, compatible_version
    )

    # 6) 修正 EOCD 的中央目录偏移并写出
    new_cd_offset = cd_offset + len(signing_block)
    struct.pack_into("<I", eocd_bytes, 16, new_cd_offset)
    out = Path(out_path)
    with open(out, "wb") as f:
        f.write(before_cd)
        f.write(signing_block)
        f.write(cd_bytes)
        f.write(eocd_bytes)
    tmp_path.unlink()
    return out


# ==== END PART 5 ====


# ============================================================ hdc 定位


def find_hdc() -> str:
    """解析 hdc：HDC_PATH 环境变量 → res/ → PATH。"""
    env = os.environ.get("HDC_PATH")
    if env:
        if not Path(env).exists():
            die(f"HDC_PATH 指定的文件不存在: {env}")
        return env
    name = "hdc.exe" if sys.platform.startswith("win") else HDC_NAME
    local = RES_DIR / name
    if local.exists():
        os.chmod(local, 0o755)
        return str(local)
    which = shutil.which(name)
    if which:
        return which
    die("未找到 hdc（HDC_PATH / res/ / PATH 均无）。可用 --udid 手动指定设备绕过。")


def read_bundle_name() -> str:
    """从上层工程的 ohos/AppScope/app.json5 读取 bundleName。"""
    aj = ROOT.parent / "ohos/AppScope/app.json5"
    if not aj.exists():
        die(f"找不到 {aj}，无法读取 bundleName（可用 --bundle 指定）")
    m = re.search(r'"bundleName"\s*:\s*"([^"]+)"', aj.read_text())
    if not m:
        die(f"{aj} 中无 bundleName")
    return m.group(1)


# ============================================================ login


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    """接收授权回调。华为 authrouter 用 POST（兼容 GET），
    参数可能在 query、form 或 JSON body 任一处，全部收集。"""

    result = {}

    def _accept(self, raw_body: bytes = b""):
        params = {
            k: v[0]
            for k, v in urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query
            ).items()
        }
        text = raw_body.decode("utf-8", "replace") if raw_body else ""
        if text.strip():
            try:
                obj = json.loads(text)
                if isinstance(obj, dict):
                    params.update({k: str(v) for k, v in obj.items()})
            except json.JSONDecodeError:
                for k, v in urllib.parse.parse_qs(text).items():
                    params.setdefault(k, v[0])
        if not params and text.strip():
            # 回调 body 可能是裸 tempToken（无 key=value 结构）
            params = {"tempToken": text.strip()}
        if params:
            type(self).result = params
        page = ("登录成功！请返回。" if params else "缺少回调参数").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def do_GET(self):  # noqa: N802
        self._accept()

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        self._accept(self.rfile.read(length))

    def log_message(self, *args):
        pass


def wait_temp_token(timeout_s: int = 300) -> str:
    try:
        srv = http.server.HTTPServer(("127.0.0.1", CALLBACK_PORT), _CallbackHandler)
    except OSError as e:
        die(f"监听 127.0.0.1:{CALLBACK_PORT} 失败(端口占用?): {e}")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    info(f"等待浏览器授权回调(最长 {timeout_s}s)...\n授权页: {APPLY_URL}")
    subprocess.run(
        ["xdg-open", APPLY_URL],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    info("如未自动打开，请手动访问上方链接并用华为开发者账号登录。")
    info("正在等待登陆成功回调...")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _CallbackHandler.result:
            break
        time.sleep(0.3)
    srv.shutdown()
    if not _CallbackHandler.result:
        die("超时未收到回调。请确认浏览器完成授权且账号具备开发者权限。")
    info(f"回调参数: {list(_CallbackHandler.result.keys())}")
    return require(
        _CallbackHandler.result, "tempToken", "(回调参数以实际为准，上方已打印 keys)"
    )


def cmd_login(args):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temp_token = wait_temp_token(args.timeout)
    url = (
        f"{AUTH_ROUTER}/temptoken/check?site=CN"
        f"&tempToken={urllib.parse.quote(temp_token)}&appid=1007&version=0.0.0"
    )
    text = http_text(url, raw_dump=DATA_DIR / "raw_temptoken.txt").strip()
    if text.startswith("eyJ"):
        jwt_token = text
    else:
        jwt_token = require(
            require(json.loads(text), "ret", "temptoken/check"),
            "msg",
            "temptoken/check",
        )
    resp = http_json(
        f"{AUTH_ROUTER}/jwToken/check",
        "GET",
        headers={"refresh": "false", "jwtToken": jwt_token},
        raw_dump=DATA_DIR / "raw_jwtoken.json",
    )
    user_info = resp.get("userInfo") or (resp.get("body") or {}).get("userInfo")
    if not user_info:
        die(f"jwToken/check 缺 userInfo: {json.dumps(resp, ensure_ascii=False)[:600]}")
    access_token = require(user_info, "accessToken", "userInfo")
    user_id = user_info.get("userId") or user_info.get("userID")
    if not user_id:
        die(f"userInfo 缺 userId: {json.dumps(user_info, ensure_ascii=False)[:600]}")
    auth = {
        "fetched_at": int(time.time()),
        "accessToken": access_token,
        "userId": user_id,
        "teamId": user_id,
        "nickName": user_info.get("nickName", ""),
        "jwtToken": jwt_token,
    }
    AUTH_FILE.write_text(json.dumps(auth, ensure_ascii=False, indent=1))
    os.chmod(AUTH_FILE, 0o600)
    info(f"登录成功: {auth['nickName']} (uid={user_id}) → {AUTH_FILE}")


# ============================================================ init


def api_headers(auth: dict) -> dict:
    return {
        "oauth2Token": auth["accessToken"],
        "teamId": str(auth["teamId"]),
        "uid": str(auth["userId"]),
    }


def load_auth() -> dict:
    if not AUTH_FILE.exists():
        die("缺少登录凭证，请先执行: hap_sign.py login")
    auth = json.loads(AUTH_FILE.read_text())
    req = urllib.request.Request(
        f"{CONNECT_API}/ups/user-permission-service/v1/user-team-list",
        headers={**api_headers(auth), "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 401:
            die("登录 token 已过期，请重新执行: hap_sign.py login")
        die(f"token 校验失败 HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:300]}")
    except urllib.error.URLError as e:
        die(f"网络失败: {e.reason}")
    if isinstance(result, dict) and (result.get("ret") or {}).get("code") in (401, "401"):
        die("登录 token 已过期，请重新执行: hap_sign.py login")
    return auth


def get_udid(udid_arg=None) -> str:
    if udid_arg:
        return udid_arg
    proc = run([find_hdc(), "shell", "bm", "get", "--udid"])
    for line in proc.stdout.splitlines():
        if line.strip() and "error" not in line.lower():
            token = line.strip().split(":")[-1].strip()
            if len(token) >= 32:
                return token
    die("hdc 取 UDID 失败。连接设备后重试或用 --udid 手动指定。")


def ensure_materials():
    """首次运行时本地生成 EC 密钥与 CSR（私钥不出本机）。"""
    if not (KEY_FILE.exists() and CSR_FILE.exists()):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        run(
            [
                "openssl",
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                str(KEY_FILE),
            ]
        )
        os.chmod(KEY_FILE, 0o600)
        run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                str(KEY_FILE),
                "-subj",
                "/C=CN/O=Personal/OU=Individual Developer/CN=quantum-debug",
                "-out",
                str(CSR_FILE),
            ]
        )
        info("已本地生成密钥与 CSR（私钥不出本机）")


def download(url: str, dest: Path):
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            dest.write_bytes(resp.read())
    except (urllib.error.URLError, OSError) as e:
        die(f"下载失败 {url}: {e}")


def cmd_init(args):
    auth = load_auth()
    ensure_materials()
    headers = api_headers(auth)
    udid = get_udid(args.udid)
    bundle = args.bundle or read_bundle_name()

    # 1) 设备：不存在则注册（deviceType=4）
    list_url = (
        f"{CONNECT_API}/cps/device-manage/v1/device/list"
        "?start=1&pageSize=100&encodeFlag=0"
    )
    devices = http_json(
        list_url, "GET", headers, raw_dump=DATA_DIR / "raw_device_list.json"
    ).get("list", [])
    if not any(d.get("udid") == udid for d in devices):
        http_json(
            f"{CONNECT_API}/cps/device-manage/v1/device/add",
            "POST",
            headers,
            {
                "deviceName": args.device_name or f"quantum-dev-{udid[:10]}",
                "udid": udid,
                "deviceType": 4,
            },
            raw_dump=DATA_DIR / "raw_device_add.json",
        )
        devices = http_json(list_url, "GET", headers).get("list", [])
    if not any(d.get("udid") == udid for d in devices):
        die(f"设备注册后仍查不到 udid={udid}，请检查账号设备配额")
    device_ids = [d["id"] for d in devices]
    info(f"设备清单: {len(device_ids)} 台")

    # 2) 调试证书（certType=1）
    cert_list = http_json(
        f"{CONNECT_API}/cps/harmony-cert-manage/v1/cert/list",
        "GET",
        headers,
        raw_dump=DATA_DIR / "raw_cert_list.json",
    ).get("certList", [])
    debug_certs = [c for c in cert_list if c.get("certType") == 1]
    existing = next((c for c in debug_certs if c.get("certName") == CERT_NAME), None)
    if existing and not CER_FILE.exists():
        info("本地证书缺失(密钥不匹配)，删除云端旧证书重建...")
        http_json(
            f"{CONNECT_API}/cps/harmony-cert-manage/v1/cert/delete",
            "DELETE",
            headers,
            {"certIds": [existing["id"]]},
        )
        existing = None
    if not existing:
        if len(debug_certs) >= 3:  # AGC 调试证书配额 3 张，满额时删最旧
            debug_certs.sort(key=lambda c: c.get("expireTime", 0))
            http_json(
                f"{CONNECT_API}/cps/harmony-cert-manage/v1/cert/delete",
                "DELETE",
                headers,
                {"certIds": [debug_certs[0]["id"]]},
            )
        resp = http_json(
            f"{CONNECT_API}/cps/harmony-cert-manage/v1/cert/add",
            "POST",
            headers,
            {"csr": CSR_FILE.read_text(), "certName": CERT_NAME, "certType": 1},
            raw_dump=DATA_DIR / "raw_cert_add.json",
        )
        harmony_cert = require(resp, "harmonyCert", "cert/add")
        cert_id = require(harmony_cert, "id", "harmonyCert")
        object_id = require(harmony_cert, "certObjectId", "harmonyCert")
        urls = http_json(
            f"{CONNECT_API}/amis/app-manage/v1/objects/url/reapply",
            "POST",
            headers,
            {"sourceUrls": object_id},
            raw_dump=DATA_DIR / "raw_reapply.json",
        )
        url = require(require(urls, "urlsInfo", "reapply")[0], "newUrl", "urlsInfo[0]")
        download(url, CER_FILE)
        info(f"证书: {CER_FILE.name} (id={cert_id})")
    else:
        cert_id = existing["id"]
        info(f"复用云端证书 {CERT_NAME} (id={cert_id})")

    # 3) 调试 Profile（全部设备 + 本证书 + 包名）
    resp = http_json(
        f"{CONNECT_API}/cps/provision-manage/v1/ide/test/provision/add",
        "POST",
        headers,
        {
            "provisionName": f"quantum-debug-{bundle}",
            "aclPermissionList": [],
            "deviceList": device_ids,
            "certList": [cert_id],
            "packageName": bundle,
        },
        raw_dump=DATA_DIR / "raw_provision_add.json",
    )
    url = require(resp, "provisionFileUrl", "provision/add")
    download(url, P7B_FILE)
    info(f"Profile: {P7B_FILE.name} (bundle={bundle})")
    info("init 完成，可执行 sign。")


# ============================================================ sign


def _do_sign(args, out=None) -> Path:
    """执行签名。out 为 None 时默认输出 <hap 同目录>/<name>-signed.hap。"""
    hap = Path(args.hap)
    if not hap.exists():
        die(f"hap 文件不存在: {hap}")
    cert_file = Path(args.cert) if args.cert else CER_FILE
    profile_file = Path(args.profile) if args.profile else P7B_FILE
    key_file = Path(args.key) if args.key else KEY_FILE
    for path, hint in (
        (cert_file, "证书"),
        (profile_file, "Profile"),
        (key_file, "私钥"),
    ):
        if not path.exists():
            die(f"缺少{hint}材料 {path}，请先执行 init")
    if args.sign_alg not in SIGN_ALG_TABLE:
        die(f"不支持的签名算法: {args.sign_alg}（支持 {', '.join(SIGN_ALG_TABLE)}）")

    certs = load_cert_chain(cert_file)
    profile_der = profile_file.read_bytes()
    if out is None:
        out = hap.with_name(hap.stem + "-signed.hap")
    sign_time = _signing_time(datetime.datetime.now(datetime.timezone.utc))
    return sign_hap_file(
        hap,
        out,
        certs,
        key_file,
        profile_der,
        args.sign_alg,
        args.compatible_version,
        args.sign_code,
        args.permission_sign,
        sign_time,
    )


def cmd_sign(args):
    signed = _do_sign(args)
    info(f"签名产物: {signed} ({signed.stat().st_size} bytes)")


# ============================================================ install


def cmd_install(args):
    """hdc install 签名产物。调试 HAP 换签名后重装需 --uninstall（先卸后装）。"""
    if args.hap:
        sources = [Path(args.hap)]
    else:
        directory = ROOT.parent / "build/ohos/hap"
        sources = sorted(
            list(directory.glob("*-signed.hap")) + list(directory.glob("*-signed.hsp"))
        )
        if not sources:
            die(f"{directory} 下没有 *-signed.hap/.hsp，先执行 sign")
    for src in sources:
        if not src.exists():
            die(f"文件不存在: {src}")
    hdc = find_hdc()
    base = [hdc] + (["-t", args.device] if args.device else [])
    if args.uninstall:
        bundle = args.bundle or read_bundle_name()
        proc = subprocess.run(base + ["uninstall", bundle], capture_output=True, text=True)
        info((proc.stdout + proc.stderr).strip())
    proc = subprocess.run(
        base + ["install", "-r"] + [str(s) for s in sources],
        capture_output=True,
        text=True,
    )
    output = (proc.stdout + proc.stderr).strip()
    info(output)
    ok = (
        proc.returncode == 0
        and "successfully" in output.lower()
        and "[fail" not in output.lower()
    )
    if not ok:
        hint = ""
        if "9568322" in output or "not trusted" in output.lower():
            hint = (
                "\n提示: 证书不受设备信任——必须用本机 init 签发的调试证书（同一华为账号），"
                "第三方/官方测试证书无法安装到零售设备"
            )
        elif (
            any(code in output for code in ("9568268", "9568289", "9568226", "9568321"))
            or "signature" in output.lower()
            or "profile" in output.lower()
        ):
            hint = (
                "\n提示: 签名或 Profile 设备不匹配——先 `signinstall --uninstall` 卸旧包重装；"
                "新设备需先跑 init 把 UDID 加进云端设备清单并刷新 Profile"
            )
        die(f"安装失败{hint}")
    info(f"安装成功: {', '.join(s.name for s in sources)}")


def cmd_signinstall(args):
    """签名后立即安装。产物固定写 data/signed.hap，重复执行直接覆盖，
    磁盘上永远只保留这一份签名产物。"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    out = DATA_DIR / "signed.hap"
    signed = _do_sign(args, out)
    info(f"签名产物: {signed} ({signed.stat().st_size} bytes)")
    args.hap = str(signed)
    cmd_install(args)


def cmd_status(_args):
    info(f"资源目录: {RES_DIR}")
    info(f"数据目录: {DATA_DIR}")
    for name in ("hdc", "libusb_shared.so"):
        info(f"  res/{name}: {'✓' if (RES_DIR / name).exists() else '✗'}")
    if AUTH_FILE.exists():
        auth = json.loads(AUTH_FILE.read_text())
        info(
            f"登录: {auth.get('nickName', '?')} teamId={auth.get('teamId')} "
            f"获取于 {time.strftime('%F %T', time.localtime(auth.get('fetched_at', 0)))}"
        )
    else:
        info("登录: 未执行")
    for path in (KEY_FILE, CSR_FILE, CER_FILE, P7B_FILE):
        info(f"  data/{path.name}: {'✓' if path.exists() else '✗'}")


# ============================================================ 入口


def _add_sign_args(p):
    p.add_argument("hap")
    p.add_argument("--cert", help="证书链文件，缺省 data/hinstall-debug.cer")
    p.add_argument("--profile", help="Profile，缺省 data/debug-profile.p7b")
    p.add_argument("--key", help="私钥 PEM，缺省 data/hinstall.key")
    p.add_argument("--sign-alg", default=SIGN_ALG, choices=sorted(SIGN_ALG_TABLE))
    p.add_argument(
        "--compatible-version", type=int, default=DEFAULT_COMPATIBLE_VERSION
    )
    p.add_argument(
        "--sign-code",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="是否生成 code sign block（默认开启）",
    )
    p.add_argument(
        "--permission-sign",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="是否生成 permission sign block（默认开启）",
    )


def _add_install_args(p):
    p.add_argument("--device", help="hdc -t connectkey（多设备时指定）")
    p.add_argument(
        "--uninstall", action="store_true", help="先卸载旧包再安装（签名变更时必须）"
    )
    p.add_argument("--bundle", help="卸载用包名，缺省读 ohos/AppScope/app.json5")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_login = sub.add_parser("login", help="华为账号 OAuth 登录")
    p_login.add_argument("--timeout", type=int, default=300)

    p_init = sub.add_parser("init", help="注册设备/证书/Profile")
    p_init.add_argument("--udid")
    p_init.add_argument("--device-name")
    p_init.add_argument("--bundle")

    p_sign = sub.add_parser("sign", help="对 hap 签名（纯本地算法）")
    _add_sign_args(p_sign)
    p_sign.add_argument("--out")

    p_install = sub.add_parser("install", help="hdc 安装签名产物到设备")
    p_install.add_argument(
        "hap",
        nargs="?",
        help="hap/hsp 文件，缺省用 build/ohos/hap/*-signed.hap(.hsp)",
    )
    _add_install_args(p_install)

    p_si = sub.add_parser(
        "signinstall",
        help="签名后直接安装（产物固定 data/signed.hap，重复执行覆盖）",
    )
    _add_sign_args(p_si)
    _add_install_args(p_si)

    sub.add_parser("status", help="查看状态")

    args = parser.parse_args()
    {
        "login": cmd_login,
        "init": cmd_init,
        "sign": cmd_sign,
        "install": cmd_install,
        "signinstall": cmd_signinstall,
        "status": cmd_status,
    }[args.cmd](args)


if __name__ == "__main__":
    main()

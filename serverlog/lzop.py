"""lzop(.lzo/.tzz) 해제 - 순수 Python 구현.

Lenovo XCC 서비스 데이터(.tzz)는 tar 를 lzop 으로 압축한 파일이다.
표준 라이브러리에 LZO 가 없어서 lzop 컨테이너와 LZO1X 해제를 직접 구현한다.
블록마다 들어 있는 Adler-32/CRC-32 체크섬으로 결과를 검증한다.
"""

import struct
import zlib

MAGIC = b"\x89LZO\x00\r\n\x1a\n"

F_ADLER32_D = 0x00000001
F_ADLER32_C = 0x00000002
F_H_EXTRA_FIELD = 0x00000040
F_CRC32_D = 0x00000100
F_CRC32_C = 0x00000200
F_H_FILTER = 0x00000800
F_H_CRC32 = 0x00001000

LZO1X_METHODS = (1, 2, 3)  # LZO1X_1, LZO1X_1_15, LZO1X_999


class LzoError(ValueError):
    pass


def is_lzop(path):
    with open(path, "rb") as f:
        return f.read(9) == MAGIC


def lzo1x_decompress(src, dst_len):
    """LZO1X 블록 하나를 해제한다 (lzo1x_decompress_safe 와 같은 규칙)."""
    out = bytearray()
    ip = 0
    n = len(src)

    def extend(base):
        # 길이 확장: 0 바이트마다 255 를 더하고 마지막 바이트를 더한다
        nonlocal ip
        add = 0
        while src[ip] == 0:
            add += 255
            ip += 1
        add += base + src[ip]
        ip += 1
        return add

    state = 0
    t = src[0]
    if t > 17:
        ip = 1
        t -= 17
        out += src[ip:ip + t]
        ip += t
        state = t if t < 4 else 4

    try:
        while True:
            t = src[ip]
            ip += 1
            if t < 16:
                if state == 0:
                    # 리터럴 묶음
                    length = (extend(15) if t == 0 else t) + 3
                    out += src[ip:ip + length]
                    ip += length
                    state = 4
                    continue
                nxt = t & 3
                if state == 4:  # 3바이트 일치
                    dist = 1 + 0x0800 + (t >> 2) + (src[ip] << 2)
                    length = 3
                else:           # 2바이트 일치
                    dist = 1 + (t >> 2) + (src[ip] << 2)
                    length = 2
                ip += 1
            elif t >= 64:       # M2
                nxt = t & 3
                dist = 1 + ((t >> 2) & 7) + (src[ip] << 3)
                ip += 1
                length = (t >> 5) + 1
            elif t >= 32:       # M3
                length = (extend(31) if (t & 31) == 0 else (t & 31)) + 2
                v = src[ip] | (src[ip + 1] << 8)
                ip += 2
                dist = 1 + (v >> 2)
                nxt = v & 3
            else:               # M4 (16..31), 거리 0 이면 스트림 끝
                high = (t & 8) << 11
                length = (extend(7) if (t & 7) == 0 else (t & 7)) + 2
                v = src[ip] | (src[ip + 1] << 8)
                ip += 2
                d = high + (v >> 2)
                if d == 0:
                    break
                dist = d + 0x4000
                nxt = v & 3

            pos = len(out) - dist
            if pos < 0:
                raise LzoError("잘못된 LZO 데이터 (참조 위치가 범위를 벗어남)")
            if dist >= length:
                out += out[pos:pos + length]
            else:  # 겹치는 복사 = 길이 dist 인 패턴의 반복
                seg = out[pos:]
                out += (seg * (length // dist + 1))[:length]
            if nxt:
                out += src[ip:ip + nxt]
                ip += nxt
            state = nxt
    except IndexError:
        raise LzoError("LZO 데이터가 중간에 끊겼습니다")
    if len(out) != dst_len or ip > n:
        raise LzoError("LZO 해제 길이가 맞지 않습니다 (%d != %d)" % (len(out), dst_len))
    return bytes(out)


def decompress_file(src_path, dst_path):
    """lzop 파일을 해제해 dst_path 에 쓴다. 해제한 바이트 수를 돌려준다."""
    with open(src_path, "rb") as f, open(dst_path, "wb") as out:
        def read(n):
            b = f.read(n)
            if len(b) != n:
                raise LzoError("lzop 파일이 중간에 끊겼습니다")
            return b

        def u8():
            return read(1)[0]

        def u16():
            return struct.unpack(">H", read(2))[0]

        def u32():
            return struct.unpack(">I", read(4))[0]

        if read(9) != MAGIC:
            raise LzoError("lzop 파일이 아닙니다")
        version = u16()
        u16()  # lib_version
        if version >= 0x0940:
            u16()  # version_needed
        method = u8()
        if version >= 0x0940:
            u8()  # level
        flags = u32()
        if flags & F_H_FILTER:
            raise LzoError("필터가 적용된 lzop 파일은 지원하지 않습니다")
        u32()  # mode
        u32()  # mtime_low
        if version >= 0x0940:
            u32()  # mtime_high
        read(u8())  # 원본 파일 이름
        u32()  # 헤더 체크섬
        if flags & F_H_EXTRA_FIELD:
            read(u32())
            u32()
        if method not in LZO1X_METHODS:
            raise LzoError("지원하지 않는 압축 방식입니다 (method=%d)" % method)

        total = 0
        while True:
            dst_len = u32()
            if dst_len == 0:
                break
            src_len = u32()
            d_adler = u32() if flags & F_ADLER32_D else None
            d_crc = u32() if flags & F_CRC32_D else None
            if src_len < dst_len:
                if flags & F_ADLER32_C:
                    u32()
                if flags & F_CRC32_C:
                    u32()
            data = read(src_len)
            block = data if src_len == dst_len else lzo1x_decompress(data, dst_len)
            if d_adler is not None and zlib.adler32(block) & 0xFFFFFFFF != d_adler:
                raise LzoError("체크섬(Adler-32)이 맞지 않습니다")
            if d_crc is not None and zlib.crc32(block) & 0xFFFFFFFF != d_crc:
                raise LzoError("체크섬(CRC-32)이 맞지 않습니다")
            out.write(block)
            total += dst_len
    return total

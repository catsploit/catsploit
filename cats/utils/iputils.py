#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
def ipv4_to_int32(ipv4: str):
    parts = ipv4.split(".")

    rval = 0
    for part in parts:
        rval = rval * 256 + int(part)

    return rval & 0xFFFFFFFF


def int32_to_ipv4(int32: int):
    int32 = int32 & 0xFFFFFFFF
    rval = list()

    for i in range(4):
        val = int32 & 0xFF
        rval.append(str(val))
        int32 >>= 8

    return ".".join(reversed(rval))


def prefix_to_bitmask(prefix: int):
    mask32 = 0xFFFFFFFF

    return (mask32 << (32 - prefix)) & 0xFFFFFFFF


def maskv4_to_prefix(mask: str):
    prefix = 0
    for part in [int(p) for p in mask.split(".")]:
        if part == 255:
            prefix += 8
        else:
            break
    else:
        return prefix

    bit = 128
    while bit > 0:
        if part & bit == 0:
            break
        bit >>= 1
        prefix += 1

    return prefix


def prefix_to_maskv4(prefix: int):
    mask32 = prefix_to_bitmask(prefix)
    return int32_to_ipv4(mask32)

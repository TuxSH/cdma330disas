#!/usr/bin/env python
# Requires Python >= 3.2 or >= 2.7

__author__    = "TuxSH"
__copyright__ = "Copyright (c) 2017 TuxSH"
__license__   = "GPLv3"
__version__   = "v0.1"

"""
Corelink DMA-330 disassembler
"""

import argparse
from struct import *
def decodeInstruction(buf, off):
    b = unpack_from("<B", buf, off)[0]
    if (b & ~2) == 0x54:
        reg = "DAR" if (b & 1) else "SAR"
        imm = unpack_from("<H", buf, off + 1)[0]
        return off + 3, "{0:14}{1}, #0x{2:X}".format("DDH", reg, imm)
    elif (b & ~2) == 0x5C:
        reg = "DAR" if (b & 1) else "SAR"
        imm = unpack_from("<H", buf, off + 1)[0]
        return off + 3, "{0:14}{1}, #0x{2:X}".format("DNH", reg, imm)
    elif b == 0:
        return off + 1, "END"
    elif b == 0x35:
        b2 = unpack_from("<B", buf, off + 1)[0]
        if (b2 & 7) == 0:
            return off + 2, "{0:14}0x{1:X}".format("FLUSHP", b2 >> 3)
        else:
            return off + 2, "<invalid>"
    elif (b & ~2) == 0xA0:
        b2 = unpack_from("<B", buf, off + 1)
        if (b2 & 7) == 0:
            secure = ", ns" if (b & 1) else ""
            chan = "C{0}".format(b2 & 7)
            imm = unpack_from("<I", buf, off + 2)[0]
            return off + 6, "{0:14}{1}, 0x{1:08X}{2}".format("GO", chan, imm, secure)
        else:
                return off + 2, "<invalid>"
    elif b == 1:
        return off + 1, "KILL"
    elif (b & ~3) == 4:
        kind = ("", "S", "<invalid>", "B")[b & 3]
        return off + 1, "LD"+kind
    elif (b & ~2) == 0x25:
        kind = "B" if (b & 2) else "S"
        b2 = unpack_from("<B", buf, off + 1)[0]
        if (b2 & 7) == 0:
            return off + 2, "{0:14}0x{1:X}".format("LDP"+kind, b2 >> 3)
        else:
            return off + 2, "<invalid>"
    elif (b & ~2) == 0x20:
        b2 = unpack_from("<B", buf, off + 1)[0]
        return off + 2, "{0:14}0x{1:X}".format("LP.{0}".format((b & 2) >> 1), b2 + 1)
    elif (b & ~0x17) == 0x28:
        b2 = unpack_from("<B", buf, off + 1)[0]
        kind = ("", "S", "<invalid>", "B")[b & 3]
        nf = "" if ((b & 0x10) >> 4) else ".FE"
        return off + 2, "{0:14}{1:08X}".format("LPEND{0}{1}.{2}".format(kind, nf, (b & 4) >> 2), off - b2)
    elif b == 0xBC:
        b2 = unpack_from("<B", buf, off + 1)[0]
        if (b2 & ~7) == 0:
            reg = ("SAR", "CCR", "DAR", "<invalid>", "<invalid>", "<invalid>", "<invalid>", "<invalid>")[b2 & 3]
            imm = unpack_from("<I", buf, off + 2)[0]
            return off + 6, "{0:14}{1}, #0x{2:08X}".format("MOV", reg, imm)
        else:
            return off + 2, "<invalid>"
    elif b == 0x18:
        return off + 1, "NOP"
    elif b == 0x12:
        return off + 1, "RMB"
    elif b == 0x34:
        b2 = unpack_from("<B", buf, off + 1)[0]
        if (b2 & 7) == 0:
            return off + 2, "{0:14}0x{1:X}".format("SEV", b2 >> 3)
        else:
            return off + 2, "<invalid>"
    elif (b & ~3) == 8:
        kind = ("", "S", "<invalid>", "B")[b & 3]
        return off + 1, "ST"+kind
    elif (b & ~2) == 0x29:
        kind = "B" if (b & 2) else "S"
        b2 = unpack_from("<B", buf, off + 1)[0]
        if (b2 & 7) == 0:
            return off + 2, "{0:14}0x{1:X}".format("STP"+kind, b2 >> 3)
        else:
            return off + 2, "<invalid>"
    elif b == 0xC:
        return off + 1, "STZ"
    elif b == 0x36:
        b2 = unpack_from("<B", buf, off + 1)[0]
        if (b2 & 5) == 0:
            inv = ", invalid" if (b2 & 2) else ""
            return off + 2, "{0:14}0x{1:X}{2}".format("WFE", b2 >> 3, inv)
        else:
            return off + 2, "<invalid>"
    elif (b & ~3) == 0x30:
        kind = ("single", "periph", "burst", "<invalid>")[b & 3]
        b2 = unpack_from("<B", buf, off + 1)[0]
        if (b2 & 7) == 0:
            return off + 2, "{0:14}0x{1:X}, {2}".format("WFP", b2 >> 3, kind)
        else:
            return off + 2, "<invalid>"
    elif b == 0x13:
        return off + 1, "WMB"
    else:
        return off + 1, "{0:14}0x{1:02X}".format(".DCB", b)

def main(args=None):
    parser = argparse.ArgumentParser(prog="cdma330disas", description="Corelink DMA-330 disassembler.")
    parser.add_argument("infile", help="Input file", type=argparse.FileType("rb"))
    parser.add_argument("-b", "--base-address", help="Base address", type=int, default=0)
    args = parser.parse_args()

    data = args.infile.read()
    args.infile.close()
    off = 0
    while off < len(data):
        newOff, instr = decodeInstruction(data, off)
        print("{0:08X}:    {1}".format(off+args.base_address, instr))
        off = newOff

if __name__ == '__main__':
    main()

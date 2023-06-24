import sys

buf = bytearray()
filesize = 0

opecodeX = [
    None,  "INC", "POP", "NIP", "SWP", "ROT", "DUP", "OVR",
    "EQU", "NEQ", "GTH", "LTH", "JMP", "JCN", "JSR", "STH",
    "LDZ", "STZ", "LDR", "STR", "LDA", "STA", "DEI", "DEO",
    "ADD", "SUB", "MUL", "DIV", "AND", "ORA", "EOR", "SFT"
]

opecode0 = [
    "BRK", "20 ", "40 ", "60 ", "LIT", "LIT", "LIT", "LIT"
]

HEXDUMP_WIDTH = 3
INSTRUCTION_STRING_LEN = 3
MODIFIER_STRING_LEN = 3
OFFSET = 0x100


def put_space(out, length):
    """Put spaces in the output string for padding."""
    for _ in range(length):
        out.append(' ')
    return out


def put_hex8(out, value):
    """Convert an 8-bit value to a hexadecimal string."""
    out.extend(f"{value:02x} ")
    return out


def put_hex16(out, value):
    """Convert a 16-bit value to a hexadecimal string."""
    out.extend(f"{value:04x} ")
    return out


def put_hexdump(out, binary, length):
    """Convert binary data to a hexadecimal dump string."""
    for i in range(length):
        out = put_hex8(out, binary[i])
    return out


def put_asciidump(out, binary, length):
    """Convert binary data to an ASCII dump string."""
    for i in range(length):
        # avoid comment identifier, '(' and ')'
        out.append(chr(binary[i]) if (32 <= binary[i] < 127 and binary[i] not in (ord('('), ord(')'))) else '.')
    return out


def get_immediate_size(opecode):
    """Get the size of the immediate value for an opcode."""
    if (opecode & 0x9f) == 0x80:
        # LIT
        return 2 if (opecode & 0x20) else 1
    else:
        # others
        return 0


def put_instruction(out, opecode):
    """Convert an opcode to its instruction string representation."""
    p0 = len(out)
    op = opecode & 0x1f
    if op:
        m = opecodeX[op]
    else:
        m = opecode0[opecode >> 5]

        if opecode & 0x80:
            # LIT: k modifier is not needed to display
            opecode &= ~0x80
        else:
            # BRK/reserved instructions: no modifier
            opecode &= ~0xe0

    out.extend(m)
    p = len(out)

    if opecode & 0x20:
        out.append('2')
    if opecode & 0x80:
        out.append('k')
    if opecode & 0x40:
        out.append('r')
    out.append('\0')

    return p - p0


def put_disassemble(out, binary, length):
    """Convert binary data to a disassembled instruction string."""
    p = put_instruction(out, binary[0])
    if p < 2:
        out = put_space(out, INSTRUCTION_STRING_LEN + MODIFIER_STRING_LEN - (len(out) - p))
    if length > 1:
        out = put_space(out, 2)
        out = put_hex8(out, binary[1] if length > 1 else 0)
    if length > 2:
        out = put_hex8(out, binary[2] if length > 2 else 0)
    return out


def assemble(line, code, immediate_size):
    """Convert code and immediate value to a disassembled line."""
    p = put_instruction(line, code[0])

    if immediate_size:
        line = put_space(line, INSTRUCTION_STRING_LEN + MODIFIER_STRING_LEN + 1 - (len(line) - p))
        if immediate_size == 1:
            line = put_hex8(line, code[1])
        elif immediate_size == 2:
            line = put_hex16(line, (code[1] << 8) | code[2])
    return line


def put_dump(line, code, length):
    """Put the hexadecimal dump of the code into the output string."""
    for i in range(length):
        line = put_hex8(line, code[i])
    return line


def build_line(line, address, code, remain):
    """Build a line for disassembly or hexadecimal dump."""
    length = get_immediate_size(code[0]) + 1
    dump = 0

    # If remains are not enough, use hex dump instead of disassemble
    if remain < length:
        length = remain
        dump = 1

    line.extend(f"( {put_hex16([], address + OFFSET)}")
    p = len(line)
    line = put_hexdump(line, code, length)
    line = put_space(line, (HEXDUMP_WIDTH * 3) - (len(line) - p))

    p = len(line)
    line = put_asciidump(line, code, length)
    line = put_space(line, HEXDUMP_WIDTH - (len(line) - p))
    line.extend(" )\t")

    if dump:
        line = put_dump(line, code, length)
    else:
        line = put_disassemble(line, code, length - 1)

    return length, line


def disassemble_all():
    """Disassemble the entire code."""
    line = []
    line.extend(f"|{OFFSET:04x}\n")

    i = 0
    while i < filesize:
        length, line = build_line(line, i, buf[i:], filesize - i)
        print(''.join(map(str, line)))
        line = []
        i += length


def loadfile(filename):
    """Load the binary file into memory."""
    global buf, filesize
    try:
        with open(filename, "rb") as fp:
            buf = bytearray(fp.read())
            filesize = len(buf)
        return 0
    except IOError:
        return -1


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"{sys.argv[0]} [filename]")
        sys.exit()

    if loadfile(sys.argv[1]) != 0:
        print("file open error")
        sys.exit()

    disassemble_all()

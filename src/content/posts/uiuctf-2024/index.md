---
title: UIUCTF 2024 – Key in a Haystack
published: 2024-07-07
description: Cheesing a crypto challenge and surprising Neobeo!
tags: [CTF, Crypto]
category: Writeup
draft: false
---

## Key in a Haystack

> I encrpyted the flag, but I lost my key in an annoyingly large haystack. Can you help me find it and decrypt the flag?
>
> ncat --ssl key-in-a-haystack.chal.uiuc.tf 1337
> 
> [chal.py](https://github.com/sahuang/sahuang.github.io/src/content/posts/uiuctf-2024/chal.py)

We are provided with a pretty short script:

```py
from Crypto.Util.number import getPrime
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

from hashlib import md5
from math import prod
import sys

from secret import flag

key = getPrime(40)
haystack = [ getPrime(1024) for _ in range(300) ]
key_in_haystack = key * prod(haystack)

enc_flag = AES.new(
	key = md5(b"%d" % key).digest(),
	mode = AES.MODE_ECB
).encrypt(pad(flag, 16))

sys.set_int_max_str_digits(0)

print(f"enc_flag: {enc_flag.hex()}")
print(f"haystack: {key_in_haystack}")

exit(0)
```

Essentially, the script generates a 40-bit key and a haystack of 300 primes, each of 1024 bits. We are given the multiplication of key and haystack, and the encrypted flag using AES-ECB with the MD5 hash of the key as the key. The goal is to find the key and decrypt the flag.

### Initial attempts

On first sight, there isn't a good algo to handle this other than factorization. Because the product is very large, if we go for the bruteforce approach it would take ages (there should be at least 2^30 40-bit prime and each time we need to do a gigantic division). Throwing it in cado-nfs or yafu is also a bit problematic because the number is really large and my terminal can't handle it. (Perhaps there's a way but I couldn't get it work zzz)

Utaha mentioned that Alpertron could factor fast for 40 bit * 960 bit numbers, and since Alpertron uses ECM, the challenge intended should be something related with ECM tuning and smart factorizations. It turns out fine-tune ECM is indeed intended, but he spent a while during the competition and couldn't get this to work.

At this point the challenge is still 0 solved, then I was told Neobeo blooded it in 5-10 minutes:

![Neobeo saw unblooded crypto](image.png)

![Neobeo blooded for Emu](image-1.png)

This made me wonder if there's some cheesy solution to the challenge, rather than normally solving it, because even with ECM factorization it wouldn't be that fast...

### Cheese

Ok, so now I had the (wrong) impression this challenge could be solved with unintendeds. The first idea came to my mind is some `gcd` related cheese, because if key repeats we can directly use gcd to find the value. I tried to do it locally, and found that the script should be extremely slow in generating and multiplying the primes. However, their server response was instant, this made me suspect the 1024-bit primes were not generated on-the-fly. Instead, there is probably a list of pre-generated primes, and the server just picks a subset of them and multiplies together.

Now let's verify this, first by getting a few haystacks:

```py
from pwn import *
from math import gcd
import sys
from Crypto.Util.number import isPrime

sys.set_int_max_str_digits(0)
haystacks = []

for _ in range(100):
    io = remote("key-in-a-haystack.chal.uiuc.tf", 1337, ssl=True)
    enc = io.recvline().strip().decode().split(": ")[1]
    haystack = io.recvline().strip().decode().split(": ")[1]
    haystacks.append(int(haystack))
    io.close()
```

After this, we can try gcd some of haystack values, and not surprisingly, their gcd are large, and we see they are pre-calculated primes.

![gcd multiple haystack is prime](image-2.png)

Now that we know it, we can just repeatedly gcd the original haystack with the remaining haystacks by keep connecting to remote and get the 40-bit key in the end.

```py
context.log_level = 'error'
target = # the original haystack
while True:
    io = remote("key-in-a-haystack.chal.uiuc.tf", 1337, ssl=True)
    io.recvline()
    haystack = int(io.recvline().strip().decode().split(": ")[1])
    curr = gcd(target, haystack)
    if curr > 1:
        print("oops")
        target //= curr
        print(target)
    io.close()
```

We could just check if final value is 40-bits but I just wanted to print the values to see if there's progress. We got the prime in the end:

```
...
oops
112688939659913406629490487167845386067751231399315913109849555229115292487855950959927027176650843915352473623487892707210009856646885955117602455611720842709305117773571460983279240682765546633507425483859031587490016626471928168564375982601715768031888038723968927176515979535143327347455189285294611760810392555698351
oops
769433032933
```

And the flag:

```py
from Crypto.Cipher import AES
from hashlib import md5

AES.new(
	key = md5(b"769433032933").digest(),
	mode = AES.MODE_ECB
).decrypt(enc_flag)

# b'uiuctf{Finding_Key_Via_Small_Subgroups}\t\t\t\t\t\t\t\t\t'
```

To summarize, the cheese is funny and apparently Neobeo solved it intended but fast.

![Neobeo solved intended](image-3.png)
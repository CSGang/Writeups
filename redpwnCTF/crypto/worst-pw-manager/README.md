# worst-pw-manager

### I found this in-progress password manager on a dead company's website. Seems neat.
### File: https://redpwn.storage.googleapis.com/uploads/ca107f407bfdcd449ecf79e736b827ab66b26e2bd43bbf800f9765fb2c4640c4/worst-pw-manager.zip

Unzipping the zip file gives us a folder, which in turn contains a subfolder called passwords and the eponymous script. The script is a... umm... long, so feel free to read it at your own leisure.

```
import itertools
import string
import pathlib

class KeyByteHolder(): # im paid by LoC, excuse the enterprise level code
    def __init__(self, num):
        assert num >= 0 and num < 256
        self.num = num

    def __repr__(self):
        return hex(self.num)[2:]
def rc4(text, key): # definitely not stolen from stackoverflow
    S = [i for i in range(256)]
    j = 0
    out = bytearray()
    
    #KSA Phase
    for i in range(256):
        j = (j + S[i] + key[i % len(key)].num) % 256
        S[i] , S[j] = S[j] , S[i]

    #PRGA Phase
    i = j = 0
    for char in text:
        i = ( i + 1 ) % 256
        j = ( j + S[i] ) % 256
        S[i] , S[j] = S[j] , S[i]
        out.append(ord(char) ^ S[(S[i] + S[j]) % 256])

    return out

def take(iterator, count):
    return [next(iterator) for _ in range(count)]

flag = itertools.cycle(bytearray(open("flag.txt").read().strip(), "utf-8"))
def generate_key():
    key = [KeyByteHolder(0)] * 8 # TODO: increase key length for more security?
    for i, c in enumerate(take(flag, 8)): # use top secret master password to encrypt all passwords
        key[i].num = c
    return key

def main(args):
    if len(args) != 2:
        print("usage: python {} [import|export|microwave_hdd]".format(args[0]))
        return

    if args[1] == "import":
        pathlib.Path("./passwords").mkdir(exist_ok=True)
        print("Importing from passwords.txt. Please wait...")
        passwords = open("passwords.txt").read()
        for pw_idx, password in enumerate(passwords.splitlines()):
            # 100% completely secure file name generation method
            masked_file_name = "".join([chr((((c - ord("0") + i) % 10) + ord("0")) * int(chr(c) not in string.ascii_lowercase) + (((c - ord("a") + i) % 26) + ord("a")) * int(chr(c) in string.ascii_lowercase)) for c, i in zip([ord(a) for a in password], range(0xffff))])
            with open("passwords/" + str(pw_idx) + "_" + masked_file_name + ".enc", "wb") as f:
                f.write(rc4(password, generate_key()))
        print("Import complete! Passwords securely stored on disk with your private key in flag.txt! You may now safely delete flag.txt.")
    else:
        print("This feature is not implemented. Check back in a later update.")

if __name__ == "__main__":
    import sys
    main(sys.argv)
```

The important parts that we can see at first glance are:
* The passwords are encrypted using RC4, which probably can't be broken
* The keys are always of length 8, and are generated from the flag
* The creepy filenames in the passwords subfolder are all masked using something _100% secure_

We first approached the last point to see how the filenames were being masked.

```
for pw_idx, password in enumerate(passwords.splitlines()):
            # 100% completely secure file name generation method
            masked_file_name = "".join([chr((((c - ord("0") + i) % 10) + ord("0")) * int(chr(c) not in string.ascii_lowercase) + (((c - ord("a") + i) % 26) + ord("a")) * int(chr(c) in string.ascii_lowercase)) for c, i in zip([ord(a) for a in password], range(0xffff))])
```

Long chunk of code, eh? But essentially, there are checks to see if each character in the password is a lowercase character or a number (ie `int(chr(c) not in string.ascii_lowercase))` and `int(chr(c) in string.ascii_lowercase))`). For each character in the password, it's incremented by its position in the password `i` and modulus'd
if needed.

For example, the password 
`password123` 
would be masked as 

```
 p  b  u  v  a  t  x  k  9  1  3 
+0 +1 +2 +3 +4 +5 +6 +7 +8 +9 +a 
```

Impromptu hex usage btw.

Reversing the password names is easy then. Just take that chunk of code and change the `+` to `-`

```
for i in range(len(pw[1])):
      temp_dec += chr((((ord(pw[1][i]) - ord("0") - i) % 10) + ord("0")) * int(pw[1][i] not in string.ascii_lowercase) + (((ord(pw[1][i]) - ord("a") - i) % 26) + ord("a")) * int(pw[1][i] in string.ascii_lowercase))
```

where `pw[1]` contains the masked filename.

Now, for dealing with the key. In all honesty, I had no idea what the itertools module is and what it did, so I just ran `generate_key` with the fake flag `abcdefghijklmnopqrstuvwxyz{_}` to see how the key was created.

```
>>>print(generate_key())

[68, 68, 68, 68, 68, 68, 68, 68]
```

Curious. How about 343 times (the no. of passwords)?

```
[68, 68, 68, 68, 68, 68, 68, 68]
[70, 70, 70, 70, 70, 70, 70, 70]
[78, 78, 78, 78, 78, 78, 78, 78]
[63, 63, 63, 63, 63, 63, 63, 63]
[6b, 6b, 6b, 6b, 6b, 6b, 6b, 6b]
[73, 73, 73, 73, 73, 73, 73, 73]
[7b, 7b, 7b, 7b, 7b, 7b, 7b, 7b]
[66, 66, 66, 66, 66, 66, 66, 66]
[6e, 6e, 6e, 6e, 6e, 6e, 6e, 6e]
[76, 76, 76, 76, 76, 76, 76, 76]
[61, 61, 61, 61, 61, 61, 61, 61]
[69, 69, 69, 69, 69, 69, 69, 69]
[71, 71, 71, 71, 71, 71, 71, 71]
[79, 79, 79, 79, 79, 79, 79, 79]
[64, 64, 64, 64, 64, 64, 64, 64]
[6c, 6c, 6c, 6c, 6c, 6c, 6c, 6c]
[74, 74, 74, 74, 74, 74, 74, 74]
[5f, 5f, 5f, 5f, 5f, 5f, 5f, 5f]
[67, 67, 67, 67, 67, 67, 67, 67]
[6f, 6f, 6f, 6f, 6f, 6f, 6f, 6f]
[77, 77, 77, 77, 77, 77, 77, 77]
[62, 62, 62, 62, 62, 62, 62, 62]
[6a, 6a, 6a, 6a, 6a, 6a, 6a, 6a]
[72, 72, 72, 72, 72, 72, 72, 72]
[7a, 7a, 7a, 7a, 7a, 7a, 7a, 7a]
[65, 65, 65, 65, 65, 65, 65, 65]
[6d, 6d, 6d, 6d, 6d, 6d, 6d, 6d]
[75, 75, 75, 75, 75, 75, 75, 75]
[7d, 7d, 7d, 7d, 7d, 7d, 7d, 7d]
...
```

Ok, that's enough of that. To save you the trouble, the `generate_key` function actually made 8-byte keys by repeating every 8th character of the flag's ASCII encoding. Neat. Since RC4 is a method of symmetric encryption, we can run the `rc4` function again with the same key on the encrypted password inside the file to get back the original password, which we can reverse from the masked filename. All we gotta do is brute force all the possible keys, which we now know are 8 repititions of the same character, until `rc4(encrypted_password, key) == reversed_filename`. That fake flag of ours will come in handy for this segment, as it gives us all possible characters in the flag by repeatedly calling `generate_key`

```
['y', 's', 'n', 'n', 'h', 'p', 'x', 'c', 'k', 's', '{', 'f', 'n', 'v', 'a', 'i', 'q', 'y', 'd', 'l', 't', '_', 'g', 'o', 'w', 'b', 'j', 'r', 'z', 'e', 'm', 'u', '}', 'h', 'p', 'x', 'c', 'k', 's', '{', 'f', 'n', 'v', 'a', 'i', 'q', 'y', 'd', 'l', 't', '_', 'g', 'o', 'w', 'b', 'j', 'r', 'z', 'e', 'm', 'u', '}', 'h', 'p', 'x', 'c', 'k', 's', '{', 'f', 'n', 'v', 'a', 'i', 'q', 'y', 'd', 'l', 't', '_', 'g', 'o', 'w', 'b', 'j', 'r', 'z', 'e', 'm', 'u', '}', 'h', 'p', 'x', 'c', 'k', 's', '{', 'f', 'n', 'v', 'a', 'i', 'q', 'y', 'd', 'l', 't', '_', 'g', 'o', 'w', 'b', 'j', 'r', 'z', 'e', 'm', 'u', '}', 'h', 'p', 'x', 'c', 'k', 's', '{', 'f', 'n', 'v', 'a', 'i', 'q', 'y', 'd', 'l', 't', '_', 'g', 'o', 'w', 'b', 'j', 'r', 'z', 'e', 'm', 'u', '}', 'h', 'p', 'x', 'c', 'k', 's', '{', 'f', 'n', 'v', 'a', 'i', 'q', 'y', 'd', 'l', 't', '_', 'g', 'o', 'w', 'b', 'j', 'r', 'z', 'e', 'm', 'u', '}', 'l', 't', 'u', '_', 'i', 'd', 'r', '_', 'a', 'o', 'u', 'g', '_', 'i', 'y', '_', 'f', 'p', 't', 'd', '_', 'i', 'c', 's', '_', 'h', 't', 'a', 'o', 'p', 'h', 'p', 'x', 'c', 'k', 's', '{', 'f', 'n', 'v', 'a', 'i', 'q', 'y', 'd', 'l', 't', '_', 'g', 'o', 'w', 'b', 'j', 'r', 'z', 'e', 'm', 'u', '}', 'h', 'p', 'x', 'c', 'k', 's', '{', 'f', 'n', 'v', 'a', 'i', 'q', 'y', 'd', 'l', 't', '_', 'g', 'o', 'w', 'b', 'j', 'r', 'z', 'e', 'm', 'u', '}', 'h', 'p', 'x', 'c', 'k', 's', '{', 'f', 'n', 'v', 'a', 'i', 'q', 'y', 'd', 'l', 't', '_', 'g', 'o', 'w', 'b', 'j', 'r', 'z', 'e', 'm', 'u', '}', 'h', 'p', 'x', 'c', 'k', 's', '{', 'f', 'n', 'v', 'a', 'i', 'q', 'y', 'd', 'l', 't', '_', 'g', 'o', 'w', 'b', 'j', 'r', 'z', 'e', 'm', 'u', '}', 'h', 'p', 'x', 'c', 'k', 's', '{', 'f', 'n', 'v', 'a', 'i', 'q', 'y', 'd', 'l', 't', '_', 'g', 'o', 'w', 'b', 'j', 'r', 'z', 'e', 'm', 'u', '}', 'h', 'p', 'x', 'c', 'k', 's', '{', 'f', 'n', 'v', 'a', 'i', 'q', 'y', 'd', 'l', 't', '_', 'g', 'o', 'w', 'b', 'j', 'r', 'z', 'e', 'm', 'u', '}', 'h', 'p', 'x', 'c', 'k', 's', '{', 'f', 'n', 'v', 'a', 'i', 'q', 'y', 'd', 'l', 't', '_', 'g', 'o', 'w', 'b', 'j', 'r', 'z', 'e', ... ]
```

Now that we've obtained every 8th character of the flag in order, we realise that we don't have the flag length. Great. Time to bruteforce again. A length of 43 gives:
`pto_is_stupid_and_python_is_stupid}flag{cry`

Rearrange it, and bingo.

###flag: flag{crypto_is_stupid_and_python_is_stupid}

redpwn really be throwin' shade, eh?

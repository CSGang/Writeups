# worst-pw-manager

### I found this in-progress password manager on a dead company's website. Seems neat.
### File: https://redpwn.storage.googleapis.com/uploads/ca107f407bfdcd449ecf79e736b827ab66b26e2bd43bbf800f9765fb2c4640c4/worst-pw-manager.zip

Unzipping the zip file gives us a folder, which in turn contains a subfolder called passwords and the eponymous script. The script is a... umm... long, so feel free to read it at your own leisure.

`
import itertools
import string
import pathlib

class KeyByteHolder(): # im paid by LoC, excuse the enterprise level code
    def __init__(self, num):
        assert num >= 0 and num < 256
        self.num = num

    def __repr__(self):
        return hex(self.num)[2:]
`
`
def rc4(text, key): # definitely not stolen from stackoverflow
    S = [i for i in range(256)]
    j = 0
    out = bytearray()
`
`
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
`
`
def take(iterator, count):
    return [next(iterator) for _ in range(count)]

flag = itertools.cycle(bytearray(open("flag.txt").read().strip(), "utf-8"))
def generate_key():
    key = [KeyByteHolder(0)] * 8 # TODO: increase key length for more security?
    for i, c in enumerate(take(flag, 8)): # use top secret master password to encrypt all passwords
        key[i].num = c
    return key
`
`
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
`
`
if __name__ == "__main__":
    import sys
    main(sys.argv)
`

The important parts that we can see at first glance are:
* The passwords are encrypted using RC4, which probably can't be broken
* The keys are always of length 8, and are generated from the flag
* The creepy filenames in the passwords subfolder are all masked using something _100% secure_

We first approached the last point to see how the filenames were being masked.

`
for pw_idx, password in enumerate(passwords.splitlines()):
            # 100% completely secure file name generation method
            masked_file_name = "".join([chr((((c - ord("0") + i) % 10) + ord("0")) * int(chr(c) not in string.ascii_lowercase) + (((c - ord("a") + i) % 26) + ord("a")) * int(chr(c) in string.ascii_lowercase)) for c, i in zip([ord(a) for a in password], range(0xffff))])
`

Long chunk of code, eh? But essentially, there are checks to see if each character in the password is a lowercase character or a number (ie `int(chr(c) not in string.ascii_lowercase))` and `int(chr(c) in string.ascii_lowercase))`). For each character in the password, it's incremented by its position in the password `i` and modulus'd
if needed.

For example, the password 
`password123` 
would be masked as 

` p  b  u  v  a  t  x  k  9  1  3 `
`+0 +1 +2 +3 +4 +5 +6 +7 +8 +9 +a `

Impromptu hex usage btw.

Reversing the password names is easy then. Just take that chunk of code and change the `+` to `-`

`for i in range(len(pw[1])):
      temp_dec += chr((((ord(pw[1][i]) - ord("0") - i) % 10) + ord("0")) * int(pw[1][i] not in string.ascii_lowercase) + (((ord(pw[1][i]) - ord("a") - i) % 26) + ord("a")) * int(pw[1][i] in string.ascii_lowercase))`

where pw[1] contains the masked filename.

Now, for dealing with the key... stay tuned


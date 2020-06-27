import glob
import string
import itertools

all_enc = glob.glob("D:/Beta/Alpha/CS/CTF/redpwnCTF/WorstPW/worst-pw-manager/passwords/*.enc")
dec = ["" for i in range(409)]
pw = []
rc4_arr = [b'' for i in range(409)]

for enc in all_enc:
    data = ""
    try:
        with open(enc,'rb') as f:
            data = f.read()
    except:
        pass
    enc = enc.replace("D:/Beta/Alpha/CS/CTF/redpwnCTF/WorstPW/worst-pw-manager/passwords\\", "")
    enc = enc.replace(".enc", "")
    pw = enc.split('_')
    temp_arr = []
    temp_dec = ""
    for i in range(len(pw[1])):
        temp_dec += chr((((ord(pw[1][i]) - ord("0") - i) % 10) + ord("0")) * int(pw[1][i] not in string.ascii_lowercase) + (((ord(pw[1][i]) - ord("a") - i) % 26) + ord("a")) * int(pw[1][i] in string.ascii_lowercase))
    dec[int(pw[0])] = temp_dec
    rc4_arr[int(pw[0])] = data
#print(dec)

class KeyByteHolder(): # im paid by LoC, excuse the enterprise level code
    def __init__(self, num):
        assert num >= 0 and num < 256
        self.num = num

    def __repr__(self):
        return hex(self.num)[2:]
    
flag = itertools.cycle(bytearray(open("flagS.txt").read().strip(), "utf-8"))
#print(flag)

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

def generate_key():
    key = [KeyByteHolder(0)] * 8 # TODO: increase key length for more security?
    for i, c in enumerate(take(flag, 8)): # use top secret master password to encrypt all passwords
        key[i].num = c
    return key

for i in range(29):
    print(generate_key())

print(dec)
print(rc4_arr)
x = []

for i in range(len(dec)):
    for j in range(29):
        key = generate_key()
        if rc4(dec[i], key) == rc4_arr[i]:
            x.append(chr(key[0].num))
print(x)
for i in range(6, 100):
    flag = ['' for i in range(101)]
    index = -1
    for j in x:
        index += 8
        index %= i
        flag[index] = j
    print(''.join(flag))
           




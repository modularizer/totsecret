# Tot Secret

## SHA256
**Much** slower than `hashlib.sha256` but it works nonetheless! Convert any string input into a unique hash.  
```python
s = SHA256("testing123")
print(s)
```

## Miller Rabin
Use the Miller Rabin test to generate/check large prime numbers with high accuracy.
```python
primes = MillerRabinTest.generate_primes(start=123456, stop=123500)
print(primes)
```

## RSA
Encrypt and decrypt messages using two large prime numbers.
```python
p = 796158404950237945787196764633550801236724792940237837217179
q = 1517812095106123640180711070925933522879203927512681025034651
r = RSA(p, q)
r.check("testing the encryption")
```

## PassphraseRSA
Hash a passphrase into a number, then use that as a seed to generate two large prime numbers. Use those prime
numbers to generate private and public keys.
```python
p = PassphraseRSA("this only works with a sufficiently long password2342342342")
p.check("this is a test")
```

## Time-Based One Time Password
Generate and validate time-based one time passwords using a master passphrase.
All that is needed to validate passwords is a real time clock, a processor, and the master passphrase.
This could be done remotely without internet connection. 
Additionally, the code can be easily reproduced in any language.
```python
o = TOTP("butterfly", fmt="%adjective% %adjective% %animal% %99%")
pwd = o.gen()
valid = o.check(pwd)
print(f"{pwd=}, {valid=}")
```
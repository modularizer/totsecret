import time
import math

from sha256 import SHA256


class MillerRabinTest(object):
    known_primes = ()
    desired_confidence = 0.99999
    max_iterations = None

    @staticmethod
    def power(x, y, p):
        res = 1
        x = x % p
        while y > 0:
            if y & 1:
                res = (res * x) % p
            y = y >> 1
            x = (x ** 2) % p
        return res

    @classmethod
    def miller(cls, d, n, a):
        x = cls.power(max([5, a]), d, n)

        if x == 1:
            return True

        while d != n - 1 and x != 1 and x != n-1:
            x = (x * x) % n
            d *= 2
        return x == n - 1

    @classmethod
    def is_prime(cls, n, max_iterations=None, desired_confidence=None, known_primes=None):
        if n <= 1 or n == 4:
            return False
        if n == 3:
            return True

        if known_primes is None:
            known_primes = cls.known_primes

        if max_iterations is None and desired_confidence is not None:
            max_iterations = -math.log(1 - desired_confidence, 4)

        if max_iterations is None:
            if cls.max_iterations is None:
                cls.max_iterations = -math.log(1 - cls.desired_confidence, 4)
            max_iterations = cls.max_iterations

        if n in known_primes:
            return True

        d = n - 1
        while d % 2 == 0:
            d //= 2

        for i in range(int(max_iterations)):
            if not cls.miller(d, n, n - 1 - i):
                return False
        return True

    @classmethod
    def generate_primes(cls, start, stop, max_iterations=None, desired_confidence=None,):
        start += (1 - start % 2)
        stop -= (1 - stop % 2)
        return [i for i in range(start, stop, 2) if cls.is_prime(i, max_iterations=max_iterations,
                                                                 desired_confidence=desired_confidence)]

    @classmethod
    def gen_loop(cls, start=0, save_interval=10000, stop=None, max_primes=None, max_iterations=None,
                 desired_confidence=None, fn=None):
        try:
            if fn is not None:
                last_known = int(open(fn).readlines()[-1])
            else:
                fn = None
        except Exception as e:
            print(e)
            last_known = 0

        if start is None:
            start = last_known
        primes_found = 0
        i = start
        t0 = time.time()
        t_last = t0
        while (stop is None or i < stop) and (max_primes is None or primes_found >= max_primes):
            if stop is None:
                new_primes = cls.generate_primes(i, i + save_interval, max_iterations=max_iterations,
                                                 desired_confidence=desired_confidence)
            else:
                new_primes = cls.generate_primes(i, min([stop, i + save_interval]), max_iterations=max_iterations,
                                                 desired_confidence=desired_confidence)
            new_prime_str = "\n".join(str(p) for p in new_primes)
            if fn is not None:
                open(fn, 'a').write(new_prime_str)
            primes_found += len(new_primes)
            i += save_interval
            t = time.time()
            print(f"{primes_found} under {i}, dt = {t - t_last}, t = {t - t0}")
            t_last = t

    @classmethod
    def next_prime(cls, start=0, max_iterations=None, desired_confidence=None):
        i = start
        while not cls.is_prime(i, max_iterations=max_iterations, desired_confidence=desired_confidence):
            i += 1
        return i

    @staticmethod
    def gen_hash(message, min_bits=1024, salt='SALT'):
        n = min_bits // 256 + 1*((min_bits % 256) != 0)
        hashes = [SHA256(message + f"{salt}{i}") for i in range(n)]
        bin_str = "".join(h.bin_str() for h in hashes).replace(" ", "")
        i = int(bin_str, 2)
        return i

    @classmethod
    def gen_primes_from_passphrase(cls, passphrase, min_bits=1024, salt_p='SALT_P', salt_q='SALT_Q',
                                   max_iterations=None, desired_confidence=None):
        p_hash = cls.gen_hash(passphrase, min_bits, salt_p) % (1 << min_bits)
        q_hash = cls.gen_hash(passphrase, min_bits, salt_q) % (1 << min_bits)
        p = cls.next_prime(p_hash, max_iterations=max_iterations, desired_confidence=desired_confidence)
        q = cls.next_prime(q_hash, max_iterations=max_iterations, desired_confidence=desired_confidence)
        return p, q


if __name__ == "__main__":
    # MillerRabinTest.gen_loop(stop=1e6, fn="primes_list")
    # p, q = MillerRabinTest.gen_primes_from_passphrase("this is my passphrase now")
    primes = MillerRabinTest.generate_primes(start=123456, stop=123500)
    print(primes)

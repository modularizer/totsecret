from rsa import RSA
from miller_rabin import MillerRabinTest


class PassphraseRSA(RSA, MillerRabinTest):
    desired_confidence = 0.99999

    def __init__(self, passphrase, min_bits=1024, salt_p='SALT_P', salt_q='SALT_Q', max_iterations=None,
                 desired_confidence=None, e=65537):
        p, q = self.gen_primes_from_passphrase(passphrase, min_bits=min_bits, salt_p=salt_p, salt_q=salt_q,
                                               max_iterations=max_iterations, desired_confidence=desired_confidence)
        super().__init__(p, q, e=e)


if __name__ == "__main__":
    p = PassphraseRSA("this only works with a sufficiently long password2342342342")
    p.check("this is a test")

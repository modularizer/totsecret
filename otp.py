import time

from sha256 import SHA256
from namednumber import NameFmt


class TOTP(object):
    """generate and validate time-based one time passwords using a master password"""
    time_offset = 1600000000

    mn = 60
    hr = 60 * mn
    dy = 24 * hr
    wk = 7 * dy
    yr = 365.25 * dy
    mnth = yr / 12
    scales = {
        'sec': 1,
        '5sec': 5,
        '15sec': 15,
        '30sec': 30,
        'min': mn,
        '5min': 5*mn,
        '15min': 15*mn,
        '30min': 30*mn,
        'hour': hr,
        '4hour': 4*hr,
        '12hour': 12*hr,
        'day': dy,
        'week': wk,
    }
    scale_keys = list(scales.keys())
    scale_values = list(scales.values())

    def __init__(self, master_password, fmt="%color% %adjective% %animal%"):
        self.digest_hex = SHA256(master_password)
        self.fmt = NameFmt(fmt) if isinstance(fmt, str) else fmt
        self.max_duration = 100
        self.collision_likelihood_pct = 100/int(self.fmt.max_number // ((self.max_duration**2)*len(self.scales)))

    @staticmethod
    def gen_salt_string(extra_salt: dict | str = None, **extra_salt_kw):
        """convert keyword arguments into a string to use as salt to create the one time password
        these same keyword arguments will need to be known in order to validate the password"""
        if extra_salt is None:
            extra_salt = {}
        extra_salt_kw_s = "&".join(f'{k}={v}' for k, v in extra_salt_kw.items())
        if isinstance(extra_salt, dict):
            extra_salt_s = "&".join(f'{k}={v}' for k, v in extra_salt.items())
        else:
            extra_salt_s = str(extra_salt)
        extra_salt_s += extra_salt_kw_s
        return extra_salt_s

    def gen(self, start_time=None, end_time=None, duration_s=None, extra_salt=None, **extra_salt_kw):
        """generate a time-based one time password"""
        extra_salt_s = self.gen_salt_string(extra_salt=extra_salt, **extra_salt_kw)

        resolution = 'sec'
        res_s = self.scales[resolution]
        if start_time is None:
            start_time = time.time()
        if end_time is None and duration_s is None:
            duration_s = 60
            duration = int(duration_s // res_s)
        elif end_time is not None:
            duration = int(end_time - start_time)
        else:
            duration = int(duration_s // res_s)

        while duration > self.max_duration:
            print("decreasing resolution to fit bounds")
            resolution = self.scale_keys[self.scale_keys.index(resolution) + 1]
            new_res_s = self.scales[resolution]
            duration *= (res_s/new_res_s)
            print(duration)
            res_s = new_res_s
            duration_s = res_s * int(duration)

        start_time -= self.time_offset

        count = int(start_time//duration_s)
        h = self.gen_hash(str(count) + extra_salt_s)
        remainder = int((start_time % duration_s) // res_s)
        nscales = len(self.scales)
        n = h * (self.max_duration**2)*nscales + duration *self.max_duration*nscales + remainder*nscales + self.scale_keys.index(resolution)
        return str(self.fmt(n))

    def gen_hash(self, secret):
        """generate a hash using the master password and the input secret string"""
        s = SHA256(str(self.digest_hex) + secret)
        i = int(str(s).split(' ')[-1], 16)
        return i % int(self.fmt.max_number // ((self.max_duration**2)*len(self.scales)))

    def check(self, otp, extra_salt=None, **extra_salt_kw):
        """check if a time based one time password is currently active"""
        extra_salt_s = self.gen_salt_string(extra_salt=extra_salt, **extra_salt_kw)
        n = int(self.fmt(otp))
        nscales = len(self.scales)
        resolution = self.scale_keys[n % nscales]
        n //= nscales
        remainder = n % self.max_duration
        n //= self.max_duration
        duration = n % self.max_duration
        n //= self.max_duration
        h = n

        resolution_s = self.scales[resolution]
        duration_s = duration * resolution_s
        t = time.time()
        t -= self.time_offset
        count = int((t - remainder * resolution_s) // duration_s)

        return h == self.gen_hash(str(count) + extra_salt_s)

    def __call__(self, totp='', **kwargs):
        """either generate or validate a time-based one time password"""
        if not totp:
            return self.gen(**kwargs)
        return self.check(totp)

    def __eq__(self, other):
        """allow using == to check validity of time-based one time passwords"""
        return self.check(other)


if __name__ == "__main__":
    o = TOTP("butterfly", fmt="%adjective% %adjective% %animal% %99%")

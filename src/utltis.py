
#y = α^x mod p 
# cant find x even if you know y, α, and p.

import math
import random
import secrets
import typing
import json
import os


def is_prime(n:int, k:int = 40) -> bool:
    
    if n < 2:
        return False
    
    # small primes check (fast path)
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    if n in small_primes:
        return True
    if any(n % p == 0 for p in small_primes):
        return False

    # write n-1 = d * 2^r
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    # Miller-Rabin rounds
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # [2, n-2]
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True
#generate P
def generate_large_prime(bits:int = 512) -> int:
    while True:
        
        number = random.getrandbits(bits)
        
        # a 512-bit number must be between 2^511 and 2^512 - 1
        if (number < 2**(bits - 1) or number >= 2**bits):
            continue
        
        if number % 2 == 0:
            number += 1
            if number >= 2**bits:   # adding 1 pushed it out of range
                continue           
            
        if is_prime(number):
            return number

#generate alpha
def get_prime_factors(n:int) -> typing.Set[int]:
    factors = set()
    d = 2
    temp = n

    while d * d <= temp:
        while temp % d == 0:
            factors.add(d)
            temp //= d
        d += 1

    if temp > 1:
        factors.add(temp)

    return factors


#y = α^x mod p 
# cant find x even if you know y, α, and p.

import math
import random
import json
import os

def is_prime(n):
    
    if n < 2:
        return False
    
    if n == 2 or n == 3:
        return True
    
    if n % 2 == 0:
        return False
    
    i = 3
    #After the middle point the pairs just flip same factors again in reverse order.
    while i <= math.isqrt(n):
        if n % i == 0:
            return False  # found a divisor not prime
        i += 2            # skip even numbers 

    return True

#generate P
def generate_large_prime(bits=512):
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
def get_prime_factors(n):
    
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

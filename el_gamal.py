#!/usr/bin/env python
# coding: utf-8

# In[3]:


# ElGamal Cryptosystem
'''
NOTE:
How ElGamal cryptosystem works:
1. Alice sends (p, g, y) where p is prime number, g is generator, and y is Alice's public key.
2. Alice generates a private key x in {1, 2, ..., (p-2)}.
3. Alice's public key, y = g^x mod p.
4. Now Bob also creates a private key k in {1, 2, ..., (p-2)}.
5. Bob generates a public key a where a = g^k mod p.
6. Bob has a message M for Alice.
7. Bob encrypts the message, b = My^k (mod p). (Alice will encrypt, b2 = Ma^x (mod p))
8. Alice decrypts the mssage, D = b(a^x)^-1 (mod p). (Bob will decrypt, D2 = b2(y^k)^-1 (mod p))
9. Now, with (p, g, y, a) as public keys and (x, k) as private keys, Alice and Bob are free to send encrypted messages to each other.

ElGamal Multiplication (multiplicative homomorphic property):
1. M1 = "msg 1" -> b1
2. M2 = "msg 2" -> b2
3. C1 = <a1, b1>
4. C2 = <a2, b2>
5. C' = C1 * C2 = <a1 * a2, b1 * b2> = <a', b'>
6. Decrypt C' by b'(a'^priv_key)^-1.
7. D' = M1 * M2
8. If C' was more than just a1, a2, b1, and b2: C' = ((C1 * C2) * C3) * ... * Cn
9. To decrypt: D' = M1 * M2 * M3 * ... * Mn
10. This property can be applied to electronic voting system.
'''

import math
import random
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime
import time

def easy_form(num):
    # This function checks whether p is of the form 2q+1.
    q = (num - 1) / 2

    if q % int(q) == 0:
        is_int = True
    else:
        is_int = False
    
    return is_int

def generator(num, zp):
    # This function finds all factors of p-1 and checks each factor whether its a generator.
    check = easy_form(num)
    
    if check:
        factors = []
        generators = []
        p_minus_one = num - 1

        for i in range(1, p_minus_one+1):
            if p_minus_one % i == 0:
                factors.append(i)
            else:
                continue
        
        #print("\nFactors of p-1 are:", factors)

        for i in zp:
            # Excluding factors 1 and p-1. 
            # For factor of 1, k = p-1, and every value raised to the Euler's totient (p-1) is equal to 1, so trivial.
            # For factor of p-1, k = 1, and every value except for 1 does not equal 1, so trivial, again.
            # All factors must be g_check == True for it to be a generator.
            # Formula is g^k mod p, where g (i) is a potential generator in Zp and k = (p - 1) / Pi (j), where Pi (j) is a factor of p - 1.
            for j in factors[1:len(factors)-1]:
                k = int(p_minus_one / j)
                g_check = pow(i, k, num) != 1
                
                if g_check == False:
                    break

            if g_check:
                generators.append(i)
            else:
                continue

        return generators
        
    else:
        print("\nModulus is not of the form 2q+1.")
        return None

def generate_keys(p, g, initial=True):
    # This function generates the public key y or ciphertext <a, b>.
    # Choosing a private key x.
    x = random.randint(1, p-2)

    # Calculating the public key y.
    y = pow(g, x, p)
    
    if initial:
        # Generating the initial set of keys.
        return (p, g, y), x

    else:
        # Generating public key a for ciphertext.
        return y, x

def encrypt(m, pub, priv, p):
    # This function encrypts the message and ouputs b in <a, b>.
    b = pow(m, 1, p) * pow(pub, priv, p)
    return b

def decrypt(c, priv, p):
    # This function decrypts the encrypted message and outputs D (decrypted message).
    # To decrypt: b(a^x)^-1.
    # Math property: (a^x)^-1 = a^(-x)
    # Making sure to perform pow() with a modulus value makes the program run with significantly better time complexity.
    a_x_inv = pow(c[0], -priv, p)
    a_x_inv_b = a_x_inv * c[1]
    D = pow(a_x_inv_b, 1, p)
    D = long_to_bytes(D)
    D = D.decode()
    return D

def main():
    # This is the main function.
    try:
        # Custom input of prime number p and generator g if available.
        p = int(input("Enter prime number p: "))
        g = int(input("Enter generator g: "))
        auto_gen = False
    
    except ValueError:
        print("\nInsufficient input. Automatically generating values...\n")
        
        # Flag for indicating that values were auto-generated.
        auto_gen = True
        
        # Generating 16 byte prime number.
        p = getPrime(16)

        # Generating Zp list (integers mod p that are relatively prime to p).
        Zp = (i for i in range(1, p))

        # Generating generator value.
        g = generator(p, Zp)
        g = random.choice(g)

        print("Prime number p:", p)
        print("Generator g:", g)
        
        pass

    # Alice (receiver of message M) generates public key (p, g, y), where y = g^x mod p.
    # x is a value in {1,2,...,(p-2)} aka the private key.
    # When generate_keys() function is called for the first time, parameter 'initial' will be set to True.
    A_pub, A_priv = generate_keys(p, g)
    print("\nAlice's public key:", A_pub)
    print("Alice's private key:", A_priv)

    # Bob (sender of message M) first receives Alice's public key.
    # Bob will call generate_keys() function with parameter 'initial' set to False.
    B_pub, B_priv = generate_keys(p, g, False)
    print("\nBob's public key:", B_pub)
    print("Bob's private key:", B_priv)

    try:
        # Only accept custom message if p and g were NOT auto generated.
        if auto_gen == False:
            # Custom input of message M if available.
            M = input("\nEnter message: ")
        
        else:
            M = ""
            time.sleep(1)

        # If input was none or just spaces, resort to default message.
        if not M.strip():
            raise ValueError

    except ValueError:
        print("\nInsufficient input. Automatically generating message...\n")
        print("Default message is: 'A+'")
        
        M = 'A+'

        pass

    # Encoding the message into bytes then to an integer.
    M = M.encode()
    M = bytes_to_long(M)
    
    # Generating ciphertext b.
    b = encrypt(M, A_pub[2], B_priv, p)

    # Ciphertext set <a, b>.
    c = (B_pub, b)
    print("\nCiphertext <a, b> is:", c)
    time.sleep(1)
    print("\nSending Ciphertext to Alice...")
    time.sleep(1)

    # Alice decrypts ciphertext.
    print("\nAlice decrypting ciphertext...")
    time.sleep(1)
    D = decrypt(c, A_priv, p)
    print("\nDecrypted message:", D)

    # Now Alice sending a ciphertext.
    try:
        # Only accept custom message if p and g were NOT auto generated.
        if auto_gen == False:
            # Custom input of message M if available.
            M = input("\nEnter 2nd message: ")
        
        else:
            M = ""
            time.sleep(1)

        # If input was none or just spaces, resort to default message.
        if not M.strip():
            raise ValueError

    except ValueError:
        print("\nInsufficient input. Automatically generating 2nd message...\n")
        print("Default 2nd message is: 'B+'")
        
        M = 'B+'

        pass    

    M = M.encode()
    M = bytes_to_long(M)

    # Generating 2nd ciphertext <a, b>.
    b_2 = encrypt(M, B_pub, A_priv, p)
    c2 = (A_pub[2], b_2)
    print("\n2nd ciphertext <a, b> is:", c2)
    time.sleep(1)
    print("\nSending 2nd ciphertext to Bob...")
    time.sleep(1)

    # Alice decrypts ciphertext.
    print("\nBob decrypting 2nd ciphertext...")
    time.sleep(1)
    D2 = decrypt(c2, B_priv, p)
    print("\n2nd decrypted message:", D2)

if __name__ == "__main__":
    main()

# Try these custom input values:
# p: 17046272524770046353534686869137152713278091964600615657915056667709973353343474041594766244938992279226019693292565663449942960155400316760678921739587963
# g: 12140268236437719850105665944733363170316629236668158185210769983102621413814683308414223003775908531242315094917088251146305097641382752827914042212846640



# In[ ]:





# In[ ]:





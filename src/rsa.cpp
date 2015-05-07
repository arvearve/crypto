//  Simple RSA Implementation for demonstrating a timing attack.
//  * Do not use this in production! *
//  Created by Arve Nygård on 05/05/15.
//  Copyright (c) 2015 Arve Nygård. All rights reserved.
//
#include "rsa.h"
using namespace std;

/*
 * Sets which exponentiation method is to be used.
 *
 * Choose between MODEXP, MODEXP_SLEEP, and POWERLADDER.
 * Default is MODEXP.
 */
void Rsa::setExpFunc(const ExpType expType){
    switch (expType) {
        case POWERLADDER:
            ef = &Rsa::PoweringLadder;
            break;
        case MODEXP:
            ef = &Rsa::ModExp;
            break;
        case MODEXP_SLEEP:
            ef = &Rsa::ModExpSleep;
            break;
        default:
            ef = &Rsa::ModExp;
            break;
    }
}

/*
 * Binary exponentiation of M raised to the power of d (mod n)
 *
 * Default algorithm.
 * Suceptible to timing attacks.
 */
num Rsa::ModExp(const num &M, const num &d, const num &n){
    if (n%2 != 1) {
        cout << "Warning! Exponentiation failed. Modulus must be odd!";
        return 0;
    }
    num r, nprime;
    nPrime(n, r, nprime);
    num M_bar = (M * r) % n;
    num x_bar = r%n;

    long k = numBits(d) - 1; // Loop over bit indices. [0, k-1]
    for (; k >= 0 ; k--) {
        x_bar = MontgomeryProduct(x_bar, x_bar, nprime, r, n);
        if (d.GetBit(k)){
            x_bar = MontgomeryProduct(M_bar, x_bar, nprime, r, n);
        }
    }
    return MontgomeryProduct(x_bar, 1, nprime, r, n);
}

/*
 * Binary exponentiation of M raised to the power of d (mod n).
 *
 * Even more suceptible to timing attacks. (purposely).
 * Used to simulate a slow device.
 * Uses MontgomeryProductSleep.
 */
num Rsa::ModExpSleep(const num &M, const num &d, const num &n){
    if (n%2 != 1) {
        cout << "Warning! Exponentiation failed. Modulus must be odd!";
        return 0;
    }
    num r, nprime;
    nPrime(n, r, nprime);
    num M_bar = (M * r) % n;
    num x_bar = r%n;

    long k = numBits(d) - 1; // Loop over bit indices. [0, k-1]
    for (; k >= 0 ; k--) {
        x_bar = MontgomeryProductSleep(x_bar, x_bar, nprime, r, n);
        if (d.GetBit(k)){
            x_bar = MontgomeryProductSleep(M_bar, x_bar, nprime, r, n);
        }
    }
    return MontgomeryProductSleep(x_bar, 1, nprime, r, n);
}

/*
 * Binary exponentiation of M raised to the power of d (mod n),
 * Using Montgomery Powering ladder
 */
num Rsa::PoweringLadder(const num &message, const num &exponent, const num &modulus){
    num R0 = 1, R1 = message;
    long t = Rsa::numBits(exponent);

    for (long i = t-1; i>=0; i--) {
        if(!exponent.GetBit(i)){
            // The bit is 0
            R1 = (R0*R1) % modulus;
            R0 = (R0*R0) % modulus;
        }
        else {
            // The bit is 1
            R0 = (R0*R1) % modulus;
            R1 = (R1*R1) % modulus;
        }
    }
    return R0;
}

/*
 * Montgomery product
 */
num Rsa::MontgomeryProduct(const num &a, const num &b, const num &nprime, const num &r, const num &n){
    num t = a * b;
    num m = t * nprime % r;
    num u = (t + m*n)/r;
    if(u >=n) { return u-n; }
    else { return u; }
}

/*
 * Montgomery product.
 * Sleeps for five millisecond if a substraction happens in step 5,
 * in order to simulate a slow device and facilitate a timing attack demonstration.
 */
num Rsa::MontgomeryProductSleep(const num &a, const num &b, const num &nprime, const num &r, const num &n){
    num t = a * b;
    num m = t * nprime % r;
    num u = (t + m*n)/r;
    if(u >=n) {
        this_thread::sleep_for(chrono::milliseconds(5));
        return u-n;
    }
    else { return u; }
}

/*
 * Calculates r^{-1} and n' as used in Montgomery exponentiation,
 * as well as the number of bits in n.
 */
void Rsa::nPrime(const num n, num &r, num &nPrime){
    r = 2;
    r.Pow(numBits(n));
    num rInverse = ModInverse(r, n);
    nPrime = (r*rInverse - 1)/n;
}

/*
 * Calculates the modular inverse of a (mod b).
 *
 * http://rosettacode.org/wiki/Modular_inverse#C
 */
num Rsa::ModInverse(num a, num b){
    num b0 = b, t, q;
    num x0 = 0, x1 = 1;
    if (b == 1) return 1;
    while (a > 1) {
        q = a / b;
        t = b, b = a % b; a = t;
        t = x0, x0 = x1 - q * x0, x1 = t;
    }
    if (x1 < 0) x1 += b0;
    return x1;
}

/*
 * Ccounts the number of bits required to represent a decimal number
 */
long Rsa::numBits(const num &n){
    ttmath::Big<32,32> k;
    k.Log(n, 2);
    k = ttmath::Floor(k);
    return k.ToInt() + 1;
}

/*
 * Encrypts a message (number) with the public key,
 * using the selected exponentiation algorithm.
 */
num Rsa::encrypt(const num &M){
    return (this->*ef)(M, e, n);
}

/*
 * Decrypts a message (encrypted by the public key), using the private key.
 * Uses the selected exponentiation algorithm.
 */
num Rsa::decrypt(const num &C){
    return  (this->*ef)(C, d, n);
}

/*
 * Signs a message using the private key
 * This is equivalent to decrypting a ciphertext
 */
num Rsa::sign(const num &M){
    return decrypt(M);
}

/*
 * Print the keys we are using.
 * Used for debugging.
 */
void Rsa::printKeys(){
    cout << "p:\t" << p << endl;
    cout << "q:\t" << q << endl;
    cout << "theta:\t" << theta << endl;
    cout << "n:\t" << n << endl;
    cout << "e:\t" << e << endl;
    cout << "d:\t" << d << endl;
}

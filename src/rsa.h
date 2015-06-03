//  Simple RSA Implementation
//  * Do not use this in production! *
//  Created by Arve Nygård on 05/05/15.
//  Copyright (c) 2015 Arve Nygård. All rights reserved.
//

#ifndef __rsa__rsa__
#define __rsa__rsa__

#include <stdio.h>
#include <assert.h>
#include <math.h>
#include <thread>

#include "lib/ttmath.h"
class Rsa;
typedef ttmath::Int<16> num; // 16 words. 16*64 = 1024 bit
typedef num (*expFunc)(const num&, const num&, const num&);
enum ExpType {
    POWERLADDER,
    MODEXP,
    MODEXP_SLEEP
};

class Rsa {

private:
    num p, q, theta;
    expFunc ef;
public:
    /* These could probably be in a RSAMath module */
    static num MontgomeryProduct(const num &a, const num &b, const num &nprime, const num &r, const num &n);
    static num MontgomeryProductSleep(const num &a, const num &b, const num &nprime, const num &r, const num &n);
    static void nPrime(const num n, num &r, num &nPrime);
    static num ModExp(const num &M, const num &d, const num &n);
    static num ModExpSleep(const num &M, const num &d, const num &n);
    static num PoweringLadder(const num &M, const num &d, const num &n);
    static num ModInverse(const num number, const num n);
    static long numBits(const num &n);
public:
    num e, n, d;
    Rsa(const num p, const num q, const num e):p(p),q(q),e(e){
        n = p*q;
        theta = (p-1)*(q-1);
        d = ModInverse(e, theta);
        ef = &Rsa::ModExp;
    }
    Rsa(){}

    void printKeys();
    num encrypt(const num &M);
    num decrypt(const num &C);
    num sign(const num &M);
    void setExpFunc(const ExpType);
};

#endif /* defined(__rsa__rsa__) */

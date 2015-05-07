//
//  main.cpp
//  rsa
//
//  Created by Arve Nygård on 06/05/15.
//  Copyright (c) 2015 Arve Nygård. All rights reserved.
//

#include <stdio.h>
#include "rsa.h"

void test();
void attack();

int main(int argc, const char * argv[]) {
    test();
    
    return 0;
}


void test(){
    num p,q,e;
    //    p = "72921395523034486567525736371230370633973787029153043254895253767587177948354404505015843041682240089";
    //    q = "27028138044587582353904781804159356623304801440906159575368078211171173680092726609842044176970728203";
    //    e = (1<<16)+1;
    p = 97;
    q = 103;
    e = 31;
    Rsa rsa = Rsa(p,q, e);

    //    rsa.printKeys();

    num M = 25;
    std::cout << "Using Montgomery Exponentiation" << std::endl; // This is default.
    num C = rsa.encrypt(M);
    num S = rsa.decrypt(C);

    std::cout << "Message: "    << M << std::endl;
    std::cout << "Expected Ciphertext: 9943" << std::endl;
    std::cout << "Ciphertext: " << C << std::endl;
    std::cout << "Decrypted: "  << S << std::endl;

    std::cout << std::endl << "Using Powering Ladder" << std::endl;
    rsa.setExpFunc(POWERLADDER);
    C = rsa.encrypt(M);
    S = rsa.decrypt(C);

    std::cout << "Message: "    << M << std::endl;
    std::cout << "Expected Ciphertext: 9943" << std::endl;
    std::cout << "Ciphertext: " << C << std::endl;
    std::cout << "Decrypted: "  << S << std::endl;

    std::cout << std::endl << "Using Montgomery with sleep" << std::endl;
    rsa.setExpFunc(MODEXP_SLEEP);
    C = rsa.encrypt(M);
    S = rsa.decrypt(C);

    std::cout << "Message: "    << M << std::endl;
    std::cout << "Expected Ciphertext: 9943" << std::endl;
    std::cout << "Ciphertext: " << C << std::endl;
    std::cout << "Decrypted: "  << S << std::endl;
}
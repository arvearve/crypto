//
//  rsa-signer.cpp
//  rsa
//
//  Created by Arve Nygård on 27/05/15.
//  Copyright (c) 2015 Arve Nygård. All rights reserved.
//

#include <stdio.h>


#include <stdio.h>
#include <fstream>
#include <stdlib.h>
#include <string.h>
#include "rsa.h"

typedef std::chrono::time_point<std::chrono::system_clock, std::chrono::nanoseconds > timepoint;


/*
 * Data structure to hold message/signature/time it took to sign
 */
struct TimedSignature {
    num message;
    num signed_message;
    std::chrono::nanoseconds duration;
};

/*
 * Output format for TimedResponse when using cout
 */
std::ostream& operator<<(std::ostream& os, const TimedSignature& ts){
    os << ts.message << "," << ts.signed_message << "," << ts.duration.count();
    return os;
}


void timed_sign(const int messageCount);
num bigrand(num max);
Rsa rsa;


/*
 * RNG with arbitrary large size (up to sizeof(num)).
 */
num bigrand(num max = 0){
    num result = 0;
    for (auto &el:result.table) {
        el = random();
    }
    return (max == 0) ? result : result % max;
}


void teste(){
    std::cout << rsa.sign(1283) << std::endl;
}

int main(int argc, const char * argv[]) {

    srandom(time(NULL)); // Seed the RNG
    if (argc != 5) {
        printf("Usage: ./rsa-server <p> <q> <e> <message count>\n");
        printf("Signs <message count> random messages, and saves the result to a CSV file\n");
        return 1;
    }

    // Initiate RSA object with primes from command line.
    rsa = Rsa(argv[1], argv[2], argv[3]);
    printf("Using Montgomery with (2ms) sleep for exponentiation\n");
    rsa.setExpFunc(MODEXP_SLEEP);

    printf("Using the following keys:\n");
    rsa.d = 7;
    rsa.printKeys();

    teste();


    timed_sign(atoi(argv[4]));
    return 0;
}


/*
 * Generate @messageCount random messages, sign them, and return the time it took.
 * It reads UDP datagrams for messages, signs the message and sends back
 * the signature on the same port.
 */
void timed_sign(const int messageCount){
    printf("Signing %d random messages (this could take a while)....\n", messageCount);
    std::ofstream csvfile;

    csvfile.open("pleb.csv");
    csvfile << "N,E" << std::endl;
    csvfile << rsa.n << "," << rsa.e << std::endl;
    csvfile << "message,signature,duration" << std::endl;
    timepoint start, end;
    num message;
    TimedSignature current;
    for (int i = 0; i < messageCount; i++) {
        // Generate a random message between 0 and the modulus.
        message = bigrand(rsa.n);
        current.message = message;
        start = std::chrono::system_clock::now();
        current.signed_message = rsa.sign(message);
        end = std::chrono::system_clock::now();
        current.duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
        csvfile << current << "\n";
    }
    csvfile.close();
    printf("done.\n");
}

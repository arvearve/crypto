//
//  attacker.h
//  rsa
//
//  Created by Arve Nygård on 07/05/15.
//  Copyright (c) 2015 Arve Nygård. All rights reserved.
//

#ifndef __rsa__attacker__
#define __rsa__attacker__

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <chrono>
#include <vector>
#include "../lib/ttmath.h"
#include "../rsa.h"

typedef ttmath::Int<32> num;
struct TimedResponse {
    std::string message;
    std::string response;
    std::chrono::duration<long long, std::ratio<1, 1000000000l> > duration;
};

std::ostream& operator<<(std::ostream& os, const TimedResponse& ts){
    os
    << "Message: " << ts.message
    << "\nSigned: " << ts.response
    << "\nDuration:" << ts.duration.count() << " nanoseconds\n";
    return os;
}

class Attacker {
private:
    struct sockaddr_in server_addr;
    int sock;
    TimedResponse sign_message(const std::string &message);
    TimedResponse sign_message(const int message);
    int current_bit;

public:
    int public_n, public_e;
    int derived_exponent;
    int messages_per_bit;
    Attacker(const char* host, const int port):messages_per_bit(100){
        hostent *hp = gethostbyname(host);
        bzero(&server_addr,sizeof(server_addr));
        memcpy((void *)&server_addr.sin_addr, hp->h_addr_list[0], hp->h_length);
        server_addr.sin_family = AF_INET;
        server_addr.sin_port=htons(port);
        sock = socket(AF_INET,SOCK_DGRAM,0);
    }
    void perform_attack();
    void simulate_attack(int number_messages,int exponent,int index);
    bool ModExpBoolean(const num &M, const num &d, const num &n);
    num MontgomeryProduct(const num &a, const num &b, const num &nprime, const num &r, const num &n, bool &step4);
    void attack_next_bit();

};

#endif /* defined(__rsa__attacker__) */

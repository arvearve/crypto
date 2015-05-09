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
#include "lib/ttmath.h"

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
public:
    Attacker(const char* host, const int port){
        hostent *hp = gethostbyname(host);
        bzero(&server_addr,sizeof(server_addr));
        memcpy((void *)&server_addr.sin_addr, hp->h_addr_list[0], hp->h_length);
        server_addr.sin_family = AF_INET;
        server_addr.sin_port=htons(port);
        sock = socket(AF_INET,SOCK_DGRAM,0);
    }
    void perform_attack();
};

#endif /* defined(__rsa__attacker__) */

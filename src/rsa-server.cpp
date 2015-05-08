//
//  main.cpp
//  rsa
//
//  Created by Arve Nygård on 06/05/15.
//  Copyright (c) 2015 Arve Nygård. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include "rsa.h"



#define BUFSIZE 255

void test();
int vulnerable_sign();
int serve(int port);
Rsa rsa;

int main(int argc, const char * argv[]) {
    if (argc != 5) {
        std::cout << "Usage: ./rsa-server <port> <p> <q> <e>" << std::endl;
        std::cout << "Feed messages as lines to stdin, signed messages will come as output" << std::endl;
        return 1;
    }

    // Initiate RSA object with primes from command line.
    rsa = Rsa(argv[2], argv[3], argv[4]);
    std::cout << "Starting signing server on port " << argv[1] << ". " << std::endl << std::endl;
    std::cout << std::endl << "Using Montgomery with (5ms) sleep for exponentiation" << std::endl;
    rsa.setExpFunc(MODEXP_SLEEP);

    std::cout << "Using the following keys:" << std::endl;
    rsa.printKeys();
    serve(atoi(argv[1]));
    
    return 0;
}

/*
 * Start the server.
 *
 * It reads UDP datagrams for messages, signs the message and sends back 
 * the signature on the same port.
 */
int serve(const int portno){
    int sockfd;
    ssize_t bytes;
    struct sockaddr_in servaddr,cliaddr;
    socklen_t len;
    char mesg[1024];

    sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&servaddr,sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
    servaddr.sin_port=htons(portno);
    bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));

    while (true){
        len = sizeof(cliaddr);
        bytes = recvfrom(sockfd,mesg,1024,0,(struct sockaddr *)&cliaddr,&len);
        mesg[bytes] = 0; // Null terminate the received string
        std::cout << "Asked to sign message: " << mesg;
        num signature = rsa.sign(mesg);
        std::cout << ". Sending response: " << signature << std::endl;
        std::string string_result;
        signature.ToString(string_result);
        sendto(sockfd,string_result.c_str(),string_result.size(),0,(struct sockaddr *)&cliaddr,sizeof(cliaddr));
        bzero(mesg, 1024);
    }
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
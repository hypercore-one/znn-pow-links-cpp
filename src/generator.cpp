#include <ctime>
#include <iostream>
#include <cstring>
#include "sha3.hpp"
#include "pow_links.hpp"
#include "utils.hpp"

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cout << "Usage: ./generator difficulty HashHex key mode\n";
        return 0;
    }
    std::cout << "Starting" << '\n';
    clock_t begin = clock();

    auto data = fromHex<kInSize>(argv[2]);
    auto nonce = argv[3] == NULL ? generate(data, atoi(argv[1])) : strcmp(argv[4], "fast") == 0 ? generateRxFast(data, atoi(argv[1]), argv[3]) : generateRxLight(data, atoi(argv[1]), argv[3]);

    clock_t end = clock();
    double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;

    std::cout << "Generated PoW for a normal transaction in " << int(elapsed_secs) << " seconds" << '\n';
    std::cout << "Difficulty is " << atoi(argv[1]) << '\n';
    std::cout << "Nonce is " << toHex(nonce) << '\n';
    std::cout << "Hash is " << toHex(data) << '\n';
}

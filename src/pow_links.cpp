#include "pow_links.hpp"
//#include "sha3.hpp"
#include "../SHA3IUF/sha3.h"
#include "../RandomX/src/randomx.h"

#include <random>
#include <cstring>

const int kDataSize = 40;

typedef std::array<uint8_t, kDataSize> Data;

void hash(Hash& ans, const Data& in) {
    sha3_context c;
    sha3_Init256(&c);
    sha3_Update(&c, in.data(), in.size());
    const void *digest = sha3_Finalize(&c);
    memcpy(ans.data(), digest, 8);
}

void hashX(Hash& ans, const Data& in, randomx_vm *vm) {
	char hash[RANDOMX_HASH_SIZE];
	randomx_calculate_hash(vm, in.data(), in.size(), hash);
    memcpy(ans.data(), hash, 8);
}

Hash getTarget(int64 difficulty) {
    // set big to 1 << 64
    __int128_t big = (1LL << 62);
    big *= 4;

    __int128_t x = big / difficulty;
    x = big - x;

    Hash h;
    // set little ending encoding
    for (int i = 0; i < 8; i += 1) {
        h[i] = (x >> (i * 8)) & 255;
    }
    return h;
}

bool nextData(Data& d, int max_size) {
    for (int i = 0; i  < max_size; i += 1) {
        d[i] += 1;
        if (d[i] != 0) {
            return true;
        }
    }
    return false;
}

bool greater(const Hash& a, const Hash& b) {
    for (int i = 7; i >= 0; i -= 1) {
        if (a[i] == b[i]) {
            continue;
        }
        return a[i] > b[i];
    }
    return true;
}

Hash getRandomSeed() {
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, 255);
    Hash h;
    for (size_t i = 0; i < h.size(); i += 1) {
        h[i] = dist(rd);
    }
    return h;
}

Data getData(const Hash& entropy, const InHash& in) {
    Data d;
    for (size_t i = 0; i < entropy.size(); i += 1) {
        d[i] = entropy[i];
    }

    for (size_t i = 0; i < in.size(); i += 1) {
        d[i + entropy.size()] = in[i];
    }

    return d;
}

Hash dataToNonce(const Data& data) {
    Hash h;
    for (size_t i = 0; i < h.size(); i += 1) {
        h[i] = data[i];
    }
    return h;
}

randomx_flags getRandomxFlags() {
    randomx_flags flags = randomx_get_flags();
	//flags |= RANDOMX_FLAG_LARGE_PAGES;
	flags |= RANDOMX_FLAG_FULL_MEM;
    return flags;
}

Hash generateRxLight(const InHash& in, int64 difficulty, const char *key) {
    printf("RandomX light mode\n");
    clock_t begin = clock();
    const auto target = getTarget(difficulty);
    const auto entropy = getRandomSeed();
    Hash h;

    const auto flags = randomx_get_flags();
	printf("Allocating RandomX cache\n");

    const auto cache = randomx_alloc_cache(flags);
    if (cache == nullptr) {
		printf("Cache allocation failed\n");
		return h;
	}
    randomx_init_cache(cache, key, sizeof &key);

	printf("Creating RandomX VM\n");
	const auto vm = randomx_create_vm(flags, cache, NULL);
	if (vm == nullptr) {
        printf("Failed to create a virtual machine\n");
		return h;
	}

    clock_t end = clock();
    double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;

    printf("Initialization took %d seconds\n", int(elapsed_secs));
	printf("Starting RandomX PoW generation\n");

    auto data = getData(entropy, in);
    uint32_t count = 0;

    begin = clock();

    while (true) {
        count += 1;
        hashX(h, data, vm);
        
        if (greater(h, target)) {
            randomx_destroy_vm(vm);
	        randomx_release_cache(cache);
            printf("Hash count: %d \n", count);
            end = clock();
            elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
            printf("Hash rate: %d H/s\n", int(count/elapsed_secs));
            return dataToNonce(data);
        }

        if (not nextData(data, entropy.size())) {
            data = getData(getRandomSeed(), in);
        }
    }
}

Hash generateRxFast(const InHash& in, int64 difficulty, const char *key) {
    printf("RandomX fast mode\n");
    clock_t begin = clock();
    const auto target = getTarget(difficulty);
    const auto entropy = getRandomSeed();
    Hash h;

    const auto flags = getRandomxFlags();
	printf("Allocating cache\n");

    const auto cache = randomx_alloc_cache(flags);
    if (cache == nullptr) {
		printf("Cache allocation failed\n");
		return h;
	}
    randomx_init_cache(cache, key, sizeof &key);

	printf("Allocating dataset\n");
	randomx_dataset *myDataset = randomx_alloc_dataset(flags);
    if (myDataset == nullptr) {
        printf("Dataset allocation failed\n");
		return h;
	}

	printf("Initializing dataset\n");
    auto datasetItemCount = randomx_dataset_item_count();
    randomx_init_dataset(myDataset, cache, 0, datasetItemCount);
	randomx_release_cache(cache);

	printf("Creating vm\n");
	const auto vm = randomx_create_vm(flags, nullptr, myDataset);
	if (vm == nullptr) {
        printf("Failed to create a virtual machine\n");
		return h;
	}

    clock_t end = clock();
    double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
    printf("Initialization took: %d \n", int(elapsed_secs));
	printf("Starting hashing\n");

    auto data = getData(entropy, in);
    uint32_t count = 0;

    begin = clock();

    while (true) {
        count += 1;
        hashX(h, data, vm);
        
        if (greater(h, target)) {
            randomx_destroy_vm(vm);
            randomx_release_dataset(myDataset);
            printf("Hash count: %d \n", count);
            end = clock();
            elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
            printf("Hash rate: %d H/s\n", int(count/elapsed_secs));
            return dataToNonce(data);
        }

        if (not nextData(data, entropy.size())) {
            data = getData(getRandomSeed(), in);
        }
    }
}

Hash generate(const InHash& in, int64 difficulty) {
    auto target = getTarget(difficulty);
    auto entropy = getRandomSeed();
    auto data = getData(entropy, in);
    Hash h;
    while (true) {
        hash(h, data);
        
        if (greater(h, target)) {
            return dataToNonce(data);
        }

        if (not nextData(data, entropy.size())) {
            data = getData(getRandomSeed(), in);
        }
    }
}

Hash benchmark(int64 difficulty) {
    auto target = getTarget(difficulty);
    auto data = getData(Hash(), InHash());
    Hash h;
    while (true) {
        hash(h, data);
        
        if (greater(h, target)) {
            return dataToNonce(data);
        }

        if (not nextData(data, kOutSize)) {
            return Hash();
        }
    }
}

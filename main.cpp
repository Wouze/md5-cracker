#include <iostream>
#include <string>
#include <string_view>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cmath>
#include <numeric>
#include <cstring> // For memcpy/memset

// ================== CONFIGURATION ==================
struct Config {
    // Character sets to include in the brute-force attempt
    static constexpr bool WITH_LOWERCASE = true;
    static constexpr bool WITH_UPPERCASE = true;
    static constexpr bool WITH_DIGITS    = true;
    static constexpr bool WITH_SYMBOLS   = false;

    // Password length range to check
    static constexpr int MIN_LENGTH = 1;
    static constexpr int MAX_LENGTH = 8;

    // The hash to crack (8244b815f48530f59449a310c077bd52 -> "654321")
    static constexpr std::string_view TARGET_HASH = "8244b815f48530f59449a310c077bd52";
};

// ================== MD5 CLASS (C++ Wrapper) ==================
class MD5 {
private:
    struct MD5_CTX {
        uint32_t lo, hi;
        uint32_t a, b, c, d;
        unsigned char buffer[64];
    };

    // The core MD5 transformations
    static void body(MD5_CTX *ctx, const unsigned char *data, size_t size) {
        uint32_t a = ctx->a, b = ctx->b, c = ctx->c, d = ctx->d;
        uint32_t saved_a, saved_b, saved_c, saved_d;
        uint32_t m[16];

        #define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
        #define G(x, y, z) ((y) ^ ((z) & ((x) ^ (y))))
        #define H(x, y, z) ((x) ^ (y) ^ (z))
        #define I(x, y, z) ((y) ^ ((x) | ~(z)))
        #define STEP(f, w, x, y, z, data, t, s) (w += f(x,y,z) + data + t, w = (w<<s)|(w>>(32-s)), w += x)

        const unsigned char *ptr = data;
        do {
            saved_a = a; saved_b = b; saved_c = c; saved_d = d;

            // This is the CRITICAL FIX:
            // Safely copy 64 bytes of data into a 16-element uint32_t array (m).
            // This avoids the unaligned memory access that caused the crash.
            for (int i = 0; i < 16; ++i) {
                m[i] = (uint32_t)ptr[i * 4] | ((uint32_t)ptr[i * 4 + 1] << 8) | ((uint32_t)ptr[i * 4 + 2] << 16) | ((uint32_t)ptr[i * 4 + 3] << 24);
            }

            // Perform all 64 steps of the MD5 algorithm
            STEP(F, a, b, c, d, m[0], 0xd76aa478, 7); STEP(F, d, a, b, c, m[1], 0xe8c7b756, 12); STEP(F, c, d, a, b, m[2], 0x242070db, 17); STEP(F, b, c, d, a, m[3], 0xc1bdceee, 22);
            STEP(F, a, b, c, d, m[4], 0xf57c0faf, 7); STEP(F, d, a, b, c, m[5], 0x4787c62a, 12); STEP(F, c, d, a, b, m[6], 0xa8304613, 17); STEP(F, b, c, d, a, m[7], 0xfd469501, 22);
            STEP(F, a, b, c, d, m[8], 0x698098d8, 7); STEP(F, d, a, b, c, m[9], 0x8b44f7af, 12); STEP(F, c, d, a, b, m[10], 0xffff5bb1, 17); STEP(F, b, c, d, a, m[11], 0x895cd7be, 22);
            STEP(F, a, b, c, d, m[12], 0x6b901122, 7); STEP(F, d, a, b, c, m[13], 0xfd987193, 12); STEP(F, c, d, a, b, m[14], 0xa679438e, 17); STEP(F, b, c, d, a, m[15], 0x49b40821, 22);

            STEP(G, a, b, c, d, m[1], 0xf61e2562, 5); STEP(G, d, a, b, c, m[6], 0xc040b340, 9); STEP(G, c, d, a, b, m[11], 0x265e5a51, 14); STEP(G, b, c, d, a, m[0], 0xe9b6c7aa, 20);
            STEP(G, a, b, c, d, m[5], 0xd62f105d, 5); STEP(G, d, a, b, c, m[10], 0x02441453, 9); STEP(G, c, d, a, b, m[15], 0xd8a1e681, 14); STEP(G, b, c, d, a, m[4], 0xe7d3fbc8, 20);
            STEP(G, a, b, c, d, m[9], 0x21e1cde6, 5); STEP(G, d, a, b, c, m[14], 0xc33707d6, 9); STEP(G, c, d, a, b, m[3], 0xf4d50d87, 14); STEP(G, b, c, d, a, m[8], 0x455a14ed, 20);
            STEP(G, a, b, c, d, m[13], 0xa9e3e905, 5); STEP(G, d, a, b, c, m[2], 0xfcefa3f8, 9); STEP(G, c, d, a, b, m[7], 0x676f02d9, 14); STEP(G, b, c, d, a, m[12], 0x8d2a4c8a, 20);

            STEP(H, a, b, c, d, m[5], 0xfffa3942, 4); STEP(H, d, a, b, c, m[8], 0x8771f681, 11); STEP(H, c, d, a, b, m[11], 0x6d9d6122, 16); STEP(H, b, c, d, a, m[14], 0xfde5380c, 23);
            STEP(H, a, b, c, d, m[1], 0xa4beea44, 4); STEP(H, d, a, b, c, m[4], 0x4bdecfa9, 11); STEP(H, c, d, a, b, m[7], 0xf6bb4b60, 16); STEP(H, b, c, d, a, m[10], 0xbebfbc70, 23);
            STEP(H, a, b, c, d, m[13], 0x289b7ec6, 4); STEP(H, d, a, b, c, m[0], 0xeaa127fa, 11); STEP(H, c, d, a, b, m[3], 0xd4ef3085, 16); STEP(H, b, c, d, a, m[6], 0x04881d05, 23);
            STEP(H, a, b, c, d, m[9], 0xd9d4d039, 4); STEP(H, d, a, b, c, m[12], 0xe6db99e5, 11); STEP(H, c, d, a, b, m[15], 0x1fa27cf8, 16); STEP(H, b, c, d, a, m[2], 0xc4ac5665, 23);

            STEP(I, a, b, c, d, m[0], 0xf4292244, 6); STEP(I, d, a, b, c, m[7], 0x432aff97, 10); STEP(I, c, d, a, b, m[14], 0xab9423a7, 15); STEP(I, b, c, d, a, m[5], 0xfc93a039, 21);
            STEP(I, a, b, c, d, m[12], 0x655b59c3, 6); STEP(I, d, a, b, c, m[3], 0x8f0ccc92, 10); STEP(I, c, d, a, b, m[10], 0xffeff47d, 15); STEP(I, b, c, d, a, m[1], 0x85845dd1, 21);
            STEP(I, a, b, c, d, m[8], 0x6fa87e4f, 6); STEP(I, d, a, b, c, m[15], 0xfe2ce6e0, 10); STEP(I, c, d, a, b, m[6], 0xa3014314, 15); STEP(I, b, c, d, a, m[13], 0x4e0811a1, 21);
            STEP(I, a, b, c, d, m[4], 0xf7537e82, 6); STEP(I, d, a, b, c, m[11], 0xbd3af235, 10); STEP(I, c, d, a, b, m[2], 0x2ad7d2bb, 15); STEP(I, b, c, d, a, m[9], 0xeb86d391, 21);

            a += saved_a; b += saved_b; c += saved_c; d += saved_d;
            ptr += 64;
        } while (size -= 64);

        ctx->a = a; ctx->b = b; ctx->c = c; ctx->d = d;
    }

public:
    static std::string hash(std::string_view text) {
        MD5_CTX ctx;

        // Init
        ctx.a = 0x67452301; ctx.b = 0xefcdab89;
        ctx.c = 0x98badcfe; ctx.d = 0x10325476;
        ctx.lo = 0; ctx.hi = 0;

        // Update
        size_t length = text.length();
        ctx.lo = (uint32_t)(length * 8); // Store length in bits
        const unsigned char *data_ptr = reinterpret_cast<const unsigned char*>(text.data());

        size_t offset = 0;
        while (length - offset >= 64) {
            body(&ctx, data_ptr + offset, 64);
            offset += 64;
        }

        // Final
        size_t final_block_len = length - offset;
        memcpy(ctx.buffer, data_ptr + offset, final_block_len);
        ctx.buffer[final_block_len] = 0x80;

        if (final_block_len >= 56) {
            memset(ctx.buffer + final_block_len + 1, 0, 64 - final_block_len - 1);
            body(&ctx, ctx.buffer, 64);
            memset(ctx.buffer, 0, 56);
        } else {
            memset(ctx.buffer + final_block_len + 1, 0, 56 - final_block_len - 1);
        }

        memcpy(ctx.buffer + 56, &ctx.lo, 4);
        memcpy(ctx.buffer + 60, &ctx.hi, 4);
        body(&ctx, ctx.buffer, 64);

        // To Hex String (handling byte order for portability)
        auto to_hex = [](uint32_t n) {
            std::ostringstream ss;
            ss << std::hex << std::setfill('0')
               << std::setw(2) << (n & 0xff)
               << std::setw(2) << ((n >> 8) & 0xff)
               << std::setw(2) << ((n >> 16) & 0xff)
               << std::setw(2) << ((n >> 24) & 0xff);
            return ss.str();
        };

        return to_hex(ctx.a) + to_hex(ctx.b) + to_hex(ctx.c) + to_hex(ctx.d);
    }
};

// ================== BRUTE-FORCE CRACKER ==================
// (This part of the code was correct and remains unchanged)
class Cracker {
private:
    std::string m_charset;
    std::atomic<bool> m_found_flag{false};
    std::atomic<uint64_t> m_attempts{0};
    std::string m_found_password;

    std::string generate_string_from_index(uint64_t index, int length) const {
        std::string result(length, ' ');
        if (index == 0) { // Handle index 0 separately
            for(int i = 0; i < length; ++i) result[i] = m_charset[0];
            return result;
        }
        for (int i = length - 1; i >= 0; --i) {
            result[i] = m_charset[index % m_charset.size()];
            index /= m_charset.size();
        }
        return result;
    }

    void worker(int length, uint64_t start_index, uint64_t end_index) {
        for (uint64_t i = start_index; i < end_index && !m_found_flag; ++i) {
            std::string candidate = generate_string_from_index(i, length);
            if (MD5::hash(candidate) == Config::TARGET_HASH) {
                m_found_flag = true;
                m_found_password = candidate;
                return;
            }
            m_attempts++;
        }
    }

public:
    Cracker() {
        if (Config::WITH_LOWERCASE) m_charset += "abcdefghijklmnopqrstuvwxyz";
        if (Config::WITH_UPPERCASE) m_charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        if (Config::WITH_DIGITS)    m_charset += "0123456789";
        if (Config::WITH_SYMBOLS)   m_charset += "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~";
    }

    void run() {
        std::cout << "[*] Charset: " << m_charset << " (Size: " << m_charset.size() << ")" << std::endl;
        std::cout << "[*] Target MD5: " << Config::TARGET_HASH << std::endl;
        unsigned int num_threads = std::thread::hardware_concurrency();
        std::cout << "[*] Using " << num_threads << " threads." << std::endl;

        auto total_start_time = std::chrono::high_resolution_clock::now();
        std::thread reporter([this, &total_start_time] {
            uint64_t last_attempts = 0;
            auto last_time = std::chrono::high_resolution_clock::now();
            while (!m_found_flag) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                uint64_t current_attempts = m_attempts.load();
                auto current_time = std::chrono::high_resolution_clock::now();
                double duration = std::chrono::duration<double>(current_time - last_time).count();
                if (duration > 0) {
                    uint64_t hps = static_cast<uint64_t>((current_attempts - last_attempts) / duration);
                    std::cout << "\r[*] Status: Cracking... " << hps << " H/s" << std::flush;
                }
                last_attempts = current_attempts;
                last_time = current_time;
            }
        });

        for (int len = Config::MIN_LENGTH; len <= Config::MAX_LENGTH && !m_found_flag; ++len) {
            std::cout << "\n[*] Trying length: " << len << std::endl;
            uint64_t total_combinations = static_cast<uint64_t>(pow(m_charset.size(), len));
            uint64_t chunk_size = (total_combinations + num_threads - 1) / num_threads;
            std::vector<std::thread> threads;
            for (unsigned int t = 0; t < num_threads; ++t) {
                uint64_t start = t * chunk_size;
                uint64_t end = std::min(start + chunk_size, total_combinations);
                if (start >= end) continue;
                threads.emplace_back(&Cracker::worker, this, len, start, end);
            }
            for (auto& th : threads) th.join();
        }

        reporter.join();
        auto total_end_time = std::chrono::high_resolution_clock::now();
        double total_duration = std::chrono::duration<double>(total_end_time - total_start_time).count();

        std::cout << std::endl;
        if (m_found_flag) {
            std::cout << "[+] SUCCESS!" << std::endl;
            std::cout << "    Password: " << m_found_password << std::endl;
            std::cout << "    Attempts: " << m_attempts << std::endl;
            std::cout << "    Time: " << std::fixed << std::setprecision(2) << total_duration << "s" << std::endl;
        } else {
            std::cout << "[-] FAILED. Password not found within the given constraints." << std::endl;
        }
    }
};

int main() {
    Cracker cracker;
    cracker.run();
    return 0;
}
#define _CRT_SECURE_NO_WARNINGS
#include <array>
#include <string>
#include <algorithm>
#include <openssl/evp.h>

const int PROTOCOL = 208;
const std::string GAME_VERSION = "4.59";

namespace hash {
    std::string sha256(const std::string& input) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx, input.c_str(), input.length());
        EVP_DigestFinal_ex(ctx, digest, &digest_len);
        EVP_MD_CTX_free(ctx);

        std::string hash;
        hash.reserve(digest_len * 2);
        for (unsigned int i = 0; i < digest_len; ++i) {
            char buffer[3];
            sprintf(buffer, "%02x", digest[i]);
            hash.append(buffer);
        }

        std::transform(hash.begin(), hash.end(), hash.begin(), ::tolower);
        return hash;
    }

    std::string md5(const std::string& input) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
        EVP_DigestUpdate(ctx, input.c_str(), input.length());
        EVP_DigestFinal_ex(ctx, digest, &digest_len);
        EVP_MD_CTX_free(ctx);

        char md5string[33];
        for (int i = 0; i < 16; ++i) {
            sprintf(&md5string[i * 2], "%02x", digest[i]);
        }
        md5string[32] = '\0';

        std::string hash(md5string);
        std::transform(hash.begin(), hash.end(), hash.begin(), ::toupper);
        return hash;
    }
}

namespace proton {
    std::string generate_klv(const int protocol, const std::string& version, const std::string& rid) {
        constexpr std::array salts = {
            "e9fc40ec08f9ea6393f59c65e37f750aacddf68490c4f92d0d2523a5bc02ea63",
            "c85df9056ee603b849a93e1ebab5dd5f66e1fb8b2f4a8caef8d13b9f9e013fa4",
            "3ca373dffbf463bb337e0fd768a2f395b8e417475438916506c721551f32038d",
            "73eff5914c61a20a71ada81a6fc7780700fb1c0285659b4899bc172a24c14fc1"
        };

        const std::string protocolStr = std::to_string(protocol);

        static const std::array constant_values = {
            hash::sha256(hash::md5(hash::sha256(protocolStr))),
            hash::sha256(hash::sha256(version)),
            hash::sha256(hash::sha256(protocolStr) + salts[3])
        };

        return hash::sha256(constant_values[0]
            + salts[0]
            + constant_values[1]
            + salts[1]
            + hash::sha256(hash::md5(hash::sha256(rid)))
            + salts[2]
            + constant_values[2]
        );
    }
}

std::string create_klv(const std::string& rid) {
    const std::string protocol = "208";
    const std::string game_version = "4.59";
    const std::string hash = "1431658473";

    constexpr std::array salts = {
        "832aac071ffbcfc15bfe1d0a7ad15221",
        "709296ddd04fc4074a7b443ecc0799aa",
        "623de1e8fff22a2b3e0d7e01593e7c22",
        "bb835e5a57e6c88e2449499ca487ced2",
        "ea76e4d6009282186063fe9465f2d9ab"
    };

    auto GetMD5CheckSumAsString = [](const std::string& input) -> std::string {
        return hash::md5(input);
    };

    return GetMD5CheckSumAsString(GetMD5CheckSumAsString(GetMD5CheckSumAsString(game_version))
        + salts[0]
        + GetMD5CheckSumAsString(GetMD5CheckSumAsString(GetMD5CheckSumAsString(protocol)))
        + salts[1]
        + salts[2]
        + GetMD5CheckSumAsString(GetMD5CheckSumAsString(rid))
        + salts[3]
        + GetMD5CheckSumAsString(GetMD5CheckSumAsString(hash))
        + salts[4]
    );
}

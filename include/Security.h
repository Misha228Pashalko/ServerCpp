#pragma once
#include <string>
#include <vector>
#include <map>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <json/json.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <random>
#include <cstdint>
#include <cstring>

namespace Security {

    // ==============================================
    // Constants
    // ==============================================
    constexpr int AES_KEY_SIZE = 256;
    constexpr int RSA_KEY_SIZE = 2048;
    constexpr int CHACHA_KEY_SIZE = 256;
    constexpr int SALT_SIZE = 16;
    constexpr int IV_SIZE = 12;
    constexpr int HMAC_SIZE = 32;
    constexpr int JWT_EXPIRY = 3600; // 1 hour

    // ==============================================
    // Utility Functions
    // ==============================================
    std::string base64Encode(const std::string& data);
    std::string base64Decode(const std::string& data);
    std::string generateRandomBytes(size_t length);
    std::string hexEncode(const std::string& data);
    std::string hexDecode(const std::string& data);

    // ==============================================
    // Hashing
    // ==============================================
    std::string sha256(const std::string& data);
    std::string sha512(const std::string& data);
    std::string hmacSha256(const std::string& key, const std::string& data);
    std::string hmacSha512(const std::string& key, const std::string& data);

    // ==============================================
    // Encryption
    // ==============================================
    class AES {
    public:
        static std::string encrypt(const std::string& plaintext, const std::string& key);
        static std::string decrypt(const std::string& ciphertext, const std::string& key);
    };

    class RSA {
    public:
        static std::string encrypt(const std::string& plaintext, const std::string& publicKey);
        static std::string decrypt(const std::string& ciphertext, const std::string& privateKey);
        static std::pair<std::string, std::string> generateKeyPair();
    };

    class ChaCha20 {
    public:
        static std::string encrypt(const std::string& plaintext, const std::string& key, const std::string& nonce);
        static std::string decrypt(const std::string& ciphertext, const std::string& key, const std::string& nonce);
    };

    // ==============================================
    // JWT (JSON Web Tokens)
    // ==============================================
    class JWT {
    public:
        static std::string generate(const std::string& payload, const std::string& secret);
        static bool verify(const std::string& token, const std::string& secret);
        static Json::Value decodePayload(const std::string& token);
    };

    // ==============================================
    // OAuth2 and OpenID Connect
    // ==============================================
    class OAuth2 {
    public:
        static std::string generateAuthCode(const std::string& clientId, const std::string& redirectUri);
        static std::string generateAccessToken(const std::string& clientId, const std::string& clientSecret);
        static bool validateAccessToken(const std::string& token);
    };

    // ==============================================
    // CSRF Protection
    // ==============================================
    class CSRF {
    public:
        static std::string generateToken();
        static bool validateToken(const std::string& token, const std::string& storedToken);
    };

    // ==============================================
    // Password Hashing
    // ==============================================
    class Password {
    public:
        static std::string hash(const std::string& password);
        static bool verify(const std::string& password, const std::string& hash);
    };

    // ==============================================
    // Multi-Factor Authentication (MFA)
    // ==============================================
    class MFA {
    public:
        static std::string generateTOTP(const std::string& secret);
        static bool verifyTOTP(const std::string& secret, const std::string& code);
        static std::string generateHOTP(const std::string& secret, uint64_t counter);
        static bool verifyHOTP(const std::string& secret, const std::string& code, uint64_t counter);
    };

    // ==============================================
    // Key Management
    // ==============================================
    class KeyManager {
    public:
        static std::string generateKey(const std::string& algorithm);
        static std::string exportKey(const std::string& key, const std::string& password);
        static std::string importKey(const std::string& encryptedKey, const std::string& password);
    };

    // ==============================================
    // Security Auditing
    // ==============================================
    class Auditor {
    public:
        static void logEvent(const std::string& event, const std::string& level = "INFO");
        static void analyzeLogs();
    };

    // ==============================================
    // File Encryption
    // ==============================================
    class FileSecurity {
    public:
        static void encryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& key);
        static void decryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& key);
    };

    // ==============================================
    // TLS/SSL Certificate Management
    // ==============================================
    class Certificate {
    public:
        static void generateSelfSignedCert(const std::string& commonName, const std::string& certFile, const std::string& keyFile);
        static bool verifyCertificate(const std::string& certFile, const std::string& caFile);
    };

    // ==============================================
    // Random Number Generation
    // ==============================================
    class Random {
    public:
        static std::string generateSecureRandom(size_t length);
        static uint64_t generateSecureRandomNumber();
    };

    // ==============================================
    // Security Headers
    // ==============================================
    class Headers {
    public:
        static std::map<std::string, std::string> getSecurityHeaders();
    };

    // ==============================================
    // Input Validation
    // ==============================================
    class Validator {
    public:
        static bool validateEmail(const std::string& email);
        static bool validatePassword(const std::string& password);
        static bool sanitizeInput(std::string& input);
    };
}
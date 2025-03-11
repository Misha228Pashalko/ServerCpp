#pragma once
#include <string>
#include <sstream>

namespace Utils {
    std::string urlDecode(const std::string& str);
    std::string base64Encode(const std::string& data);
    std::string generateUUID();
    std::string getMimeType(const std::string& extension);
}
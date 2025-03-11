cmake_minimum_required(VERSION 3.15)
project(AdvancedServer)

set(CMAKE_CXX_STANDARD 17)

find_package(Boost 1.70 REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

include_directories(
    include
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

add_executable(Server
    src/main.cpp
    src/Server.cpp
    src/Database.cpp
    src/Security.cpp
    src/Router.cpp
    src/Utils.cpp
)

target_link_libraries(Server
    PRIVATE 
    Boost::system
    OpenSSL::SSL
    SQLite::SQLite3
)
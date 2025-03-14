cmake_minimum_required(VERSION 3.15)
project(AdvancedServer VERSION 1.0.0 LANGUAGES CXX)

# втановлення С++ як стандартну мову
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Найти відсутні пакети
find_package(Boost 1.70 REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

# Define source files
set(SERVER_SOURCES
    src/main.cpp
    src/Server.cpp
    src/Database.cpp
    src/Security.cpp
    src/Router.cpp
    src/Utils.cpp
)

# Cстворення виконуваного файло
add_executable(Server ${SERVER_SOURCES})

# Набір містить каталоги
target_include_directories(Server
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${Boost_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
)

# Посилання на бібліотеки
target_link_libraries(Server
    PRIVATE 
        Boost::system
        OpenSSL::SSL
        SQLite::SQLite3
)

# Додавання правил встановлення (оптимально) 
install(TARGETS Server
    RUNTIME DESTINATION bin
)
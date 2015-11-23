# <Nathan Bass>. Copyright (C) <2015(s)>. <MIT>.
CMAKE_MINIMUM_REQUIRED (VERSION 2.6)
PROJECT (irrational_httpc)

set(CMAKE_CXX_FLAGS	"${CMAKE_CXX_FLAGS} -std=c++1y -lpthread -lcrypto -lssl")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${CMAKE_CXX_FLAGS} -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${CMAKE_CXX_FLAGS}")

find_package(OpenSSL REQUIRED)
find_package(Boost COMPONENTS system thread REQUIRED)

include_directories(${OpenSSL_INCLUDE_DIR})
link_libraries(${OpenSSL_LIBRARIES})

link_directories(${Boost_LIBRARY_DIR})
include_directories(Boost_INCLUDE_DIRS)
link_libraries(${Boost_LIBRARIES})

include_directories(include)
include_directories(lib)

add_subdirectory(lib)

link_libraries(JSONSpirit)
add_subdirectory(src)

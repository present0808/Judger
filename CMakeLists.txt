cmake_minimum_required(VERSION 3.10)
project(judger C)

#set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/output)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-g -Wall -Werror -Wno-error=stringop-overflow -O3 -pie -fPIC")

# make judger lib
file(GLOB SOURCE "src/*.c" "src/rules/*.c")
add_executable(libjudger.so ${SOURCE})
target_link_libraries(libjudger.so pthread seccomp)


install(FILES output/libjudger.so
    PERMISSIONS OWNER_EXECUTE OWNER_READ
    DESTINATION /usr/lib/judger)
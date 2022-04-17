cmake_minimum_required(VERSION 3.15...3.21)

project(czsfp_cli
	VERSION 1.0
	LANGUAGES CXX
)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
add_executable(app cli.cpp)
target_link_libraries(app OpenSSL::SSL curl)
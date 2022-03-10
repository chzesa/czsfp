#define CZSFP_IMPLEMENTATION
#include "filepack.hpp"

int main(int argc, char** argv)
{
	if (argc != 3)
		throw std::invalid_argument("Supply a directory name as the first argument and a filename as the second argument.");

	uint64_t threads = 32;
	uint64_t memory = uint64_t(1024) * 1024 * 128 * threads;
	czsfp::FilePack::create(argv[2], argv[1], threads, memory);
}
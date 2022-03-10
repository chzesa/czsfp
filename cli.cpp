#define CZSFP_IMPLEMENTATION
#include "filepack.hpp"

#include <filesystem>
#include <vector>

int main(int argc, char** argv)
{
	if (argc != 3)
		throw std::invalid_argument("Supply a directory name as the first argument and a filename as the second argument.");

	uint64_t threads = 32;
	uint64_t memory = uint64_t(1024) * 1024 * 128 * threads;
	std::vector<std::string> file_names;

	for (auto const& dir_entry : std::filesystem::recursive_directory_iterator(argv[1]))
	{
		if (!dir_entry.is_regular_file())
			continue;

		file_names.push_back(dir_entry.path());
	}

	const char** array = new const char*[file_names.size()];

	for (size_t i = 0; i < file_names.size(); i++)
		array[i] = file_names[i].c_str();

	czsfp::FilePack::create(argv[2], argv[1], file_names.size(), array, threads, memory);
	delete array;
}
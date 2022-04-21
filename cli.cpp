#define CZSFP_IMPLEMENTATION
#include "czsfp.hpp"

#include <filesystem>
#include <vector>
#include <algorithm>

int main(int argc, char** argv)
{
	if (argc != 3)
		throw std::invalid_argument("Supply a directory name as the first argument and a filename as the second argument.");

	uint64_t threads = 32;
	uint64_t memory = 1024l * 1024 * 16 * threads;
	char* origin = argv[1];
	char* dest = argv[2];

	std::vector<std::string> file_names;

	for (auto const& dir_entry : std::filesystem::recursive_directory_iterator(origin))
	{
		if (!dir_entry.is_regular_file())
			continue;

		file_names.push_back(dir_entry.path());
	}

	std::sort(file_names.begin(), file_names.end());

	const char** array = new const char*[file_names.size()];

	for (size_t i = 0; i < file_names.size(); i++)
		array[i] = file_names[i].c_str();

	czsfp::FilePack::create(dest, origin, file_names.size(), array, threads, memory);
	delete array;

	auto pack = czsfp::FilePack(dest);

	std::cout << "Files:" << std::endl;

	for (const auto& [k, v] : pack)
	{
		std::cout << '\t' << k << std::endl;
	}
}
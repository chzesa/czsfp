#include <string>
#include <stdexcept>
#include <filesystem>
#include <iostream>
#include <vector>
#include <iostream>
#include <fstream>
#include <atomic>
#include <thread>
#include <algorithm>
#include <cstring>

#include <openssl/md5.h>

#include "filepack.hpp"

using namespace czsfp;

static const uint64_t COPY_BUFFER_SIZE = 128 * 1024 * 1024;

void copy_file(std::ofstream& output, const FileInfo& info, const std::filesystem::path& path, char* buffer)
{
	std::ifstream input(path, std::ios::binary | std::ios::in);
	output.seekp(info.offset);

	for (uint64_t block = 0; block < info.size; block += COPY_BUFFER_SIZE)
	{
		uint64_t block_size = std::min(info.size - block, COPY_BUFFER_SIZE);
		input.read(buffer, block_size);
		output.write(buffer, block_size);
	}

	input.close();
}

int main(int argc, char** argv)
{
	if (argc != 3)
		throw std::invalid_argument("Supply a directory name as the first argument and a filename as the second argument.");

	std::string origin_path_str = std::string(argv[1]);
	auto origin_path = std::filesystem::path(origin_path_str);

	std::vector<std::string> names;
	std::vector<std::filesystem::path> paths;
	std::vector<FileInfo> file_infos;

	uint64_t offset = 0;
	uint64_t name_offset = 0;
	uint64_t total_size = 3 * sizeof(uint64_t);

	for (auto const& dir_entry : std::filesystem::recursive_directory_iterator(argv[1]))
	{
		if (!dir_entry.is_regular_file())
			continue;

		std::string filename = std::string(dir_entry.path());
		std::string substr = filename.substr(origin_path_str.length(), filename.length() - origin_path_str.length());

		names.push_back(substr);
		paths.push_back(std::filesystem::path(dir_entry));

		FileInfo info;
		info.offset = offset;
		info.size = std::filesystem::file_size(dir_entry);
		info.name_length = substr.length() + 1;
		info.name_offset = name_offset;
		file_infos.push_back(info);

		offset += info.size;
		name_offset += info.name_length;
		total_size += info.size + info.name_length + sizeof info;
	}

	// Create file
	auto destination_path = std::filesystem::path(argv[2]);
	std::ofstream ofs(destination_path);
	ofs.close();
	std::filesystem::resize_file(destination_path, total_size);

	// Thread handles for copy operations
	uint64_t thread_count = std::min(uint64_t(32), uint64_t(file_infos.size()));
	std::thread handles[thread_count];
	std::atomic_uint64_t index = 0;

	std::cout
		<< "Generating output file"
		<< "\n\tTotal size: " << total_size
		<< "\n\tFile count: " << file_infos.size()
		<< "\nUsing " << thread_count << " threads"
		<< std::endl;

	// Copy file data
	for (uint64_t t = 0; t < thread_count; t++)
	{
		handles[t] = std::thread([&]
		{
			char* buffer = reinterpret_cast<char*>(malloc(COPY_BUFFER_SIZE));
			std::ofstream output(destination_path, std::ios::binary | std::ios::out);

			for (int i = index++; i < file_infos.size(); i = index++)
				copy_file(output, file_infos[i], paths[i], buffer);

			output.close();
			free(buffer);
		});
	}

	// Write EoF data
	FileInfo last_file;
	if (file_infos.size() > 0)
		last_file = file_infos[file_infos.size() - 1];
	char* data = reinterpret_cast<char*>(malloc(total_size - last_file.size - last_file.offset));
	char* ptr = data;

	// Concatenate filenames
	for (const auto& name : names)
	{
		uint64_t size = name.length() + 1;
		memcpy(ptr, name.c_str(), size);
		ptr += size;
	}

	// Copy file info block
	uint64_t file_info_block_size = sizeof(FileInfo) * file_infos.size();
	memcpy(ptr, file_infos.data(), file_info_block_size);
	ptr += file_info_block_size;

	// End of File info
	uint64_t eof_info[3];
	eof_info[0] = last_file.size + last_file.offset;
	eof_info[1] = eof_info[0] + last_file.name_length + last_file.name_offset;
	eof_info[2] = file_infos.size();
	memcpy(ptr, eof_info, sizeof eof_info);

	// Copy EoF info
	std::ofstream output(destination_path, std::ios::binary | std::ios::out);
	output.seekp(last_file.size + last_file.offset);
	output.write(data, total_size - last_file.size - last_file.offset);

	output.close();
	free(data);
	// Wait for all copies to finish
	for (uint64_t i = 0; i < thread_count; i++)
		handles[i].join();
}
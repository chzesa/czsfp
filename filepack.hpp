#ifndef CZSFP_HEADERS_H
#define CZSFP_HEADERS_H

#include <cstdint>
#include <unordered_map>
#include <string>

namespace czsfp
{

static const uint64_t CZSFP_VERSION = 1;

struct FileManifest;

struct FileQuery
{
	uint64_t offset;
	uint64_t size;
};

struct FilePack
{
	FilePack();
	FilePack(const char* path);
	FileQuery get(const char* pack_path) const;
	static FilePack load(const char* pack_path);
	static void create(const char* pack_path, const char* asset_folder_path, uint64_t threads, uint64_t memory);
	static void update(const char* pack_path, uint64_t manifest_count, FileManifest* manifests, uint64_t threads, uint64_t memory);
private:
	std::unordered_map<std::string, FileQuery> locations;
};

} // namespace czsfp
#endif // CZSFP_HEADERS_H

#ifdef CZSFP_IMPLEMENTATION
#ifndef CZSFP_IMPLEMENTATION_GUARD_
#define CZSFP_IMPLEMENTATION_GUARD_

#include <algorithm>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <stdio.h>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
	
#endif

#ifdef __unix__
	#include <unistd.h>
	#include <sys/types.h>
#endif

#include <openssl/md5.h>

namespace czsfp
{

struct FileManifest 
{
	uint64_t name_offset;
	uint64_t name_length;
	uint64_t offset;
	uint64_t size;
	char md5[MD5_DIGEST_LENGTH];
};

struct PackManifest
{
	uint64_t name_offset;
	uint64_t info_offset;
	uint64_t file_count;
	uint64_t version;

	uint64_t names_size() { return info_offset - name_offset; }
	uint64_t infos_size() { return sizeof (FileManifest) * file_count; }
};

FileQuery FilePack::get(const char* filename) const
{
	auto res = this->locations.find(filename);
	if (res == this->locations.end())
		return { uint64_t(-1), 0 };

	return res->second;
}

FilePack::FilePack() {}

FilePack::FilePack(const char* path)
{
	std::ifstream file(path, std::ios::binary | std::ios::in | std::ios::ate);
	uint64_t file_size = file.tellg();
	PackManifest manifest;

	file.seekg(file_size - sizeof manifest);
	file.read(reinterpret_cast<char*>(&manifest), sizeof manifest);

	char* file_names = reinterpret_cast<char*>(malloc(manifest.names_size()));
	FileManifest* file_infos = reinterpret_cast<FileManifest*>(malloc(manifest.infos_size()));

	file.seekg(manifest.name_offset);
	file.read(file_names, manifest.names_size());
	file.read(reinterpret_cast<char*>(file_infos), manifest.infos_size());
	file.close();

	for (int i = 0; i < manifest.file_count; i++)
	{
		FileManifest info = file_infos[i];
		std::string file_name(file_names + info.name_offset, info.name_length);
		this->locations.insert({
			file_name,
			{info.offset, info.size}
		});
	}

	free(file_names);
	free(file_infos);
}

void copy_file(FILE* output, const FileManifest& info, const char* path, char* buffer, uint64_t buffer_size)
{
	FILE* input = fopen(path, "r");

	if (!input)
	{
		std::cout << "Failed to open istream to " << path << std::endl;
		return;
	}

	fseek(output, info.offset, SEEK_SET);

	for (uint64_t block = 0; block < info.size; block += buffer_size)
	{
		uint64_t block_size = std::min(info.size - block, buffer_size);
		fread(buffer, sizeof(char), block_size, input);
		fwrite(buffer, sizeof(char), block_size, output);
	}

	fclose(input);
}

void copy_thread(std::atomic_uint64_t* index, const char* destination_path, std::vector<std::string>* paths, std::vector<FileManifest>* file_infos, char* buffer, uint64_t buffer_block_size)
{
	FILE* output = fopen(destination_path, "r+b");

	if (!output)
	{
		std::cout << "Failed to open ostream to " << destination_path << std::endl;
		return;
	}

	for (uint64_t i = (*index)++; i < file_infos->size(); i = (*index)++)
	{
		copy_file(output, (*file_infos)[i], (*paths)[i].c_str(), buffer, buffer_block_size);
	}

	fclose(output);
}

void check_result(std::vector<FileManifest>& infos, std::vector<std::string>& paths, const char* asset_folder_path, const char* pack_path, uint64_t threads, uint64_t memory)
{
	FilePack pack(pack_path);
	uint64_t file_name_prefix_length = std::string(asset_folder_path).length();
	char* buffer = reinterpret_cast<char*>(malloc(memory));
	std::ifstream pack_file(pack_path, std::ios::binary | std::ios::in);

	for (int i = 0; i < paths.size(); i++)
	{
		auto path = paths[i].substr(file_name_prefix_length);
		auto info = infos[i];
		FileQuery query = pack.get(path.c_str());

		if (query.size == 0 && query.offset == uint64_t(-1))
		{
			std::cout << "[Error] Failed to find " << path << std::endl;
			return;
		}

		if (info.size != query.size)
		{
			std::cout << "[ERROR] Incorrect size: Expected " << info.size << "; got " << query.size << " (" << path <<  ")" << std::endl;
			return;
		}

		if (info.offset != query.offset)
		{
			std::cout << "[ERROR] Incorrect offset: Expected " << info.offset << "; got " << query.offset << " (" << path <<  ")" << std::endl;
			return;
		}

		uint64_t buffer_size = memory / 2;
		std::ifstream original_file(paths[i], std::ios::binary | std::ios::in);
		pack_file.seekg(info.offset);

		for (uint64_t block = 0; block < info.size; block += buffer_size)
		{
			uint64_t block_size = std::min(info.size - block, buffer_size);
			memset(buffer, 0, block_size * 2);
			original_file.read(buffer, block_size);
			pack_file.read(buffer + block_size, block_size);
			if (memcmp(buffer, buffer + block_size, block_size))
			{
				std::cout << "[Error] Contents differ: " << path << std::endl;
				std::cout << std::string(buffer, std::min(block_size, uint64_t(512))) << std::endl;
				std:: cout << "=============================" << std::endl;
				std::cout << std::string(buffer + block_size, std::min(block_size, uint64_t( 512))) << std::endl;
				return;
			}
		}

		original_file.close();
	}

	free(buffer);
	pack_file.close();
}

void FilePack::create(const char* pack_path, const char* asset_folder_path, uint64_t threads, uint64_t memory)
{
	std::string origin_path_str = std::string(asset_folder_path);

	std::vector<std::string> names;
	std::vector<std::string> paths;
	std::vector<FileManifest> file_infos;

	uint64_t offset = 0;
	uint64_t name_offset = 0;
	uint64_t total_size = sizeof(PackManifest);

	for (auto const& dir_entry : std::filesystem::recursive_directory_iterator(origin_path_str))
	{
		if (!dir_entry.is_regular_file())
			continue;

		std::string filename = std::string(dir_entry.path());
		std::string substr = filename.substr(origin_path_str.length(), filename.length() - origin_path_str.length());

		names.push_back(substr);
		paths.push_back(std::filesystem::path(dir_entry).string());

		FileManifest info;
		info.offset = offset;
		info.size = std::filesystem::file_size(dir_entry);
		info.name_length = substr.length();
		info.name_offset = name_offset;
		file_infos.push_back(info);

		offset += info.size;
		name_offset += info.name_length;
		total_size += info.size + info.name_length + sizeof info;
	}

	uint64_t thread_count = std::min(uint64_t(threads), uint64_t(file_infos.size()));

	std::cout
		<< "Generating output file"
		<< "\n\tTotal size: " << total_size
		<< "\n\tFile count: " << file_infos.size()
		<< "\nUsing " << thread_count << " threads"
		<< "\nUsing " << memory << " bytes of memory"
		<< std::endl;

	// Create file and set size
	auto output = fopen(pack_path, "w");

	#ifdef _WIN32
	#endif
	#ifdef __unix__
	if (truncate(pack_path, total_size))
	{
		std::cout << "Failed to create asset file." << std::endl;
		return;
	}
	#endif

	fclose(output);

	// Spawn threads for copying file contents
	std::thread handles[thread_count];
	uint64_t buffer_block_size = memory / threads;
	std:: atomic_uint64_t index = 0;
	char* buffer = reinterpret_cast<char*>(malloc(memory));

	for (uint64_t i = 0; i < thread_count; i++)
		handles[i] = std::thread(copy_thread, &index, pack_path, &paths, &file_infos, buffer + (i * buffer_block_size), buffer_block_size);

	// Write EoF data
	FileManifest last_file;
	if (file_infos.size() > 0)
		last_file = file_infos[file_infos.size() - 1];

	uint64_t eof_block_size = total_size - last_file.size - last_file.offset;
	char* data = reinterpret_cast<char*>(malloc(eof_block_size));
	char* ptr = data;

	// Concatenate filenames
	for (const auto& name : names)
	{
		memcpy(ptr, name.c_str(), name.length());
		ptr += name.length();
	}

	// Copy file info block
	uint64_t file_info_block_size = sizeof(FileManifest) * file_infos.size();
	memcpy(ptr, file_infos.data(), file_info_block_size);
	ptr += file_info_block_size;

	// File Pack manifest
	PackManifest manifest;
	manifest.name_offset = last_file.size + last_file.offset;
	manifest.info_offset = manifest.name_offset + last_file.name_length + last_file.name_offset;
	manifest.file_count = file_infos.size();
	manifest.version = CZSFP_VERSION;
	memcpy(ptr, &manifest, sizeof manifest);
	ptr += sizeof manifest;

	// Write to file
	output = fopen(pack_path, "r+b");
	fseek(output, last_file.size + last_file.offset, SEEK_SET);
	fwrite(data, sizeof(char), eof_block_size, output);
	fclose(output);
	free(data);

	// Wait for all copies to finish
	for (uint64_t i = 0; i < thread_count; i++)
		handles[i].join();

	free(buffer);
	check_result(file_infos, paths, asset_folder_path, pack_path, threads, memory);
}

} //namespace czsfp
#endif // CZSFP_IMPLEMENTATION_GUARD_
#endif // CZSFP_IMPLEMENTATION
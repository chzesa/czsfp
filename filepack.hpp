#ifndef CZSFP_HEADERS_H
#define CZSFP_HEADERS_H

#include <cstdint>
#include <unordered_map>
#include <string>

namespace czsfp
{

static const uint64_t CZSFP_VERSION = 2;

/*
	Output file organized as follows:
		Copied file contents
		File path+name suffixes
		File manifests
		Pack manifest

	Offsets in PackManifest are calculated from the beginning of file
	Offsets in FileManifest are from the beginning of the appropriate block
*/

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
	FileQuery get(const char* filename) const;
	static FilePack load(const char* pack_path);
	static bool load(FilePack* pack, const char* pack_path);
	static void create(const char* pack_path, const char* asset_path_prefix, uint64_t file_count, const char** file_paths, uint64_t threads, uint64_t memory);
	static void update(const char* pack_path, uint64_t manifest_count, FileManifest* manifests, uint64_t* update_indices, uint64_t threads, uint64_t memory);
	static void verify_integrity(const char* path);
	std::unordered_map<std::string, FileQuery>::const_iterator begin() const;
	std::unordered_map<std::string, FileQuery>::const_iterator end() const;
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
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <stdio.h>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <openssl/md5.h>

namespace czsfp
{

struct FileManifest 
{
	uint64_t name_offset;
	uint64_t name_length;
	uint64_t offset;
	uint64_t size;
	unsigned char md5[MD5_DIGEST_LENGTH];
};

struct PackManifest
{
	uint64_t name_offset;
	uint64_t info_offset;
	uint64_t file_count;
	uint64_t version;
	unsigned char md5[MD5_DIGEST_LENGTH];

	uint64_t names_size() { return info_offset - name_offset; }
	uint64_t infos_size() { return sizeof (FileManifest) * file_count; }
	uint64_t total_size() { return name_offset + names_size() + infos_size() + sizeof(PackManifest); }
};

struct Builder
{
	uint64_t file_count;
	const char** file_paths;
	const char* path_prefix;
	const char* output;
	std::vector<FileManifest> manifests;
};

FileQuery FilePack::get(const char* filename) const
{
	auto res = this->locations.find(filename);
	if (res == this->locations.end())
		return { uint64_t(-1), 0 };

	return res->second;
}

FilePack::FilePack() {}

FileManifest* manifests_from_buffer(PackManifest& manifest, char* buffer)
{
	return reinterpret_cast<FileManifest*>(buffer + manifest.info_offset - manifest.name_offset);
}

void read_pack(const char* path, PackManifest** manifest, char** buffer)
{
	std::ifstream file(path, std::ios::binary | std::ios::in | std::ios::ate);
	uint64_t file_size = file.tellg();

	PackManifest mf;

	file.seekg(file_size - sizeof mf);
	file.read(reinterpret_cast<char*>(&mf), sizeof mf);

	*buffer = reinterpret_cast<char*>(malloc(file_size - mf.name_offset));

	file.seekg(mf.name_offset);
	file.read(*buffer, file_size - sizeof mf);
	file.close();

	*manifest = reinterpret_cast<PackManifest*>(*buffer + mf.names_size() + mf.infos_size());
}

bool FilePack::load(FilePack* pack, const char* path)
{
	PackManifest* manifest;
	char* buffer;

	read_pack(path, &manifest, &buffer);

	FileManifest* file_infos = manifests_from_buffer(*manifest, buffer);

	for (int i = 0; i < manifest->file_count; i++)
	{
		FileManifest info = file_infos[i];

		if (info.name_offset, info.name_length >= manifest->names_size())
			continue;

		std::string file_name(buffer + info.name_offset, info.name_length);
		pack->locations.insert({
			file_name,
			{info.offset, info.size}
		});
	}

	free(buffer);
	return true;
}

FilePack FilePack::load(const char* path)
{
	FilePack ret;
	load(&ret, path);
	return ret;
}

FilePack::FilePack(const char* path)
{
	load(this, path);
}

void copy_region(FILE* input, FILE* output, uint64_t size, char* buffer, uint64_t buffer_size)
{
	for (uint64_t block = 0; block < size; block += buffer_size)
	{
		uint64_t block_size = std::min(size - block, buffer_size);
		fread(buffer, sizeof(char), block_size, input);
		fwrite(buffer, sizeof(char), block_size, output);
	}
}

void copy_file(FILE* output, FileManifest& info, const char* path, char* buffer, uint64_t buffer_size)
{
	FILE* input = fopen(path, "r");

	if (!input)
	{
		std::cout << "Failed to open istream to " << path << std::endl;
		return;
	}

	fseek(output, info.offset, SEEK_SET);

	struct MD5state_st md5;
	MD5_Init(&md5);

	for (uint64_t block = 0; block < info.size; block += buffer_size)
	{
		uint64_t block_size = std::min(info.size - block, buffer_size);
		fread(buffer, sizeof(char), block_size, input);
		fwrite(buffer, sizeof(char), block_size, output);
		MD5_Update(&md5, buffer, block_size);
	}

	MD5_Final(info.md5, &md5);
	fclose(input);
}

void copy_thread(Builder* builder, std::atomic_uint64_t* index, char* buffer, uint64_t buffer_block_size)
{
	FILE* output = fopen(builder->output, "r+b");

	if (!output)
	{
		std::cout << "Failed to open ostream to " << builder->output << std::endl;
		return;
	}

	for (uint64_t i = (*index)++; i < builder->file_count; i = (*index)++)
	{
		copy_file(output, builder->manifests[i], builder->file_paths[i], buffer, buffer_block_size);
	}

	fclose(output);
}

void check_result(std::vector<FileManifest>& infos,  uint64_t file_count, const char** file_paths, const char* asset_folder_path, const char* pack_path, uint64_t threads, uint64_t memory)
{
	FilePack pack(pack_path);
	uint64_t file_name_prefix_length = std::string(asset_folder_path).length();
	char* buffer = reinterpret_cast<char*>(malloc(memory));
	std::ifstream pack_file(pack_path, std::ios::binary | std::ios::in);

	for (int i = 0; i < file_count; i++)
	{
		auto path = std::string(file_paths[i]).substr(file_name_prefix_length);
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
		std::ifstream original_file(file_paths[i], std::ios::binary | std::ios::in);
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

void md5_to_buffer(const unsigned char* md5, char* output)
{
	for (int i = 0; i < 16; i++)
		sprintf(&output[i * 2], "%02x", md5[i]);
}

void FilePack::create(const char* pack_path, const char* asset_path_prefix, uint64_t file_count, const char** file_paths, uint64_t threads, uint64_t memory)
{
	Builder builder;
	builder.file_count = file_count;
	builder.file_paths = file_paths;
	builder.path_prefix = asset_path_prefix;
	builder.output = pack_path;

	std::string origin_path_str = std::string(asset_path_prefix);

	std::vector<std::string> names;

	uint64_t offset = 0;
	uint64_t name_offset = 0;
	uint64_t total_size = sizeof(PackManifest);

	for (int i = 0; i < file_count; i++)
	{
		std::string filename = std::string(file_paths[i]);
		std::string substr = filename.substr(origin_path_str.length(), filename.length() - origin_path_str.length());

		names.push_back(substr);

		FileManifest info;
		info.offset = offset;

		auto handle = fopen(file_paths[i], "rb");
		fseek(handle, 0, SEEK_END);
		info.size = ftell(handle);
		fclose(handle);

		info.name_length = substr.length();
		info.name_offset = name_offset;
		builder.manifests.push_back(info);

		offset += info.size;
		name_offset += info.name_length;
		total_size += info.size + info.name_length + sizeof info;
	}

	uint64_t thread_count = std::min(threads, file_count);

	std::cout
		<< "Generating output file"
		<< "\n\tTotal size: " << total_size
		<< "\n\tFile count: " << file_count
		<< "\nUsing " << thread_count << " threads"
		<< "\nUsing " << memory << " bytes of memory"
		<< std::endl;

	// Create file and set size
	auto output = fopen(pack_path, "w");
	fclose(output);

	// Spawn threads for copying file contents
	std::thread handles[thread_count];
	uint64_t buffer_block_size = memory / threads;
	std:: atomic_uint64_t index(0);
	char* buffer = reinterpret_cast<char*>(malloc(memory));

	for (uint64_t i = 0; i < thread_count; i++)
		handles[i] = std::thread(copy_thread, &builder, &index, buffer + (i * buffer_block_size), buffer_block_size);

	// Wait for all copies to finish
	for (uint64_t i = 0; i < thread_count; i++)
		handles[i].join();

	free(buffer);

	// Write EoF data
	uint64_t eof_block_size = total_size - offset;
	char* data = reinterpret_cast<char*>(malloc(eof_block_size));
	char* ptr = data;

	// Concatenate filenames
	for (const auto& name : names)
	{
		memcpy(ptr, name.c_str(), name.length());
		ptr += name.length();
	}

	// Copy file info block
	uint64_t file_info_block_size = sizeof(FileManifest) * file_count;
	memcpy(ptr, builder.manifests.data(), file_info_block_size);
	ptr += file_info_block_size;

	// File Pack manifest
	PackManifest manifest;
	manifest.name_offset = offset;
	manifest.info_offset = manifest.name_offset + name_offset;
	manifest.file_count = file_count;
	manifest.version = CZSFP_VERSION;
	memcpy(ptr, &manifest, sizeof manifest);

	struct MD5state_st md5;
	MD5_Init(&md5);
	MD5_Update(&md5, data, eof_block_size - MD5_DIGEST_LENGTH);
	MD5_Final(manifest.md5, &md5);
	memcpy(ptr, &manifest, sizeof manifest);

	// Write to file
	output = fopen(pack_path, "r+b");
	fseek(output, offset, SEEK_SET);
	fwrite(data, sizeof(char), eof_block_size, output);
	fclose(output);
	free(data);

	check_result(builder.manifests, file_count, file_paths, asset_path_prefix, pack_path, threads, memory);

	char md5str[33];
	md5_to_buffer(manifest.md5, md5str);
	std::cout << "Created output file " << pack_path << " with hash " << md5str << std::endl;
	FilePack::verify_integrity(pack_path);
}

void FilePack::update(const char* pack_path, uint64_t manifests_count, FileManifest* manifests, uint64_t* update_indices, uint64_t threads, uint64_t memory)
{
	std::unordered_map<std::string, FileManifest> updated_manifests;
	std::unordered_map<std::string, FileManifest> current_manifests;
	std::map<uint64_t, FileManifest> file_locations;
	std::vector<FileQuery> open_regions;

	PackManifest* current_manifest;
	char* manifest_buffer;

	read_pack(pack_path, &current_manifest, &manifest_buffer);
	FileManifest* file_infos = manifests_from_buffer(*current_manifest, manifest_buffer);

	for (uint64_t i = 0; i < current_manifest->file_count; i++)
	{
		char md5[33];
		FileManifest manifest = file_infos[i];
		md5_to_buffer(manifest.md5, md5);
		current_manifests.insert({std::string(md5), manifest});
	}

	for (uint64_t i = 0; i < manifests_count; i++)
	{
		char md5[33];
		FileManifest manifest = manifests[i];
		md5_to_buffer(manifest.md5, md5);
		updated_manifests.insert({std::string(md5), manifest});
		file_locations.insert({manifest.offset, manifest});

		auto result = current_manifests.find(md5);
		if (result == current_manifests.end())
		{
			*update_indices = i;
			update_indices++;
		}
		else if(result->second.size != manifest.size)
		{
			*update_indices = i;
			update_indices++;

			current_manifests.erase(result);
			open_regions.push_back({result->second.offset, result->second.size});
		}
	}

	FILE* read = fopen(pack_path, "r+b");
	FILE* write = fopen(pack_path, "r+b");

	int64_t delta = manifests[manifests_count - 1].offset + manifests[manifests_count - 1].size
		- current_manifest->name_offset;

	if (delta > 0)
		open_regions.push_back({current_manifest->name_offset, uint64_t(delta)});

	char* buffer = reinterpret_cast<char*>(malloc(memory));

	while(open_regions.size() > 0)
	{
		FileQuery region = open_regions.back();
		open_regions.pop_back();

		FileManifest new_location;
		FileManifest old_location;

		auto result = file_locations.lower_bound(region.offset);

		if (result == file_locations.end() || region.offset >= result->second.offset + result->second.size)
		{
			// Nothing maps to this area in new manifest.
			// The entire region can be discarded since the files are packed left to right
			// so if no file maps to the beginning of the region, no file will map to
			// the end of the region.
			continue;
		}

		new_location = result->second;
		char md5[33];
		md5_to_buffer(new_location.md5, md5);

		auto result2 = current_manifests.find(md5);
		if (result2 == current_manifests.end())
		{
			// File contents not present in current pack, must be added after update
			continue;
		}

		old_location = result2->second;

		uint64_t mapped_region_begin = new_location.offset - region.offset + old_location.offset;
		uint64_t region_end = std::min(region.offset + region.size, new_location.offset + new_location.size);
		uint64_t block_size = region_end - region.offset;

		fseek(read, mapped_region_begin, SEEK_SET);
		fseek(write, region.offset, SEEK_SET);
		copy_region(read, write, block_size, buffer, memory);

		if (new_location.offset + new_location.size < region.offset + region.size)
			open_regions.push_back({region.offset + block_size, region.size - block_size});

		open_regions.push_back({mapped_region_begin, block_size});
	}

	fclose(read);
	fclose(write);

	free(buffer);
	free(manifest_buffer);
}

void FilePack::verify_integrity(const char* path)
{
	PackManifest* manifest;
	char* manifest_buffer;

	read_pack(path, &manifest, &manifest_buffer);
	FileManifest* file_infos = manifests_from_buffer(*manifest, manifest_buffer);

	unsigned char final_md5[MD5_DIGEST_LENGTH];

	struct MD5state_st md5;
	MD5_Init(&md5);
	MD5_Update(&md5, manifest_buffer, manifest->total_size() - manifest->name_offset - MD5_DIGEST_LENGTH);
	MD5_Final(final_md5, &md5);

	if(memcmp(final_md5, manifest->md5, MD5_DIGEST_LENGTH))
	{
		std::cout << "Integrity error in manifest header." << std::endl;
		return;
	}

	FILE* read = fopen(path, "rb");

	static const uint64_t buffer_size = 1024 * 1024 * 128;
	char* buffer = reinterpret_cast<char*>(malloc(buffer_size)); // todo

	for (uint64_t i = 0; i < manifest->file_count; i++)
	{
		FileManifest file = file_infos[i];
		fseek(read, file.offset, SEEK_SET);
		MD5_Init(&md5);

		for (uint64_t block = 0; block < file.size; block += buffer_size)
		{
			uint64_t block_size = std::min(file.size - block, buffer_size);
			fread(buffer, sizeof(char), block_size, read);
			MD5_Update(&md5, buffer, block_size);
		}

		MD5_Final(final_md5, &md5);

		if (memcmp(final_md5, file.md5, MD5_DIGEST_LENGTH))
			std::cout << "Integrity error in content" << std::endl;
	}

	free(buffer);
	free(manifest_buffer);
}

std::unordered_map<std::string, FileQuery>::const_iterator FilePack::begin() const
{
	return locations.begin();
}

std::unordered_map<std::string, FileQuery>::const_iterator FilePack::end() const
{
	return locations.end();
}

} //namespace czsfp
#endif // CZSFP_IMPLEMENTATION_GUARD_
#endif // CZSFP_IMPLEMENTATION
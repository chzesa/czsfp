#ifndef CZSFP_HEADERS_H
#define CZSFP_HEADERS_H

#include <cstdint>
#include <unordered_map>
#include <string>
#include <vector>

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
	FileManifest md5 is calculated from file content
	PackManifest md5 is calculated from the beginning of file names up until pack manifest
		md5 field
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
	~FilePack();
	FileQuery get(const char* filename) const;
	FileQuery get(uint64_t index) const;
	static FilePack load(const char* pack_path);
	static bool load(FilePack* pack, const char* pack_path);
	static void create(const char* pack_path, const char* asset_path_prefix, uint64_t file_count, const char** file_paths, uint64_t threads, uint64_t memory);
	static uint64_t update(const char* pack_path, uint64_t manifest_count, FileManifest* manifests, uint64_t* update_indices, uint64_t threads, uint64_t memory);
	static bool verify_integrity(const char* path);
#ifdef CZSFP_CURL
	static bool update_from_url(const char* url, const char* pack_path, uint64_t threads, uint64_t memory, bool create = true, int64_t rate_limit = 0);
#endif // CZSFP_CURL

	struct Info : FileQuery
	{
		const char* name;
		uint64_t name_length;
	};

	std::vector<Info>::const_iterator begin() const;
	std::vector<Info>::const_iterator end() const;
	
private:
	static bool sort_fn(const Info& a, const Info& b);

	char* strings;
	std::vector<FileQuery> indexLocations;
	std::vector<Info> locations;
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
#include <cstring>

#ifdef CZSFP_CURL
#include <curl/curl.h>
#endif // CZSFP_CURL

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

	uint64_t files_size() { return name_offset; }
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

bool FilePack::sort_fn(const Info& a, const Info& b)
{
	if (a.name_length != b.name_length)
		return a.name_length < b.name_length;

	return memcmp(a.name, b.name, a.name_length) < 0;
}

FileQuery FilePack::get(uint64_t index) const
{
	if (index < indexLocations.size())
		return indexLocations[index];

	return { uint64_t(-1), 0 };
}

FileQuery FilePack::get(const char* filename) const
{
	Info info = {
		0,
		0,
		filename,
		strlen(filename)
	};

	auto res = std::lower_bound(locations.begin(), locations.end(), info, sort_fn);

	if (sort_fn(info, *res) || sort_fn(*res, info))
		return { uint64_t(-1), 0 };

	return {
		res->offset,
		res->size
	};
}

FilePack::FilePack() {}

struct Reader
{
	char* names_buffer = nullptr;
	PackManifest* manifest = nullptr;
	FileManifest* file_manifests = nullptr;

	Reader(const char* path)
	{
		Reader::read_pack(path, &names_buffer, &file_manifests, &manifest);
	}

	~Reader()
	{
		free(names_buffer);
		free(manifest);
		free(file_manifests);
		names_buffer = nullptr;
		manifest = nullptr;
		file_manifests = nullptr;
	}

	bool valid()
	{
		return names_buffer != nullptr && manifest != nullptr && file_manifests != nullptr && validate_header_md5() && sanity_check();
	}

	bool sanity_check()
	{
		uint64_t files_size = 0;
		uint64_t names_length = 0;

		for (uint64_t i = 0; i < manifest->file_count; i++)
		{
			// TODO
			// check file regions don't overlap
			// check file names don't overlap

			FileManifest& fm = file_manifests[i];
			files_size += fm.size;
			names_length += fm.name_length;

			if ( !file_region_valid(fm) || !name_region_valid(fm) )
				return false;
		}

		if (files_size != manifest->files_size() || names_length != manifest->names_size())
			return false;

		return true;
	}

private:
	bool validate_header_md5()
	{
		unsigned char final_md5[MD5_DIGEST_LENGTH];

		struct MD5state_st md5;

		MD5_Init(&md5);
		MD5_Update(&md5, names_buffer, manifest->names_size());
		MD5_Update(&md5, file_manifests, manifest->infos_size());
		MD5_Update(&md5, manifest, sizeof (PackManifest) - MD5_DIGEST_LENGTH);
		MD5_Final(final_md5, &md5);

		if(memcmp(final_md5, manifest->md5, MD5_DIGEST_LENGTH))
		{
			std::cout << "Integrity error in manifest header." << std::endl;
			return false;
		}

		return true;
	}

	bool file_region_valid(FileManifest& file)
	{
		uint64_t limit = manifest->files_size();
		return file.offset < limit
			&& file.size < limit
			&& file.offset + file.size <= limit;
	}

	bool name_region_valid(FileManifest& file)
	{
		uint64_t limit = manifest->names_size();
		return file.name_offset < limit
			&& file.name_length < limit
			&& file.name_offset + file.name_length <= limit;
	}

	static bool read_pack(const char* path, char** names_buffer, FileManifest** file_manifests, PackManifest** manifest)
	{
		std::ifstream file(path, std::ios::binary | std::ios::in | std::ios::ate);
		uint64_t file_size = file.tellg();

		if (file_size < sizeof (PackManifest))
			return false;

		PackManifest* mf = new PackManifest();

		file.seekg(file_size - sizeof (PackManifest));
		file.read(reinterpret_cast<char*>(mf), sizeof (PackManifest));

		if (mf->total_size() != file_size
			|| ( mf->file_count == 0 && ( mf->infos_size() != 0 || mf->names_size() != 0 || mf->files_size() != 0 ) )
			|| ( mf->infos_size() != sizeof (FileManifest) * mf->file_count ) )
		{
			free(mf);
			return false;
		}

		*file_manifests = reinterpret_cast<FileManifest*>(malloc(mf->infos_size()));
		*names_buffer = reinterpret_cast<char*>(malloc(mf->names_size()));

		file.seekg(mf->name_offset);
		file.read(*names_buffer, mf->names_size());

		file.seekg(mf->info_offset);
		file.read(reinterpret_cast<char*>(*file_manifests), mf->infos_size());

		file.close();

		*manifest = mf;

		return true;
	}
};

bool FilePack::load(FilePack* pack, const char* path)
{
	Reader reader(path);
	if (!reader.valid())
		return false;

	pack->strings = reinterpret_cast<char*>(malloc(reader.manifest->names_size()));
	memcpy(pack->strings, reader.names_buffer, reader.manifest->names_size());
	pack->locations.reserve(reader.manifest->file_count);
	pack->indexLocations.reserve(reader.manifest->file_count);

	for (int i = 0; i < reader.manifest->file_count; i++)
	{
		FileManifest& info = reader.file_manifests[i];

		pack->indexLocations.push_back({
			info.offset,
			info.size
		});

		pack->locations.push_back({
			info.offset,
			info.size,
			pack->strings + info.name_offset,
			info.name_length
		});
	}

	std::sort(pack->locations.begin(), pack->locations.end(), sort_fn);
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

FilePack::~FilePack()
{
	free(strings);
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

uint64_t FilePack::update(const char* pack_path, uint64_t manifests_count, FileManifest* manifests, uint64_t* update_indices, uint64_t threads, uint64_t memory)
{
	uint64_t updated_file_count = 0;
	std::unordered_map<std::string, FileManifest> updated_manifests;
	std::unordered_map<std::string, FileManifest> current_manifests;
	std::map<uint64_t, FileManifest> file_locations;
	std::vector<FileQuery> open_regions;

	Reader reader(pack_path);

	for (uint64_t i = 0; i < reader.manifest->file_count; i++)
	{
		char md5[33];
		FileManifest manifest = reader.file_manifests[i];
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
			updated_file_count++;
		}
		else if(result->second.size != manifest.size)
		{
			*update_indices = i;
			update_indices++;
			updated_file_count++;

			current_manifests.erase(result);
			open_regions.push_back({result->second.offset, result->second.size});
		}
	}

	FILE* read = fopen(pack_path, "r+b");
	FILE* write = fopen(pack_path, "r+b");

	int64_t delta = manifests[manifests_count - 1].offset + manifests[manifests_count - 1].size
		- reader.manifest->name_offset;

	if (delta > 0)
		open_regions.push_back({reader.manifest->name_offset, uint64_t(delta)});

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
	return updated_file_count;
}

bool FilePack::verify_integrity(const char* path)
{
	Reader reader(path);
	if (!reader.valid())
	{
		std::cout << "Pack not valid" << std::endl;
		return false;
	}

	struct MD5state_st md5;
	unsigned char final_md5[MD5_DIGEST_LENGTH];

	FILE* read = fopen(path, "rb");

	static const uint64_t buffer_size = 1024 * 1024 * 128;
	char* buffer = reinterpret_cast<char*>(malloc(buffer_size)); // todo

	for (uint64_t i = 0; i < reader.manifest->file_count; i++)
	{
		FileManifest file = reader.file_manifests[i];
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
		{
			std::cout << "Integrity error in content" << std::endl;
			return false;
		}
	}

	free(buffer);
	return true;
}

std::vector<FilePack::Info>::const_iterator FilePack::begin() const
{
	return locations.begin();
}

std::vector<FilePack::Info>::const_iterator FilePack::end() const
{
	return locations.end();
}

#ifdef CZSFP_CURL

size_t curl_buffer_write(void *ptr, size_t size, size_t nmemb, void* buffer)
{
	memcpy(buffer, ptr, size * nmemb);
	return size * nmemb;
}

void curl_range(uint64_t begin, uint64_t end, CURL* curl)
{
	std::string range = std::to_string(begin) + "-" + std::to_string(end);
	curl_easy_setopt(curl, CURLOPT_RANGE, range.c_str());
}

bool update_from_url(CURL* curl, FILE* file, const char* url, const char* pack_path, uint64_t threads, uint64_t memory, bool create, int64_t rate_limit)
{
	CURLcode res;
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_MAX_RECV_SPEED_LARGE, rate_limit);

	if (!file && create)
	{
		file = fopen(pack_path, "wb");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
		res = curl_easy_perform(curl);
		fclose(file);
		return res == CURLE_OK;
	}

	// Query filesize
	curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
	res = curl_easy_perform(curl);

	if (res != CURLE_OK)
		return false;

	double filesize;
	res = curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &filesize);

	curl_easy_setopt(curl, CURLOPT_NOBODY, 0);

	// Download manifest header
	PackManifest manifest;
	curl_range(filesize - sizeof (PackManifest), filesize, curl);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_buffer_write);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &manifest);

	res = curl_easy_perform(curl);
	if (res != CURLE_OK)
		return false;

	// Check which manifests to update
	FileManifest file_manifests[manifest.file_count];
	uint64_t update_indices[manifest.file_count];

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &file_manifests);
	curl_range(manifest.info_offset, manifest.info_offset + manifest.infos_size(), curl);

	res = curl_easy_perform(curl);
	if (res != CURLE_OK)
		return false;

	uint64_t num_update = FilePack::update(pack_path, manifest.file_count, file_manifests, update_indices, threads, memory);

	// Download updated contents
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);

	for (uint64_t i = 0; i < num_update; i++)
	{
		FileManifest& fm = file_manifests[i];
		fseek(file, fm.offset, SEEK_SET);
		curl_range(fm.offset, fm.offset + fm.size, curl);

		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
			return false;
	}

	// Write updated file names
	fseek(file, manifest.name_offset, SEEK_SET);
	curl_range(manifest.name_offset, manifest.name_offset + manifest.names_size(), curl);

	res = curl_easy_perform(curl);
	if (res != CURLE_OK)
		return false;

	// Write updated infos
	fseek(file, manifest.info_offset, SEEK_SET);
	fwrite(file_manifests, sizeof(FileManifest), manifest.file_count, file);

	// write manifest data
	fwrite(&manifest, sizeof manifest, 1, file);

	return true;
}


bool FilePack::update_from_url(const char* url, const char* pack_path, uint64_t threads, uint64_t memory, bool create, int64_t rate_limit)
{
	CURL* curl = curl_easy_init();

	if (!curl)
		return false;

	FILE* file = fopen(pack_path, "r+b");

	bool result = czsfp::update_from_url(curl, file, url, pack_path, threads, memory, create,  rate_limit);

	if (file)
		fclose(file);

	curl_easy_cleanup(curl);

	FilePack::verify_integrity(pack_path);

	return result;
}

#endif // CZSFP_CURL

} //namespace czsfp
#endif // CZSFP_IMPLEMENTATION_GUARD_
#endif // CZSFP_IMPLEMENTATION
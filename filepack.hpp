#ifndef CZSFP_HEADERS_H
#define CZSFP_HEADERS_H

#include <cstdint>
#include <unordered_map>
#include <string>

namespace czsfp
{
struct FileInfo
{
	uint64_t name_offset;
	uint64_t name_length;
	uint64_t offset;
	uint64_t size;
};

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
	static FilePack load(const char* filename);
private:
	std::unordered_map<std::string, FileQuery> locations;
};

}
#endif

#ifdef CZSFP_IMPLEMENTATION
#ifndef CZSFP_IMPLEMENTATION_GUARD_
#define CZSFP_IMPLEMENTATION_GUARD_
#include <iostream>
#include <fstream>

namespace czsfp
{

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
	uint64_t eof[3];

	file.seekg(file_size - sizeof eof);
	file.read(reinterpret_cast<char*>(eof), sizeof eof);

	uint64_t name_pos = eof[0];
	uint64_t info_pos = eof[1];
	uint64_t file_count = eof[2];

	char* file_names = reinterpret_cast<char*>(malloc(info_pos - name_pos));
	FileInfo* file_infos = reinterpret_cast<FileInfo*>(malloc(file_count * sizeof(FileInfo)));
	file.seekg(name_pos);
	file.read(file_names, info_pos - name_pos);
	file.read(reinterpret_cast<char*>(file_infos), file_size - sizeof eof - info_pos);
	file.close();

	for (int i = 0; i < file_count; i++)
	{
		FileInfo& info = file_infos[i];
		this->locations.insert({
			std::string(file_names + info.name_offset),
			{info.offset, info.size}
		});
	}

	free(file_names);
	free(file_infos);
}

}
#endif
#endif
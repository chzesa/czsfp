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
	FileQuery get(const char*) const;
private:
	std::unordered_map<std::string, FileQuery> locations;
};

#ifdef CZSFP_IMPLEMENTATION
#ifndef CZSFP_IMPLEMENTATION_GUARD_
#define CZSFP_IMPLEMENTATION_GUARD_
FileQuery FilePack::get(const char* filename) const
{
	auto res = this->locations.find(filename);
	if (res == this->locations.end())
		return { uint64_t(-1), 0 };

	return res->second;
}

#endif
#endif
}
#endif
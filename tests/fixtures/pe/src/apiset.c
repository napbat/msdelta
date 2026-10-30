/* A DLL with data only, in the shape of apisetschema.dll: .rdata, .apiset and .rsrc sections,
 * no code. Build with scripts/build-pe-fixtures.py. VERSION selects the version. */
#ifndef VERSION
#define VERSION 1
#endif

#pragma section(".apiset", read)

typedef struct {
    unsigned int flags;
    unsigned int name_offset;
    unsigned int name_length;
    unsigned int value_offset;
} entry;

#define NAME(n) L"api-ms-win-core-sample-l1-1-" L#n

__declspec(allocate(".apiset")) const struct {
    unsigned int version;
    unsigned int size;
    unsigned int count;
    entry entries[VERSION + 3];
    unsigned short names[VERSION + 3][40];
} apiset_data = {
    6, sizeof(apiset_data), VERSION + 3,
    {
        { 1, 0x100, 60, 0x200 },
        { 1, 0x140, 60, 0x240 },
        { 0, 0x180, 60, 0x280 },
#if VERSION >= 2
        { 1, 0x1c0, 60, 0x2c0 },
#endif
        { 1, 0x200, 60, 0x300 },
    },
    {
        NAME(0), NAME(1), NAME(2),
#if VERSION >= 2
        NAME(3),
#endif
        NAME(4),
    },
};

/* Keep the data in the image: export it. */
__declspec(dllexport) const void *const apiset_root = &apiset_data;

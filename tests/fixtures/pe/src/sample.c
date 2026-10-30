/* A small DLL with code, imports, exports, relocations, resources and unwind data.
 * Build with scripts/build-pe-fixtures.py. VERSION selects the first or the second version. */
#include <windows.h>

#ifndef VERSION
#define VERSION 1
#endif

typedef int (*op_fn)(int, int);

static int add(int a, int b) { return a + b; }
static int sub(int a, int b) { return a - b; }
static int mul(int a, int b) { return a * b; }
#if VERSION >= 2
static int mod(int a, int b) { return b ? a % b : 0; }
#endif

/* Absolute pointers: base relocations. */
static op_fn ops[] = { add, sub, mul,
#if VERSION >= 2
    mod,
#endif
};
static const char *names[] = { "add", "sub", "mul",
#if VERSION >= 2
    "mod",
#endif
};

static volatile int counter;
static char scratch[256];

__declspec(noinline) static int dispatch(int op, int a, int b)
{
    switch (op) {
    case 0: return ops[0](a, b);
    case 1: return ops[1](a, b) + 1;
    case 2: return ops[2](a, b) * 3;
    case 3: return a ^ b;
    case 4: return a | b;
    case 5: return a & b;
#if VERSION >= 2
    case 6: return ops[3](a, b);
    case 7: return a << (b & 7);
#endif
    default: return -1;
    }
}

__declspec(dllexport) int __cdecl sample_dispatch(int op, int a, int b)
{
    counter++;
    return dispatch(op, a, b);
}

__declspec(dllexport) const char *__cdecl sample_name(int op)
{
    if (op < 0 || op >= (int)(sizeof names / sizeof names[0]))
        return "none";
    return names[op];
}

__declspec(dllexport) DWORD __cdecl sample_ticks(void)
{
    DWORD t = GetTickCount();
    wsprintfA(scratch, "ticks %lu count %d", t, counter);
    OutputDebugStringA(scratch);
    return t;
}

__declspec(dllexport) int __cdecl sample_message(const char *text)
{
#if VERSION >= 2
    if (text == NULL)
        text = "(null)";
#endif
    return MessageBoxA(NULL, text, "sample", MB_OK);
}

#if VERSION >= 2
__declspec(dllexport) int __cdecl sample_sum(const int *values, int count)
{
    int total = 0;
    for (int i = 0; i < count; i++)
        total += values[i];
    return total;
}
#endif

__declspec(dllexport) int sample_data[16] = { 1, 2, 3, 4, 5, 6, 7, VERSION };

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
        counter = 0;
    return TRUE;
}

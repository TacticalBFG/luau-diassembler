#include <Windows.h>
#include <string>
#include <vector>
#include <stdint.h>

extern "C" {
  #include "Lua/lopcodes.h"
  #include "Lua/lobject.h"
  #include "Lua/lfunc.h"
}

typedef unsigned char   uint8;
#define _BYTE  uint8
#define BYTEn(x, n)   (*((_BYTE*)&(x)+n))
#define BYTE1(x)   BYTEn(x,  1)  

#define LUAU_SIZE_A 8
#define LUAU_SIZE_B 16
#define LUAU_SIZE_C 24
#define LUAU_SIZE_Bx 16

#define LUAU_GET_OPCODE(i) FindOpcodeOnLuau(i & 0xFF)
#define LUAU_GET_VM_CASE(i) (unsigned __int8)(OpCodeList[i])

#define LUAU_GETARG_A(i) BYTE1(i)
#define LUAU_GETARG_B(i) ((i >> LUAU_SIZE_B) & 0xFF)
#define LUAU_GETARG_C(i) (i >> LUAU_SIZE_C)

#define LUAU_GETARG_Bx(i) (i >> LUAU_SIZE_Bx)
#define LUAU_GETARG_sBx(i) LUAU_GETARG_Bx(i) // They don't use MAXARG_sBx for theirs, their sBx looks something like this: pc += GETARG_Bx(inst)

// I'm not giving out private shit here lol, you can find this in like 20 seconds if u decompile their vm

//////// UPDATE 
#define SetfieldAddy 0x84F600 // also will have to change calling convention
#define GetfieldAddy 0x84D460 // same thing as above
#define LuaVmLoadAddy 0xDEADBEEF // "oldResult, moduleRef" > 2nd call below
#define DeserializerAddy 0xDEADBEEF // LuaVM::load addy > 1st call
#define RBX_TOP 20 // L->Top offset

typedef void(__cdecl *gf)(int, int, const char*);
gf getfield;

typedef void(__stdcall *sf)(int, int, const char*);
sf setfield;

typedef int(__cdecl *deserialize_)(int, int, const char*, unsigned int);
deserialize_ deserialize;


OpCode LuauToOp(uint8_t op);
Proto *unconvert(int L, int p, lua_State *Ls);
void decompileScript(std::string path);
void pushboolean(int L, bool val);

void loadAddys(); // CALL THIS BEFORE ANYTHING ELSE

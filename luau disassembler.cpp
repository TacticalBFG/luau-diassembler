#include "luau disassembler.h"

// Eternal's RetCheck bypass, https://github.com/EternalV3/Retcheck
namespace Retcheck {
	DWORD unprotect(DWORD addr)
	{

		BYTE* tAddr = (BYTE *)addr;

		do {
			tAddr += 0x10;
		} while (!(tAddr[0] == 0x55 && tAddr[1] == 0x8B && tAddr[2] == 0xEC));

		DWORD funcSz = tAddr - (BYTE*)addr;

		PVOID nFunc = VirtualAlloc(NULL, funcSz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (nFunc == NULL)
			return addr;

		memcpy(nFunc, (BYTE*)addr, funcSz);

		DWORD pos = (DWORD)nFunc;
		BOOL valid = false;
		do {
			if (*(BYTE*)pos == 0x72 && *(BYTE*)(pos + 0x2) == 0xA1 && *(BYTE*)(pos + 0x7) == 0x8B) {
				memcpy((void*)pos, "\xEB", 1);

				DWORD cNFunc = (DWORD)nFunc;
				do {
					if (*(BYTE*)cNFunc == 0xE8)
					{
						DWORD tFunc = addr + (cNFunc - (DWORD)nFunc);
						DWORD oFunc = (tFunc + *(DWORD*)(tFunc + 1)) + 5;

						if (oFunc % 16 == 0)
						{
							DWORD rebFAddr = oFunc - cNFunc - 5;
							*(DWORD*)(cNFunc + 1) = rebFAddr;
						}
						cNFunc += 5;
					}
					else
						cNFunc += 1;
				} while (cNFunc - (DWORD)nFunc < funcSz);

				valid = true;
			}
			pos += 1;
		} while (pos < (DWORD)nFunc + funcSz);

		if (!valid) {
			VirtualFree(nFunc, funcSz, MEM_RELEASE);
			return addr;
		}

		return (DWORD)nFunc;
	}
}


void loadAddys() {
  getfield = (gf)Retcheck::unprotect(aslr(GetfieldAddy));
  setfield = (sf)Retcheck::unprotect(aslr(SetfieldAddy));
  deserialize = (deserialize_)aslr(DeserializerAddy);
}

OpCode LuauToOp(uint8_t op) {
	switch (op) {
	case 0x52: return OP_MOVE; break;
	case 0x6F: return OP_LOADK; break;
	case 0xA9: return OP_LOADBOOL; break;
	case 0xC6: return OP_LOADNIL; break;
	case 0xFB: return OP_GETUPVAL; break;
	case 0x35: return OP_GETGLOBAL; break;
	case 0x87: return OP_GETTABLE; break;
	case 0x18: return OP_SETGLOBAL; break;
	case 0xDE: return OP_SETUPVAL; break;
	case 0x6A: return OP_SETTABLE; break;
	case 0xFF: return OP_NEWTABLE; break;
  
	case 0x95: return OP_ADD; break;
	case 0x78: return OP_SUB; break;
	case 0x5B: return OP_MUL; break;
	case 0x3D: return OP_DIV; break;
	case 0xCF: return OP_MOD; break;

	case 0x39: return OP_UNM; break;

	case 0x1C: return OP_LEN; break;
	case 0x73: return OP_CONCAT; break;
	case 0x65: return OP_JMP; break;

	case 0x60: return OP_LT; break;
	case 0x7D: return OP_LE; break;
	case 0x0E: return OP_TEST; break;

	case 0x9F: return OP_CALL; break;
	case 0x82: return OP_RETURN; break;



	case 0xC5: return OP_SETLIST; break;
	case 0xC1: return OP_CLOSE; break;
	case 0xD9: return OP_CLOSURE; break;
	}
} // Missing some opcodes rn, will complete later

Proto *unconvert(int L, int p, lua_State *Ls) {
	Proto *f = luaF_newproto(Ls);
	f->sizek = *(DWORD*)(p + proto::sizek);
	f->sizecode = *(DWORD*)(p + proto::sizecode);
	f->sizep = *(DWORD*)(p + proto::sizep);

	f->k = luaM_newvector(Ls, f->sizek, TValue);
	f->code = luaM_newvector(Ls, f->sizecode, Instruction);
	f->p = luaM_newvector(Ls, f->sizep, Proto*);

	int *rp = (int*)RBX_DECRYPT_PROTO(p + proto::p);
	for (int i = 0; i < f->sizep; i++)
		f->p[i] = unconvert(L, rp[i], Ls);

	TValue *_rk = (TValue*)RBX_DECRYPT_PROTO(p + proto::k);
	for (int i = 0; i < f->sizek; i++) {
		TValue *pk = &f->k[i];
		TValue *rk = &_rk[i];

		switch (rk->tt) {
		case 0:
			pk->tt = LUA_TNIL;
			break;
		case 2:
			pk->tt = LUA_TNUMBER;
			pk->value.n = UnxorDouble(&nvalue(rk));
			break;
		case 3:
			pk->tt = LUA_TBOOLEAN;
			pk->value.b = bvalue(rk);
			break;
		case 4:
			pk->tt = LUA_TSTRING;
			pk->value.gc = (GCObject*)luaS_new(Ls, svalue(rk));
			break;
		}
	}

	Instruction *rc = (Instruction*)RBX_DECRYPT_PROTO(p + proto::code);
	for (int i = 0; i < f->sizecode; i++) {
		Instruction rinst = rc[i];
		Instruction inst = f->code[i];

		OpCode op = LUAU_GET_OPCODE(rinst);
		uint8_t rop = rinst & 0xFF;
		

		SET_OPCODE(inst, op);
		SETARG_A(inst, LUAU_GETARG_A(rinst));
		switch (getOpMode(inst)) {
		case iABC:
			SETARG_B(inst, LUAU_GETARG_B(rinst));
			SETARG_C(inst, LUAU_GETARG_C(rinst));
			break;
		case iABx:
			SETARG_Bx(inst, LUAU_GETARG_Bx(rinst));
			break;
    case iAsBx:
      SETARG_sBx(inst, LUAU_GETARG_Bx(rinst));
      break;
		}
	}
	
	return f;
}

void decompileScript(std::string path) {
	std::vector<std::string>indicies = SplitString(path.c_str(), '.');
	getglobal(L, "game");
	for (int i = 1; i < indicies.size(); i++)
		getfield(L, -1, indicies.at(i).c_str());

	pushboolean(L, true);
	setfield(L, -2, "Disabled");
	deserializer_hook();
	pushboolean(L, false);
	setfield(L, -2, "Disabled");

	if (DecompiledCl && !(*(DWORD*)(DecompiledCl + 6))) {
		DWORD cl = RBX_DECRYPT_CLOSURE(*(DWORD*)DecompiledCl);
		Proto *f = unconvert(L, cl, lua_open());
	}
	else {
		printf("what");
	}
}

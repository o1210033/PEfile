#include <stdio.h>

#include "disasm.h"

void Set_opc1(t_disasm *da){
	switch (da->opc[0])
	{
	case 0x03:
		strcpy(da->asm, "ADD");
		da->arg[0] = R32; da->arg[1] = RM32; da->arg[2] = 0;
		break;
	case 0x05:
		strcpy(da->asm, "ADD");
		da->arg[0] = EAX; da->arg[1] = IMM32; da->arg[2] = 0;
		break;
	case 0x0B:
		strcpy(da->asm, "OR");
		da->arg[0] = R32; da->arg[1] = RM32; da->arg[2] = 0;
		break;
	case 0x0D:
		strcpy(da->asm, "OR");
		da->arg[0] = EAX; da->arg[1] = IMM32; da->arg[2] = 0;
		break;
	case 0x1B:
		strcpy(da->asm, "SBB");
		da->arg[0] = R32; da->arg[1] = RM32; da->arg[2] = 0;
		break;
	case 0x25:
		strcpy(da->asm, "AND");
		da->arg[0] = EAX; da->arg[1] = IMM32; da->arg[2] = 0;
		break;
	case 0x2B:
		strcpy(da->asm, "SUB");
		da->arg[0] = R32; da->arg[1] = RM32; da->arg[2] = 0;
		break;
	case 0x2D:
		strcpy(da->asm, "SUB");
		da->arg[0] = EAX; da->arg[1] = IMM32; da->arg[2] = 0;
		break;
	case 0x31:
		strcpy(da->asm, "XOR");
		da->arg[0] = RM32; da->arg[1] = R32; da->arg[2] = 0;
		break;
	case 0x33:
		strcpy(da->asm, "XOR");
		da->arg[0] = R32; da->arg[1] = RM32; da->arg[2] = 0;
		break;
	case 0x39:
		strcpy(da->asm, "CMP");
		da->arg[0] = RM32; da->arg[1] = R32; da->arg[2] = 0;
		break;
	case 0x3B:
		strcpy(da->asm, "CMP");
		da->arg[0] = R32; da->arg[1] = RM32; da->arg[2] = 0;
		break;
	case 0x3D:
		strcpy(da->asm, "CMP");
		da->arg[0] = EAX; da->arg[1] = IMM32; da->arg[2] = 0;
		break;
	case 0x40:
		strcpy(da->asm, "INC");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x41:
		strcpy(da->asm, "INC");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x42:
		strcpy(da->asm, "INC");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x43:
		strcpy(da->asm, "INC");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x44:
		strcpy(da->asm, "INC");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x45:
		strcpy(da->asm, "INC");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x46:
		strcpy(da->asm, "INC");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x47:
		strcpy(da->asm, "INC");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x48:
		strcpy(da->asm, "DEC");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x49:
		strcpy(da->asm, "DEC");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x4A:
		strcpy(da->asm, "DEC");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x4B:
		strcpy(da->asm, "DEC");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x4C:
		strcpy(da->asm, "DEC");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x4D:
		strcpy(da->asm, "DEC");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x4E:
		strcpy(da->asm, "DEC");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x4F:
		strcpy(da->asm, "DEC");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x50:
		strcpy(da->asm, "PUSH");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x51:
		strcpy(da->asm, "PUSH");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x52:
		strcpy(da->asm, "PUSH");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x53:
		strcpy(da->asm, "PUSH");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x54:
		strcpy(da->asm, "PUSH");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x55:
		strcpy(da->asm, "PUSH");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x56:
		strcpy(da->asm, "PUSH");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x57:
		strcpy(da->asm, "PUSH");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x58:
		strcpy(da->asm, "POP");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x59:
		strcpy(da->asm, "POP");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x5A:
		strcpy(da->asm, "POP");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x5B:
		strcpy(da->asm, "POP");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x5C:
		strcpy(da->asm, "POP");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x5D:
		strcpy(da->asm, "POP");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x5E:
		strcpy(da->asm, "POP");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x5F:
		strcpy(da->asm, "POP");
		da->arg[0] = R32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x68:
		strcpy(da->asm, "PUSH");
		da->arg[0] = IMM32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x69:
		strcpy(da->asm, "IMUL");
		da->arg[0] = R32; da->arg[1] = RM32; da->arg[2] = IMM32;
		break;
	case 0x6A:
		strcpy(da->asm, "PUSH");
		da->arg[0] = IMM8; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x6B:
		strcpy(da->asm, "IMUL");
		da->arg[0] = R32; da->arg[1] = RM32; da->arg[2] = IMM8;
		break;
	case 0x72:
		strcpy(da->asm, "JB");
		da->arg[0] = REL8; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x73:
		strcpy(da->asm, "JNB");
		da->arg[0] = REL8; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x74:
		strcpy(da->asm, "JE");
		da->arg[0] = REL8; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x75:
		strcpy(da->asm, "JNZ");
		da->arg[0] = REL8; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x76:
		strcpy(da->asm, "JBE");
		da->arg[0] = REL8; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x77:
		strcpy(da->asm, "JA");
		da->arg[0] = REL8; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x79:
		strcpy(da->asm, "JNS");
		da->arg[0] = REL8; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x7C:
		strcpy(da->asm, "JL");
		da->arg[0] = REL8; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x7E:
		strcpy(da->asm, "JLE");
		da->arg[0] = REL8; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x7F:
		strcpy(da->asm, "JG");
		da->arg[0] = REL8; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x81:
		strcpy(da->asm, "ModRM");
		da->arg[0] = RM32; da->arg[1] = IMM32; da->arg[2] = 0;
		break;
	case 0x82:
		strcpy(da->asm, "ModRM");
		da->arg[0] = RM8; da->arg[1] = IMM8; da->arg[2] = 0;
		break;
	case 0x83:
		strcpy(da->asm, "ModRM");
		da->arg[0] = RM32; da->arg[1] = IMM8; da->arg[2] = 0;
		break;
	case 0x85:
		strcpy(da->asm, "TEST");
		da->arg[0] = RM32; da->arg[1] = R32; da->arg[2] = 0;
		break;
	case 0x89:
		strcpy(da->asm, "MOV");
		da->arg[0] = RM32; da->arg[1] = R32; da->arg[2] = 0;
		break;
	case 0x8B:
		strcpy(da->asm, "MOV");
		da->arg[0] = R32; da->arg[1] = RM32; da->arg[2] = 0;
		break;
	case 0x8C:
		strcpy(da->asm, "MOV");
		da->arg[0] = RM32; da->arg[1] = SREG; da->arg[2] = 0;
		break;
	case 0x8D:
		strcpy(da->asm, "LEA");
		da->arg[0] = R32; da->arg[1] = RM32; da->arg[2] = 0;
		break;
	case 0x8F:
		strcpy(da->asm, "POP");
		da->arg[0] = RM32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x90:
		strcpy(da->asm, "NOP");
		da->arg[0] = 0; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x9C:
		strcpy(da->asm, "PUSHFD");
		da->arg[0] = 0; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0xA1:
		strcpy(da->asm, "MOV");
		da->arg[0] = EAX; da->arg[1] = MOFFS32; da->arg[2] = 0;
		break;
	case 0xA3:
		strcpy(da->asm, "MOV");
		da->arg[0] = MOFFS32; da->arg[1] = EAX; da->arg[2] = 0;
		break;
	case 0xB8:
		strcpy(da->asm, "MOV");
		da->arg[0] = R32; da->arg[1] = IMM32; da->arg[2] = 0;
		break;
	case 0xB9:
		strcpy(da->asm, "MOV");
		da->arg[0] = R32; da->arg[1] = IMM32; da->arg[2] = 0;
		break;
	case 0xBA:
		strcpy(da->asm, "MOV");
		da->arg[0] = R32; da->arg[1] = IMM32; da->arg[2] = 0;
		break;
	case 0xBB:
		strcpy(da->asm, "MOV");
		da->arg[0] = R32; da->arg[1] = IMM32; da->arg[2] = 0;
		break;
	case 0xBC:
		strcpy(da->asm, "MOV");
		da->arg[0] = R32; da->arg[1] = IMM32; da->arg[2] = 0;
		break;
	case 0xBD:
		strcpy(da->asm, "MOV");
		da->arg[0] = R32; da->arg[1] = IMM32; da->arg[2] = 0;
		break;
	case 0xBE:
		strcpy(da->asm, "MOV");
		da->arg[0] = R32; da->arg[1] = IMM32; da->arg[2] = 0;
		break;
	case 0xBF:
		strcpy(da->asm, "MOV");
		da->arg[0] = R32; da->arg[1] = IMM32; da->arg[2] = 0;
		break;
	case 0xC1:
		strcpy(da->asm, "ModRM");
		da->arg[0] = RM32; da->arg[1] = IMM8; da->arg[2] = 0;
		break;
	case 0xC2:
		strcpy(da->asm, "RETN");
		da->arg[0] = IMM16; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0xC3:
		strcpy(da->asm, "RETN");
		da->arg[0] = 0; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0xC7:
		strcpy(da->asm, "MOV");
		da->arg[0] = RM32; da->arg[1] = IMM32; da->arg[2] = 0;
		break;
	case 0xC9:
		strcpy(da->asm, "LEAVE");
		da->arg[0] = 0; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0xCC:
		strcpy(da->asm, "INT3");
		da->arg[0] = 0; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0xD1:
		strcpy(da->asm, "ModRM");
		da->arg[0] = RM32; da->arg[1] = DEF1; da->arg[2] = 0;
		break;
	case 0xE8:
		strcpy(da->asm, "CALL");
		da->arg[0] = REL32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0xE9:
		strcpy(da->asm, "JMP");
		da->arg[0] = REL32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0xEB:
		strcpy(da->asm, "JMP");
		da->arg[0] = REL8; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0xF6:
		strcpy(da->asm, "ModRM");
		da->arg[0] = RM8; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0xF7:
		strcpy(da->asm, "ModRM");
		da->arg[0] = RM32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0xFF:
		strcpy(da->asm, "ModRM");
		da->arg[0] = RM32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	default:
		strcpy(da->asm, "??");
		da->arg[0] = 0; da->arg[1] = 0; da->arg[2] = 0;
		break;
	}
}

void Set_opc2(t_disasm *da){
	switch (da->opc[1])
	{
	case 0x83:
		strcpy(da->asm, "JAE");
		da->arg[0] = REL32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x84:
		strcpy(da->asm, "JE");
		da->arg[0] = REL32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x85:
		strcpy(da->asm, "JNE");
		da->arg[0] = REL32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x86:
		strcpy(da->asm, "JBE");
		da->arg[0] = REL32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x8c:
		strcpy(da->asm, "JL");
		da->arg[0] = REL32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x8e:
		strcpy(da->asm, "JLE");
		da->arg[0] = REL32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x8f:
		strcpy(da->asm, "JG");
		da->arg[0] = REL32; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x94:
		strcpy(da->asm, "SETE");
		da->arg[0] = RM8; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0x95:
		strcpy(da->asm, "SETNE");
		da->arg[0] = RM8; da->arg[1] = 0; da->arg[2] = 0;
		break;
	case 0xb7:
		strcpy(da->asm, "MOVZX");
		da->arg[0] = R32; da->arg[1] = RM32; da->arg[2] = 0;
		break;
	default:
		strcpy(da->asm, "??");
		da->arg[0] = 0; da->arg[1] = 0; da->arg[2] = 0;
		break;
	}
}
#include <stdio.h>

#include "disasm.h"

void Set_opc1(t_disasm *da){
	switch (da->opc[0])
	{
	case 0x03:
		strcpy(da->asm, "ADD");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = 0;
		break;
	case 0x05:
		strcpy(da->asm, "ADD");
		da->operand[0] = EAX; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0x0B:
		strcpy(da->asm, "OR");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = 0;
		break;
	case 0x0D:
		strcpy(da->asm, "OR");
		da->operand[0] = EAX; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0x1B:
		strcpy(da->asm, "SBB");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = 0;
		break;
	case 0x25:
		strcpy(da->asm, "AND");
		da->operand[0] = EAX; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0x2B:
		strcpy(da->asm, "SUB");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = 0;
		break;
	case 0x2D:
		strcpy(da->asm, "SUB");
		da->operand[0] = EAX; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0x31:
		strcpy(da->asm, "XOR");
		da->operand[0] = RM32; da->operand[1] = R32; da->operand[2] = 0;
		break;
	case 0x32:
		strcpy(da->asm, "XOR");
		da->operand[0] = R8; da->operand[1] = RM8; da->operand[2] = 0;
		break;
	case 0x33:
		strcpy(da->asm, "XOR");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = 0;
		break;
	case 0x39:
		strcpy(da->asm, "CMP");
		da->operand[0] = RM32; da->operand[1] = R32; da->operand[2] = 0;
		break;
	case 0x3B:
		strcpy(da->asm, "CMP");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = 0;
		break;
	case 0x3D:
		strcpy(da->asm, "CMP");
		da->operand[0] = EAX; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0x40:
		strcpy(da->asm, "INC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x41:
		strcpy(da->asm, "INC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x42:
		strcpy(da->asm, "INC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x43:
		strcpy(da->asm, "INC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x44:
		strcpy(da->asm, "INC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x45:
		strcpy(da->asm, "INC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x46:
		strcpy(da->asm, "INC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x47:
		strcpy(da->asm, "INC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x48:
		strcpy(da->asm, "DEC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x49:
		strcpy(da->asm, "DEC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x4A:
		strcpy(da->asm, "DEC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x4B:
		strcpy(da->asm, "DEC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x4C:
		strcpy(da->asm, "DEC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x4D:
		strcpy(da->asm, "DEC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x4E:
		strcpy(da->asm, "DEC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x4F:
		strcpy(da->asm, "DEC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x50:
		strcpy(da->asm, "PUSH");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x51:
		strcpy(da->asm, "PUSH");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x52:
		strcpy(da->asm, "PUSH");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x53:
		strcpy(da->asm, "PUSH");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x54:
		strcpy(da->asm, "PUSH");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x55:
		strcpy(da->asm, "PUSH");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x56:
		strcpy(da->asm, "PUSH");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x57:
		strcpy(da->asm, "PUSH");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x58:
		strcpy(da->asm, "POP");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x59:
		strcpy(da->asm, "POP");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x5A:
		strcpy(da->asm, "POP");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x5B:
		strcpy(da->asm, "POP");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x5C:
		strcpy(da->asm, "POP");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x5D:
		strcpy(da->asm, "POP");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x5E:
		strcpy(da->asm, "POP");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x5F:
		strcpy(da->asm, "POP");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x68:
		strcpy(da->asm, "PUSH");
		da->operand[0] = IMM32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x69:
		strcpy(da->asm, "IMUL");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = IMM32;
		break;
	case 0x6A:
		strcpy(da->asm, "PUSH");
		da->operand[0] = IMM8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x6B:
		strcpy(da->asm, "IMUL");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = IMM8;
		break;
	case 0x72:
		strcpy(da->asm, "JB");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x73:
		strcpy(da->asm, "JNB");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x74:
		strcpy(da->asm, "JE");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x75:
		strcpy(da->asm, "JNZ");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x76:
		strcpy(da->asm, "JBE");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x77:
		strcpy(da->asm, "JA");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x79:
		strcpy(da->asm, "JNS");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x7C:
		strcpy(da->asm, "JL");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x7D:
		strcpy(da->asm, "JGE");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x7E:
		strcpy(da->asm, "JLE");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x7F:
		strcpy(da->asm, "JG");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x80:
		strcpy(da->asm, "ModRM");
		da->operand[0] = RM8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0x81:
		strcpy(da->asm, "ModRM");
		da->operand[0] = RM32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0x82:
		strcpy(da->asm, "ModRM");
		da->operand[0] = RM8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0x83:
		strcpy(da->asm, "ModRM");
		da->operand[0] = RM32; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0x84:
		strcpy(da->asm, "TEST");
		da->operand[0] = RM8; da->operand[1] = R8; da->operand[2] = 0;
		break;
	case 0x85:
		strcpy(da->asm, "TEST");
		da->operand[0] = RM32; da->operand[1] = R32; da->operand[2] = 0;
		break;
	case 0x87:
		strcpy(da->asm, "XCHG");
		da->operand[0] = RM32; da->operand[1] = R32; da->operand[2] = 0;
		break;
	case 0x88:
		strcpy(da->asm, "MOV");
		da->operand[0] = RM8; da->operand[1] = R8; da->operand[2] = 0;
		break;
	case 0x89:
		strcpy(da->asm, "MOV");
		da->operand[0] = RM32; da->operand[1] = R32; da->operand[2] = 0;
		break;
	case 0x8A:
		strcpy(da->asm, "MOV");
		da->operand[0] = R8; da->operand[1] = RM8; da->operand[2] = 0;
		break;
	case 0x8B:
		strcpy(da->asm, "MOV");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = 0;
		break;
	case 0x8C:
		strcpy(da->asm, "MOV");
		da->operand[0] = RM32; da->operand[1] = SREG; da->operand[2] = 0;
		break;
	case 0x8D:
		strcpy(da->asm, "LEA");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = 0;
		break;
	case 0x8F:
		strcpy(da->asm, "POP");
		da->operand[0] = RM32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x90:
		strcpy(da->asm, "NOP");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x9C:
		strcpy(da->asm, "PUSHFD");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xA1:
		strcpy(da->asm, "MOV");
		da->operand[0] = EAX; da->operand[1] = MOFFS32; da->operand[2] = 0;
		break;
	case 0xA3:
		strcpy(da->asm, "MOV");
		da->operand[0] = MOFFS32; da->operand[1] = EAX; da->operand[2] = 0;
		break;
	case 0xA4:
		strcpy(da->asm, "MOVSB");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xA5:
		strcpy(da->asm, "MOVSD");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xAA:
		strcpy(da->asm, "STOSB");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xAB:
		strcpy(da->asm, "STOSD");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xB0:
		strcpy(da->asm, "MOV");
		da->operand[0] = R8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xB1:
		strcpy(da->asm, "MOV");
		da->operand[0] = R8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xB2:
		strcpy(da->asm, "MOV");
		da->operand[0] = R8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xB3:
		strcpy(da->asm, "MOV");
		da->operand[0] = R8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xB4:
		strcpy(da->asm, "MOV");
		da->operand[0] = R8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xB5:
		strcpy(da->asm, "MOV");
		da->operand[0] = R8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xB6:
		strcpy(da->asm, "MOV");
		da->operand[0] = R8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xB7:
		strcpy(da->asm, "MOV");
		da->operand[0] = R8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xB8:
		strcpy(da->asm, "MOV");
		da->operand[0] = R32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0xB9:
		strcpy(da->asm, "MOV");
		da->operand[0] = R32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0xBA:
		strcpy(da->asm, "MOV");
		da->operand[0] = R32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0xBB:
		strcpy(da->asm, "MOV");
		da->operand[0] = R32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0xBC:
		strcpy(da->asm, "MOV");
		da->operand[0] = R32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0xBD:
		strcpy(da->asm, "MOV");
		da->operand[0] = R32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0xBE:
		strcpy(da->asm, "MOV");
		da->operand[0] = R32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0xBF:
		strcpy(da->asm, "MOV");
		da->operand[0] = R32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0xC1:
		strcpy(da->asm, "ModRM");
		da->operand[0] = RM32; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xC2:
		strcpy(da->asm, "RETN");
		da->operand[0] = IMM16; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xC3:
		strcpy(da->asm, "RETN");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xC6:
		strcpy(da->asm, "MOV");
		da->operand[0] = RM8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xC7:
		strcpy(da->asm, "MOV");
		da->operand[0] = RM32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0xC9:
		strcpy(da->asm, "LEAVE");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xCC:
		strcpy(da->asm, "INT3");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xCD:
		strcpy(da->asm, "INT");
		da->operand[0] = IMM8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xD1:
		strcpy(da->asm, "ModRM");
		da->operand[0] = RM32; da->operand[1] = DEF1; da->operand[2] = 0;
		break;
	case 0xE8:
		strcpy(da->asm, "CALL");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xE9:
		strcpy(da->asm, "JMP");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xEB:
		strcpy(da->asm, "JMP");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xF6:
		strcpy(da->asm, "ModRM");
		da->operand[0] = RM8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xF7:
		strcpy(da->asm, "ModRM");
		da->operand[0] = RM32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xFF:
		strcpy(da->asm, "ModRM");
		da->operand[0] = RM32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	default:
		strcpy(da->asm, "??");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	}
}

void Set_opc2(t_disasm *da){
	switch (da->opc[1])
	{
	case 0x82:
		strcpy(da->asm, "JB");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x83:
		strcpy(da->asm, "JAE");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x84:
		strcpy(da->asm, "JE");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x85:
		strcpy(da->asm, "JNE");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x86:
		strcpy(da->asm, "JBE");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x87:
		strcpy(da->asm, "JA");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x8c:
		strcpy(da->asm, "JL");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x8e:
		strcpy(da->asm, "JLE");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x8f:
		strcpy(da->asm, "JG");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x94:
		strcpy(da->asm, "SETE");
		da->operand[0] = RM8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x95:
		strcpy(da->asm, "SETNE");
		da->operand[0] = RM8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xb1:
		strcpy(da->asm, "CMPXCHG");
		da->operand[0] = RM32; da->operand[1] = R32; da->operand[2] = 0;
		break;
	case 0xb6:
		strcpy(da->asm, "MOVZX");
		da->operand[0] = R32; da->operand[1] = RM8; da->operand[2] = 0;
		break;
	case 0xb7:
		strcpy(da->asm, "MOVZX");
		da->operand[0] = R32; da->operand[1] = RM16; da->operand[2] = 0;
		break;
	default:
		strcpy(da->asm, "??");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	}
}
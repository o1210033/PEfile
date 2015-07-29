/* opcode.c */
/* オペコードに対応した命令・オペランドを設定 */



#include <stdio.h>

#include "disasm.h"



/* 1バイトオペコードに対応した命令・オペランドを設定する関数 */
void Set_opc1(t_disasm *da){
	switch (da->opc[0])
	{
	case 0x03:
		strcpy(da->instruction, "ADD");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = 0;
		break;
	case 0x05:
		strcpy(da->instruction, "ADD");
		da->operand[0] = EAX; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0x0B:
		strcpy(da->instruction, "OR");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = 0;
		break;
	case 0x0D:
		strcpy(da->instruction, "OR");
		da->operand[0] = EAX; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0x1B:
		strcpy(da->instruction, "SBB");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = 0;
		break;
	case 0x25:
		strcpy(da->instruction, "AND");
		da->operand[0] = EAX; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0x2B:
		strcpy(da->instruction, "SUB");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = 0;
		break;
	case 0x2D:
		strcpy(da->instruction, "SUB");
		da->operand[0] = EAX; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0x31:
		strcpy(da->instruction, "XOR");
		da->operand[0] = RM32; da->operand[1] = R32; da->operand[2] = 0;
		break;
	case 0x32:
		strcpy(da->instruction, "XOR");
		da->operand[0] = R8; da->operand[1] = RM8; da->operand[2] = 0;
		break;
	case 0x33:
		strcpy(da->instruction, "XOR");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = 0;
		break;
	case 0x39:
		strcpy(da->instruction, "CMP");
		da->operand[0] = RM32; da->operand[1] = R32; da->operand[2] = 0;
		break;
	case 0x3B:
		strcpy(da->instruction, "CMP");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = 0;
		break;
	case 0x3D:
		strcpy(da->instruction, "CMP");
		da->operand[0] = EAX; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0x40:
		strcpy(da->instruction, "INC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x41:
		strcpy(da->instruction, "INC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x42:
		strcpy(da->instruction, "INC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x43:
		strcpy(da->instruction, "INC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x44:
		strcpy(da->instruction, "INC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x45:
		strcpy(da->instruction, "INC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x46:
		strcpy(da->instruction, "INC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x47:
		strcpy(da->instruction, "INC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x48:
		strcpy(da->instruction, "DEC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x49:
		strcpy(da->instruction, "DEC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x4A:
		strcpy(da->instruction, "DEC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x4B:
		strcpy(da->instruction, "DEC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x4C:
		strcpy(da->instruction, "DEC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x4D:
		strcpy(da->instruction, "DEC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x4E:
		strcpy(da->instruction, "DEC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x4F:
		strcpy(da->instruction, "DEC");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x50:
		strcpy(da->instruction, "PUSH");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x51:
		strcpy(da->instruction, "PUSH");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x52:
		strcpy(da->instruction, "PUSH");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x53:
		strcpy(da->instruction, "PUSH");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x54:
		strcpy(da->instruction, "PUSH");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x55:
		strcpy(da->instruction, "PUSH");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x56:
		strcpy(da->instruction, "PUSH");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x57:
		strcpy(da->instruction, "PUSH");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x58:
		strcpy(da->instruction, "POP");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x59:
		strcpy(da->instruction, "POP");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x5A:
		strcpy(da->instruction, "POP");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x5B:
		strcpy(da->instruction, "POP");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x5C:
		strcpy(da->instruction, "POP");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x5D:
		strcpy(da->instruction, "POP");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x5E:
		strcpy(da->instruction, "POP");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x5F:
		strcpy(da->instruction, "POP");
		da->operand[0] = R32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x68:
		strcpy(da->instruction, "PUSH");
		da->operand[0] = IMM32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x69:
		strcpy(da->instruction, "IMUL");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = IMM32;
		break;
	case 0x6A:
		strcpy(da->instruction, "PUSH");
		da->operand[0] = IMM8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x6B:
		strcpy(da->instruction, "IMUL");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = IMM8;
		break;
	case 0x72:
		strcpy(da->instruction, "JB");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x73:
		strcpy(da->instruction, "JNB");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x74:
		strcpy(da->instruction, "JE");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x75:
		strcpy(da->instruction, "JNZ");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x76:
		strcpy(da->instruction, "JBE");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x77:
		strcpy(da->instruction, "JA");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x79:
		strcpy(da->instruction, "JNS");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x7C:
		strcpy(da->instruction, "JL");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x7D:
		strcpy(da->instruction, "JGE");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x7E:
		strcpy(da->instruction, "JLE");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x7F:
		strcpy(da->instruction, "JG");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x80:
		strcpy(da->instruction, "ModRM");
		da->operand[0] = RM8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0x81:
		strcpy(da->instruction, "ModRM");
		da->operand[0] = RM32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0x82:
		strcpy(da->instruction, "ModRM");
		da->operand[0] = RM8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0x83:
		strcpy(da->instruction, "ModRM");
		da->operand[0] = RM32; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0x84:
		strcpy(da->instruction, "TEST");
		da->operand[0] = RM8; da->operand[1] = R8; da->operand[2] = 0;
		break;
	case 0x85:
		strcpy(da->instruction, "TEST");
		da->operand[0] = RM32; da->operand[1] = R32; da->operand[2] = 0;
		break;
	case 0x87:
		strcpy(da->instruction, "XCHG");
		da->operand[0] = RM32; da->operand[1] = R32; da->operand[2] = 0;
		break;
	case 0x88:
		strcpy(da->instruction, "MOV");
		da->operand[0] = RM8; da->operand[1] = R8; da->operand[2] = 0;
		break;
	case 0x89:
		strcpy(da->instruction, "MOV");
		da->operand[0] = RM32; da->operand[1] = R32; da->operand[2] = 0;
		break;
	case 0x8A:
		strcpy(da->instruction, "MOV");
		da->operand[0] = R8; da->operand[1] = RM8; da->operand[2] = 0;
		break;
	case 0x8B:
		strcpy(da->instruction, "MOV");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = 0;
		break;
	case 0x8C:
		strcpy(da->instruction, "MOV");
		da->operand[0] = RM32; da->operand[1] = SREG; da->operand[2] = 0;
		break;
	case 0x8D:
		strcpy(da->instruction, "LEA");
		da->operand[0] = R32; da->operand[1] = RM32; da->operand[2] = 0;
		break;
	case 0x8F:
		strcpy(da->instruction, "POP");
		da->operand[0] = RM32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x90:
		strcpy(da->instruction, "NOP");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x9C:
		strcpy(da->instruction, "PUSHFD");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xA1:
		strcpy(da->instruction, "MOV");
		da->operand[0] = EAX; da->operand[1] = MOFFS32; da->operand[2] = 0;
		break;
	case 0xA3:
		strcpy(da->instruction, "MOV");
		da->operand[0] = MOFFS32; da->operand[1] = EAX; da->operand[2] = 0;
		break;
	case 0xA4:
		strcpy(da->instruction, "MOVSB");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xA5:
		strcpy(da->instruction, "MOVSD");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xAA:
		strcpy(da->instruction, "STOSB");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xAB:
		strcpy(da->instruction, "STOSD");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xB0:
		strcpy(da->instruction, "MOV");
		da->operand[0] = R8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xB1:
		strcpy(da->instruction, "MOV");
		da->operand[0] = R8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xB2:
		strcpy(da->instruction, "MOV");
		da->operand[0] = R8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xB3:
		strcpy(da->instruction, "MOV");
		da->operand[0] = R8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xB4:
		strcpy(da->instruction, "MOV");
		da->operand[0] = R8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xB5:
		strcpy(da->instruction, "MOV");
		da->operand[0] = R8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xB6:
		strcpy(da->instruction, "MOV");
		da->operand[0] = R8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xB7:
		strcpy(da->instruction, "MOV");
		da->operand[0] = R8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xB8:
		strcpy(da->instruction, "MOV");
		da->operand[0] = R32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0xB9:
		strcpy(da->instruction, "MOV");
		da->operand[0] = R32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0xBA:
		strcpy(da->instruction, "MOV");
		da->operand[0] = R32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0xBB:
		strcpy(da->instruction, "MOV");
		da->operand[0] = R32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0xBC:
		strcpy(da->instruction, "MOV");
		da->operand[0] = R32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0xBD:
		strcpy(da->instruction, "MOV");
		da->operand[0] = R32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0xBE:
		strcpy(da->instruction, "MOV");
		da->operand[0] = R32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0xBF:
		strcpy(da->instruction, "MOV");
		da->operand[0] = R32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0xC1:
		strcpy(da->instruction, "ModRM");
		da->operand[0] = RM32; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xC2:
		strcpy(da->instruction, "RETN");
		da->operand[0] = IMM16; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xC3:
		strcpy(da->instruction, "RETN");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xC6:
		strcpy(da->instruction, "MOV");
		da->operand[0] = RM8; da->operand[1] = IMM8; da->operand[2] = 0;
		break;
	case 0xC7:
		strcpy(da->instruction, "MOV");
		da->operand[0] = RM32; da->operand[1] = IMM32; da->operand[2] = 0;
		break;
	case 0xC9:
		strcpy(da->instruction, "LEAVE");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xCC:
		strcpy(da->instruction, "INT3");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xCD:
		strcpy(da->instruction, "INT");
		da->operand[0] = IMM8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xD1:
		strcpy(da->instruction, "ModRM");
		da->operand[0] = RM32; da->operand[1] = DEF1; da->operand[2] = 0;
		break;
	case 0xE8:
		strcpy(da->instruction, "CALL");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xE9:
		strcpy(da->instruction, "JMP");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xEB:
		strcpy(da->instruction, "JMP");
		da->operand[0] = REL8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xF6:
		strcpy(da->instruction, "ModRM");
		da->operand[0] = RM8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xF7:
		strcpy(da->instruction, "ModRM");
		da->operand[0] = RM32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xFF:
		strcpy(da->instruction, "ModRM");
		da->operand[0] = RM32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	default:
		strcpy(da->instruction, "??");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	}
}


/* 2バイトオペコード対応した命令・オペランドを設定する関数 */
void Set_opc2(t_disasm *da){
	switch (da->opc[1])
	{
	case 0x82:
		strcpy(da->instruction, "JB");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x83:
		strcpy(da->instruction, "JAE");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x84:
		strcpy(da->instruction, "JE");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x85:
		strcpy(da->instruction, "JNE");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x86:
		strcpy(da->instruction, "JBE");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x87:
		strcpy(da->instruction, "JA");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x8c:
		strcpy(da->instruction, "JL");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x8e:
		strcpy(da->instruction, "JLE");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x8f:
		strcpy(da->instruction, "JG");
		da->operand[0] = REL32; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x94:
		strcpy(da->instruction, "SETE");
		da->operand[0] = RM8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0x95:
		strcpy(da->instruction, "SETNE");
		da->operand[0] = RM8; da->operand[1] = 0; da->operand[2] = 0;
		break;
	case 0xb1:
		strcpy(da->instruction, "CMPXCHG");
		da->operand[0] = RM32; da->operand[1] = R32; da->operand[2] = 0;
		break;
	case 0xb6:
		strcpy(da->instruction, "MOVZX");
		da->operand[0] = R32; da->operand[1] = RM8; da->operand[2] = 0;
		break;
	case 0xb7:
		strcpy(da->instruction, "MOVZX");
		da->operand[0] = R32; da->operand[1] = RM16; da->operand[2] = 0;
		break;
	default:
		strcpy(da->instruction, "??");
		da->operand[0] = 0; da->operand[1] = 0; da->operand[2] = 0;
		break;
	}
}
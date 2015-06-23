#include <stdio.h>
#include <string.h>

#include "disasm.h"

/* 引数da構造体の要素を初期化する関数 */
void Init_disasm(t_disasm *da){
	int i;

	da->asm[0] = '\0';

	da->flag_modrm = da->flag_sib = 0;

	for (i = 0; i < 3; i++)
		da->arg[i] = -1;

	da->size_disp = da->size_imm = 0;
	da->size_rm = da->size_ro = 32;
}

/* 引数hexがprefixであるかどうかを判定する関数 */
void Check_pref(t_disasm *da, unsigned char hex){
	da->flag_pref = 1;
	da->size_opc = -1;
	switch (hex)
	{
	//group1
	case 0xf0:
	case 0xf2:
	case 0xf3:
		da->pref[1] = hex;
		break;
	//group2
	case 0x2e:
	case 0x36:
	case 0x3e:
	case 0x26:
	case 0x64:
	case 0x65:
		da->pref[2] = hex;
		break;
	//group3
	case 0x66:
		da->pref[3] = hex;
		break;
	//group4
	case 0x67:
		da->pref[4] = hex;
		break;
	//Not Prefix
	default:
		da->flag_pref = 0;
		da->ptr_opc = 0;
		da->size_opc = 1;
		break;
	}

	sprintf(da->asm, "%02X", hex);
	switch (hex)
	{
	//group1
	case 0xf0:
		strcpy(da->asm, "LOCK");
		break;
	case 0xf2:
		break;
	case 0xf3:
		strcpy(da->asm, "REP");
		break;
	//group2
	case 0x2e:
	case 0x36:
	case 0x3e:
	case 0x26:
	case 0x64:
	case 0x65:
		break;
	//group3
	case 0x66:
		break;
	//group4
	case 0x67:
		break;
	}
}

/* 引数hex（オペコード）を判定し、逆アセンブルに必要な情報を設定する関数 */
void Set_opc(t_disasm *da, unsigned char hex){
	da->opc[da->ptr_opc] = hex;

	if (da->size_opc == 1){		//1 byte opcode
		switch (hex)
		{
		case 0x03:
			strcpy(da->asm, "ADD");
			da->flag_modrm = 1;
			da->arg[0] = RO;
			da->arg[1] = RM;
			break;
		case 0x05:
			strcpy(da->asm, "ADD");
			da->reg_no = 0;
			da->size_imm = 32;
			da->arg[0] = REG;
			da->arg[1] = IMM;
			break;
		case 0x0b:
			strcpy(da->asm, "OR");
			da->flag_modrm = 1;
			da->arg[0] = RO;
			da->arg[1] = RM;
			break;
		case 0x0d:
			strcpy(da->asm, "OR");
			da->reg_no = 0;
			da->size_imm = 32;
			da->arg[0] = REG;
			da->arg[1] = IMM;
			break;
		case 0x0f:
			da->size_opc = 2;
			break;
		case 0x1b:
			strcpy(da->asm, "SBB");
			da->flag_modrm = 1;
			da->arg[0] = RO;
			da->arg[1] = RM;
			break;
		case 0x25:
			strcpy(da->asm, "AND");
			da->reg_no = 0;
			da->size_imm = 32;
			da->arg[0] = REG;
			da->arg[1] = IMM;
			break;
		case 0x2b:
			strcpy(da->asm, "SUB");
			da->flag_modrm = 1;
			da->arg[0] = RO;
			da->arg[1] = RM;
			break;
		case 0x2d:
			strcpy(da->asm, "SUB");
			da->reg_no = 0;
			da->size_imm = 32;
			da->arg[0] = REG;
			da->arg[1] = IMM;
			break;
		case 0x31:
			strcpy(da->asm, "XOR");
			da->flag_modrm = 1;
			da->arg[0] = RM;
			da->arg[1] = RO;
			break;
		case 0x33:
			strcpy(da->asm, "XOR");
			da->flag_modrm = 1;
			da->arg[0] = RO;
			da->arg[1] = RM;
			break;
		case 0x39:
			strcpy(da->asm, "CMP");
			da->flag_modrm = 1;
			da->arg[0] = RM;
			da->arg[1] = RO;
			break;
		case 0x3b:
			strcpy(da->asm, "CMP");
			da->flag_modrm = 1;
			da->arg[0] = RO;
			da->arg[1] = RM;
			break;
		case 0x3d:
			strcpy(da->asm, "CMP");
			da->reg_no = 0;
			da->size_imm = 32;
			da->arg[0] = REG;
			da->arg[1] = IMM;
			break;
		case 0x40:
		case 0x41:
		case 0x42:
		case 0x43:
		case 0x44:
		case 0x45:
		case 0x46:
		case 0x47:
			strcpy(da->asm, "INC");
			da->reg_no = hex - 0x40;
			da->arg[0] = REG;
			break;
		case 0x48:
		case 0x49:
		case 0x4a:
		case 0x4b:
		case 0x4c:
		case 0x4d:
		case 0x4e:
		case 0x4f:
			strcpy(da->asm, "DEC");
			da->reg_no = hex - 0x48;
			da->arg[0] = REG;
			break;
		case 0x50:
		case 0x51:
		case 0x52:
		case 0x53:
		case 0x54:
		case 0x55:
		case 0x56:
		case 0x57:
			strcpy(da->asm, "PUSH");
			da->reg_no = hex - 0x50;
			da->arg[0] = REG;
			break;
		case 0x58:
		case 0x59:
		case 0x5a:
		case 0x5b:
		case 0x5c:
		case 0x5d:
		case 0x5e:
		case 0x5f:
			strcpy(da->asm, "POP");
			da->reg_no = hex - 0x58;
			da->arg[0] = REG;
			break;
		case 0x68:
			strcpy(da->asm, "PUSH");
			da->size_imm = 32;
			da->arg[0] = IMM;
			break;
		case 0x69:
			strcpy(da->asm, "IMUL");
			da->flag_modrm = 1;
			da->size_imm = 32;
			da->arg[0] = RO;
			da->arg[1] = RM;
			da->arg[2] = IMM;
			break;
		case 0x6a:
			strcpy(da->asm, "PUSH");
			da->size_imm = 8;
			da->arg[0] = IMM;
			break;
		case 0x6b:
			strcpy(da->asm, "IMUL");
			da->flag_modrm = 1;
			da->size_imm = 8;
			da->arg[0] = RO;
			da->arg[1] = RM;
			da->arg[2] = IMM;
			break;
		case 0x72:
			strcpy(da->asm, "JB");
			da->size_imm = 8;
			da->arg[0] = REL;
			break;
		case 0x73:
			strcpy(da->asm, "JNB");
			da->size_imm = 8;
			da->arg[0] = REL;
			break;
		case 0x74:
			strcpy(da->asm, "JE");
			da->size_imm = 8;
			da->arg[0] = REL;
			break;
		case 0x75:
			strcpy(da->asm, "JNZ");
			da->size_imm = 8;
			da->arg[0] = REL;
			break;
		case 0x76:
			strcpy(da->asm, "JBE");
			da->size_imm = 8;
			da->arg[0] = REL;
			break;
		case 0x77:
			strcpy(da->asm, "JA");
			da->size_imm = 8;
			da->arg[0] = REL;
			break;
		case 0x79:
			strcpy(da->asm, "JNS");
			da->size_imm = 8;
			da->arg[0] = REL;
			break;
		case 0x7c:
			strcpy(da->asm, "JL");
			da->size_imm = 8;
			da->arg[0] = REL;
			break;
		case 0x7e:
			strcpy(da->asm, "JLE");
			da->size_imm = 8;
			da->arg[0] = REL;
			break;
		case 0x7f:
			strcpy(da->asm, "JG");
			da->size_imm = 8;
			da->arg[0] = REL;
			break;
		case 0x81:
			da->flag_modrm = 1;
			da->size_imm = 32;
			da->arg[0] = RM;
			da->arg[1] = IMM;
			break;
		case 0x82:
			da->flag_modrm = 1;
			da->size_imm = 8;
			da->arg[0] = RM;
			da->arg[1] = IMM;
			break;
		case 0x83:
			da->flag_modrm = 1;
			da->size_imm = 8;
			da->arg[0] = RM;
			da->arg[1] = IMM;
			break;
		case 0x85:
			strcpy(da->asm, "TEST");
			da->flag_modrm = 1;
			da->arg[0] = RM;
			da->arg[1] = RO;
			break;
		case 0x89:
			strcpy(da->asm, "MOV");
			da->flag_modrm = 1;
			da->arg[0] = RM;
			da->arg[1] = RO;
			break;
		case 0x8b:
			strcpy(da->asm, "MOV");
			da->flag_modrm = 1;
			da->arg[0] = RO;
			da->arg[1] = RM;
			break;
		case 0x8c:
			strcpy(da->asm, "MOV");
			da->flag_modrm = 1;
			da->size_ro = SREG;
			da->arg[0] = RM;
			da->arg[1] = RO;
			break;
		case 0x8d:
			strcpy(da->asm, "LEA");
			da->flag_modrm = 1;
			da->arg[0] = RO;
			da->arg[1] = RM;
			break;
		case 0x8f:
			strcpy(da->asm, "POP");
			da->flag_modrm = 1;
			da->arg[0] = RM;
			break;
		case 0x90:
			strcpy(da->asm, "NOP");
			break;
		case 0x9c:
			strcpy(da->asm, "PUSHFD");
			break;
		case 0xa1:
			strcpy(da->asm, "MOV");
			da->reg_no = 0;
			da->size_imm = 32;
			da->arg[0] = REG;
			da->arg[1] = MOFFS;
			break;
		case 0xa3:
			strcpy(da->asm, "MOV");
			da->reg_no = 0;
			da->size_imm = 32;
			da->arg[0] = MOFFS;
			da->arg[1] = REG;
			break;
		case 0xb8:
		case 0xb9:
		case 0xba:
		case 0xbb:
		case 0xbc:
		case 0xbd:
		case 0xbe:
		case 0xbf:
			strcpy(da->asm, "MOV");
			da->reg_no = hex - 0xb8;
			da->size_imm = 32;
			da->arg[0] = REG;
			da->arg[1] = IMM;
			break;
		case 0xc1:
			da->flag_modrm = 1;
			da->size_imm = 8;
			da->arg[0] = RM;
			da->arg[1] = IMM;
			break;
		case 0xc2:
			strcpy(da->asm, "RETN");
			da->size_imm = 16;
			da->arg[0] = IMM;
			break;
		case 0xc3:
			strcpy(da->asm, "RETN");
			break;
		case 0xc7:
			strcpy(da->asm, "MOV");
			da->flag_modrm = 1;
			da->size_imm = 32;
			da->arg[0] = RM;
			da->arg[1] = IMM;
			break;
		case 0xc9:
			strcpy(da->asm, "LEAVE");
			break;
		case 0xcc:
			strcpy(da->asm, "INT3");
			break;
		case 0xd1:
			da->flag_modrm = 1;
			da->def = 1;
			da->arg[0] = RM;
			da->arg[1] = DEF;
			break;
		case 0xe8:
			strcpy(da->asm, "CALL");
			da->size_imm = 32;
			da->arg[0] = REL;
			break;
		case 0xe9:
			strcpy(da->asm, "JMP");
			da->size_imm = 32;
			da->arg[0] = REL;
			break;
		case 0xeb:
			strcpy(da->asm, "JMP");
			da->size_imm = 8;
			da->arg[0] = REL;
			break;
		case 0xf6:
			da->flag_modrm = 1;
			break;
		case 0xf7:
			da->flag_modrm = 1;
			break;
		case 0xff:
			da->flag_modrm = 1;
			da->arg[0] = RM;
			break;
		default:
			strcpy(da->asm, "??");
			break;
		}
	}
	else if (da->size_opc == 2 && da->opc[0] == 0x0f){		//2 byte opcode
		switch (hex)
		{
		case 0x83:
			strcpy(da->asm, "JAE");
			da->size_imm = 32;
			da->arg[0] = REL;
			break;
		case 0x84:
			strcpy(da->asm, "JE");
			da->size_imm = 32;
			da->arg[0] = REL;
			break;
		case 0x85:
			strcpy(da->asm, "JNE");
			da->size_imm = 32;
			da->arg[0] = REL;
			break;
		case 0x86:
			strcpy(da->asm, "JBE");
			da->size_imm = 32;
			da->arg[0] = REL;
			break;
		case 0x8c:
			strcpy(da->asm, "JL");
			da->size_imm = 32;
			da->arg[0] = REL;
			break;
		case 0x8e:
			strcpy(da->asm, "JLE");
			da->size_imm = 32;
			da->arg[0] = REL;
			break;
		case 0x8f:
			strcpy(da->asm, "JG");
			da->size_imm = 32;
			da->arg[0] = REL;
			break;
		case 0x94:
			strcpy(da->asm, "SETE");
			da->flag_modrm = 1;
			da->size_rm = 8;
			da->arg[0] = RM;
			break;
		case 0x95:
			strcpy(da->asm, "SETNE");
			da->flag_modrm = 1;
			da->size_rm = 8;
			da->arg[0] = RM;
			break;
		case 0xb7:
			strcpy(da->asm, "MOVZX");
			da->flag_modrm = 1;
			da->arg[0] = RO;
			da->arg[1] = RM;
			break;
		default:
			strcpy(da->asm, "??");
			break;
		}
	}
}

/* 引数hexをModR/Mとして設定する関数 */
void Set_modrm(t_disasm *da, unsigned char hex){
	da->modrm.mod = hex >> 6;
	da->modrm.ro = (hex >> 3) & 7;
	da->modrm.rm = hex & 7;

	if (da->modrm.rm == 4 && da->modrm.mod != 3){
		da->flag_sib = 1;
	}

	switch (da->modrm.mod)
	{
	case 0:
		if (da->modrm.rm == 5) da->size_disp = 32;
		break;
	case 1:
		da->size_disp = 8;
		break;
	case 2:
		da->size_disp = 32;
		break;
	}

	char ro_0x81[8][10] = { "ADD", "OR", "ADC", "SBB", "AND", "SUB", "XOR", "CMP" };
	char ro_0xc1[8][10] = { "ROL", "ROR", "RCL", "RCR", "SHL", "SHR", "SAL", "SAR" };
	char ro_0xf6[8][10] = { "TEST", "TEST", "NOT", "NEG", "MUL", "IMUL", "DIV", "IDIV" };
	char ro_0xff[8][10] = { "INC", "DEC", "CALL", "CALLF", "JMP", "JMPF", "PUSH", "??" };
	switch (da->opc[0])
	{
	case 0x81:
	case 0x82:
	case 0x83:
		strcpy(da->asm, ro_0x81[da->modrm.ro]);
		break;
	case 0xc1:
	case 0xd1:
		strcpy(da->asm, ro_0xc1[da->modrm.ro]);
		break;
	case 0xf6:
		strcpy(da->asm, ro_0xf6[da->modrm.ro]);
		switch (da->modrm.ro)
		{
		case 0:
			da->size_imm = 8;
			da->arg[0] = RM;
			da->arg[1] = IMM;
			break;
		default:
			break;
		}
		break;
	case 0xf7:
		strcpy(da->asm, ro_0xf6[da->modrm.ro]);
		switch (da->modrm.ro)
		{
		case 2:
		case 3:
			da->arg[0] = RM;
			break;
		default:
			break;
		}
		break;
	case 0xff:
		strcpy(da->asm, ro_0xff[da->modrm.ro]);
		break;
	}
}

/* 引数hexをSIBとして設定する関数 */
void Set_sib(t_disasm *da, unsigned char hex){
	da->sib.scale = hex >> 6;
	da->sib.index = (hex >> 3) & 7;
	da->sib.base = hex & 7;
}
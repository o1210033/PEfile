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
}

/* 引数hex（オペコード）を判定し、逆アセンブルに必要な情報を設定する関数 */
void Set_opc(t_disasm *da, unsigned char hex){
	int i;
	int size[3] = { 8, 16, 32 };

	da->opc[da->ptr_opc] = hex;

	if (da->size_opc == 1){		//1 byte opcode
		if (hex == 0x0f){
			da->size_opc = 2;
		}
		else{
			Set_opc1(da);
		}
	}
	else if (da->size_opc == 2 && da->opc[0] == 0x0f){		//2 byte opcode
		Set_opc2(da);
	}

	for (i = 0; i < 3; i++){
		if (!da->arg[i]){ break; }
		switch (da->arg[i])
		{
		case IMM8:
		case IMM16:
		case IMM32:
			da->size_imm = size[da->arg[i] - IMM8];
			break;
		case R32:
			da->modrm.ro = hex % 8;
			break;
		case RM8:
		case RM16:
		case RM32:
			da->flag_modrm = 1;
			break;
		case REL8:
		case REL16:
		case REL32:
			da->size_imm = size[da->arg[i] - REL8];
			break;
		case MOFFS8:
		case MOFFS16:
		case MOFFS32:
			da->size_imm = size[da->arg[i] - MOFFS8];
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
			da->arg[0] = RM8; da->arg[1] = IMM8;
			da->size_imm = 8;
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
			da->arg[0] = RM32;
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
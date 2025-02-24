/* disasm.c */
/* 逆アセンブル処理 */



#include <stdio.h>
#include <string.h>

#include "disasm.h"



/* 
引数FILE *bfpの現在位置から1命令文読み込み、
引数da構造体に適切な値をセット
*/
int Disasm(FILE *bfp, t_disasm *da){
	int i;
	unsigned char hex;


	//prefixの有無を確認＆解析
	fread(&hex, 1, 1, bfp);
	da->offs = 1;
	da->ptr_pref = 0;
	Check_pref(da, hex);
	while (da->flag_pref){
		fread(&hex, 1, 1, bfp);
		da->offs++;
		Check_pref(da, hex);
	}

	//opcodeの解析
	da->size_opc = 1;
	da->ptr_opc = 0;
	Set_opc(da, hex);
	while (da->ptr_opc < da->size_opc){
		fread(&hex, 1, 1, bfp);
		da->offs++;
		Set_opc(da, hex);
	}

	if (da->flag_modrm){		//ModR/M アリ
		fread(&hex, 1, 1, bfp);
		da->offs++;
		Set_modrm(da, hex);
	}

	if (da->flag_sib){		//SIB アリ
		fread(&hex, 1, 1, bfp);
		da->offs++;
		Set_sib(da, hex);
	}

	switch (da->size_disp)	//ディスプレースメント アリ
	{
	case 8:
		fread(&da->disp8, 1, 1, bfp);
		da->offs++;
		break;
	case 32:
		fread(&da->disp32, 1, 4, bfp);
		da->offs += 4;
		break;
	}

	switch (da->size_imm)	//即値 アリ
	{
	case 8:
		fread(&da->imm8, 1, 1, bfp);
		da->offs++;
		break;
	case 16:
		fread(&da->imm16, 1, 2, bfp);
		da->offs += 2;
		break;
	case 32:
		fread(&da->imm32, 1, 4, bfp);
		da->offs += 4;
		break;
	}

	return 0;
}


/* 引数hexがprefixであるかどうかを判定する関数 */
void Check_pref(t_disasm *da, unsigned char hex){
	da->flag_pref = 1;
	switch (hex)
	{
	case 0xf0:
	case 0xf2:
	case 0xf3:
	case 0x2e:
	case 0x36:
	case 0x3e:
	case 0x26:
	case 0x64:
	case 0x65:
	case 0x66:
	case 0x67:
		da->pref[da->ptr_pref++] = hex;
		if (da->ptr_pref == 4){ da->flag_pref = 0; }
		break;
	//Not Prefix
	default:
		da->flag_pref = 0;
		break;
	}
}


/*
引数hex（オペコード）を判定し、逆アセンブルに必要な情報を設定する関数 
オペコードフィールド終了時は0を、そうでない場合は-1を返す
*/
int Set_opc(t_disasm *da, unsigned char hex){
	int i;
	int size[3] = { 8, 16, 32 };

	da->opc[da->ptr_opc++] = hex;

	if (da->size_opc == 1){		//1 byte opcode
		if (hex == 0x0f){
			da->size_opc = 2;
			return -1;
		}
		else{
			Set_opc1(da);
		}
	}
	else if (da->size_opc == 2 && da->opc[0] == 0x0f){		//2 byte opcode
		Set_opc2(da);
	}

	//opcodeに適した値を各変数にセット
	da->flag_modrm = da->flag_sib = 0;
	da->size_disp = da->size_imm = 0;
	for (i = 0; i < 3; i++){
		if (!da->operand[i]){ break; }
		switch (da->operand[i])
		{
		case IMM8:
		case IMM16:
		case IMM32:
			da->size_imm = size[da->operand[i] - IMM8];
			break;
		case R8:
		case R16:
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
			da->size_imm = size[da->operand[i] - REL8];
			break;
		case MOFFS8:
		case MOFFS16:
		case MOFFS32:
			da->size_disp = size[da->operand[i] - MOFFS8];
			break;
		}
	}

	return 0;
}


/* 引数hexをModR/Mとして設定する関数 */
void Set_modrm(t_disasm *da, unsigned char hex){
	da->modrm.mod = hex >> 6;
	da->modrm.ro = (hex >> 3) & 7;
	da->modrm.rm = hex & 7;
	da->modrm.hex = hex;   //ファイル出力用

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

	char ro_0x80[8][10] = { "ADD", "OR", "ADC", "SBB", "AND", "SUB", "XOR", "CMP" };
	char ro_0xc1[8][10] = { "ROL", "ROR", "RCL", "RCR", "SHL", "SHR", "SAL", "SAR" };
	char ro_0xf6[8][10] = { "TEST", "TEST", "NOT", "NEG", "MUL", "IMUL", "DIV", "IDIV" };
	char ro_0xff[8][10] = { "INC", "DEC", "CALL", "CALLF", "JMP", "JMPF", "PUSH", "??" };
	switch (da->opc[0])
	{
	case 0x80:
	case 0x81:
	case 0x82:
	case 0x83:
		strcpy(da->instruction, ro_0x80[da->modrm.ro]);
		break;
	case 0xc1:
	case 0xd1:
		strcpy(da->instruction, ro_0xc1[da->modrm.ro]);
		break;
	case 0xf6:
		strcpy(da->instruction, ro_0xf6[da->modrm.ro]);
		switch (da->modrm.ro)
		{
		case 0:
			da->operand[0] = RM8; da->operand[1] = IMM8;
			da->size_imm = 8;
			break;
		default:
			break;
		}
		break;
	case 0xf7:
		strcpy(da->instruction, ro_0xf6[da->modrm.ro]);
		switch (da->modrm.ro)
		{
		case 2:
		case 3:
			da->operand[0] = RM32;
			break;
		default:
			break;
		}
		break;
	case 0xff:
		strcpy(da->instruction, ro_0xff[da->modrm.ro]);
		break;
	}
}


/* 引数hexをSIBとして設定する関数 */
void Set_sib(t_disasm *da, unsigned char hex){
	da->sib.scale = hex >> 6;
	da->sib.index = (hex >> 3) & 7;
	da->sib.base = hex & 7;
	da->sib.hex = hex;   //ファイル出力用

	if (da->sib.base == 5){
		if (da->modrm.mod == 1)
			da->size_disp = 8;
		else
			da->size_disp = 32;
	}
}
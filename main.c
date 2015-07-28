#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <wchar.h>
#include <wctype.h>
#include <locale.h>
#include <windows.h>

#include "disasm.h"
#include "PEfile.h"


char *Get_filename(void);

//�t�A�Z���u�����ʏo�͊֘A�̊֐�
int Disasm_LinearSweep(FILE *bfp, t_disasm *da, t_header *th, t_idata ti[]);
void change_reg(char reg_name[8][5], char reg[8][5]);
void Set_regname(char reg_name[8][5], int size_reg);
int Print_disasm(FILE *dtfp, FILE *bfp, t_disasm *da, t_header *th, t_idata ti[]);
int Print_function(FILE *dtfp, unsigned long rva, t_idata ti[]);
int Print_string(FILE *dtfp, unsigned long rva, FILE *bfp, t_header *th);
int Set_rtable(FILE *bfp, t_disasm *da, t_header *th, t_idata ti[]);
void Free_rtable(t_disasm *da);



/* main�֐� */
int main(void){
	int i;

	FILE *bfp;
	t_disasm da;
	t_header th;
	t_idata ti[30];
	char szFile[300], fname[300];

	/* �K�v�ȃt�@�C�������擾�A�ݒ� */
	//strcpy(szFile, Get_filename(szFile));
	strcpy(szFile, "wsample01a.exe");
	//strcpy(szFile, "HelloWorld(MBCS).exe");
	//strcpy(szFile, "HelloWorld(Unicode).exe");
	//strcpy(szFile, "ls.exe");
	//strcpy(szFile, "memo(32bit).exe");
	//strcpy(szFile, "calculator(32bit).exe");
	strcpy(fname, szFile);
	for (i = 0; i < 300; i++){
		if (szFile[i] == '.')
			szFile[i] = '\0';
	}
	sprintf(da.dtname, "%s_Disasm.txt", szFile);
	sprintf(th.htname, "%s_Header.txt", szFile);
	sprintf(th.itname, "%s_Imports.txt", szFile);


	/* PE�t�@�C���̃I�[�v������ */
	if ((bfp = fopen(fname, "rb")) == NULL){
		printf("\a�t�@�C�����I�[�v���ł��܂���B\n");
		exit(1);
	}

	/* �w�b�_�����擾���t�@�C���o�� */
	if (Read_header(bfp, &th) != 0){
		printf("ERROR: Read_header\n");
		fclose(bfp);
		exit(1);
	}

	/* �C���|�[�g�����擾���t�@�C���o�� */
	if (Read_idata(bfp, &th, ti) != 0){
		printf("ERROR: Read_idata\n");
	}

	/* reference�i�V�̋t�A�Z���u�����ʂ��t�@�C���o�� */
	da.flag_print = 1;
	da.flag_ref = 0;
	if (Disasm_LinearSweep(bfp, &da, &th, ti) != 0){
		printf("ERROR: Disasm_LinearSweep\n");
		fclose(bfp);
		exit(1);
	}

	/* jump, call���߂�reference table��ݒ� */
	if (Set_rtable(bfp, &da, &th, ti) != 0){
		printf("ERROR: Set_rtable\n");
		fclose(bfp);
		exit(1);
	}

	/* reference�A���̋t�A�Z���u�����ʂ��t�@�C���o�� */
	da.flag_print = 1;
	da.flag_ref = PRINT;
	sprintf(da.dtname, "%s_RefDisasm.txt", szFile);
	if (Disasm_LinearSweep(bfp, &da, &th, ti) != 0){
		printf("ERROR: Disasm_LinearSweep\n");
		Free_rtable(&da);
		fclose(bfp);
		exit(1);
	}

	/* rtable�\���̓��̓��I�m�ۂ�������������� */
	Free_rtable(&da);

	/* PE�t�@�C���̃N���[�Y���� */
	fclose(bfp);

	return 0;
}


/* �I�[�v���t�@�C���_�C�A���O��p���ē����t�@�C������Ԃ��֐� */
char *Get_filename(void){
	int i;
	OPENFILENAME ofn;
	char szFile[250];

	szFile[0] = '\0';
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.lpstrFilter = "all file(*.*)\0*.*\0\0";
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = sizeof(szFile);
	ofn.Flags = OFN_FILEMUSTEXIST;

	GetOpenFileName(&ofn);

	return szFile;
}


/* .text�Z�N�V�����̓ǂݍ��݁��t�A�Z���u���������t�@�C���o�͊֐� */
int Disasm_LinearSweep(FILE *bfp, t_disasm *da, t_header *th, t_idata ti[]){
	int i, j;
	FILE *dtfp;
	unsigned char hex;
	unsigned long rva;
	unsigned long AddressOfCode = th->ImageBase + th->ts[th->ptr_text].VirtualAddress;
	unsigned long EndAddressOfCode = th->ImageBase + th->ts[th->ptr_text].VirtualAddress + th->ts[th->ptr_text].SizeOfRawData;


	/* �t�A�Z���u�����ʏo�̓t�@�C���̃I�[�v������ */
	if (da->flag_print){
		if ((dtfp = fopen(da->dtname, "w")) == NULL){
			printf("\a�t�@�C�����I�[�v���ł��܂���B\n");
			return 1;
		}
	}
	
	/* da�\���̂�addr_code, offs�̏����� */
	da->addr_code = AddressOfCode;
	da->offs = 0;

	/* .text�Z�N�V�����̓ǂݍ��݁��t�A�Z���u���������t�@�C���o�� */
	fseek(bfp, th->ts[th->ptr_text].PointerToRawData, SEEK_SET);   //.text�Z�N�V�����̐擪�փV�[�N
	while (da->addr_code < EndAddressOfCode){   //.text�Z�N�V�����̍Ō�܂œǂݍ���
		//�l�C�e�B�u�R�[�h�ȊO�̃f�[�^(IMAGE_DATA_DIRECTORY)�����͋t�A�Z���u�����Ȃ�
		for (i = 0; i < 16; i++){ da->flag_IDD[i] = 0; }
		while (1){
			rva = da->addr_code - th->ImageBase;
			for (i = 0; i < 16; i++){
				if (th->IDD[i].RVA <= rva && rva < th->IDD[i].RVA + th->IDD[i].Size){
					da->addr_code += th->IDD[i].Size - (rva - th->IDD[i].RVA);
					fseek(bfp, th->ts[th->ptr_text].PointerToRawData + (da->addr_code - AddressOfCode), SEEK_SET);
					da->flag_IDD[i] = 1;   //�t�@�C���o�͗p�̃t���O�Z�b�g
					break;
				}
			}
			if (i == 16){ break; }
		}

		//�t�A�Z���u������
		if (Disasm(bfp, da) != 0){ return 1; }

		//�t�A�Z���u�����ʂ��t�@�C���o��
		if (da->flag_print){
			Print_disasm(dtfp, bfp, da, th, ti);
		}

		//jump, call���߂�reference table �ݒ�p
		if (da->flag_ref){
			if ((da->instruction[0] == 'J' && strcmp(da->instruction, "JMPF") != 0) || strcmp(da->instruction, "CALL") == 0){
				if (da->flag_ref == COUNT){   //jump, call���߂̑������J�E���g
					da->rtable.num++;
				}
				if (da->flag_ref == SET){   //rtable�\���̂ɓK�؂Ȓl���Z�b�g
					da->rtable.src[da->rtable.ptr] = da->addr_code;
					if (da->operand[0] == REL8){
						da->rtable.dst[da->rtable.ptr] = da->addr_code + da->offs + (char)da->imm8;
					}
					else if (da->operand[0] == REL32){
						da->rtable.dst[da->rtable.ptr] = da->addr_code + da->offs + (long)da->imm32;
					}
					if (strcmp(da->instruction, "JMP") == 0){
						da->rtable.flag[da->rtable.ptr] = UJMP;
					}
					else if (da->instruction[0] == 'J'){
						da->rtable.flag[da->rtable.ptr] = CJMP;
					}
					else if (strcmp(da->instruction, "CALL") == 0){
						da->rtable.flag[da->rtable.ptr] = CALL;
					}
					da->rtable.ptr++;
				}
			}
		}
	
		//Address�̍X�V
		da->addr_code += da->offs;
		da->offs = 0;
	}

	if (da->flag_print){ fclose(dtfp); }
	return 0;
}

/* Set_regname�֐��ɗp����֐� */
void change_reg(char reg_name[8][5], char reg[8][5]){
	int i;
	for (i = 0; i < 8; i++){
		strcpy(reg_name[i], reg[i]);
	}
}

/* ����reg_name[8][5]�Ƀ��W�X�^�����i�[����֐� */
void Set_regname(char reg_name[8][5], int size_reg){
	int i;
	char reg8[8][5] = {
		"AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"
	};
	char reg16[8][5] = {
		"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"
	};
	char reg32[8][5] = {
		"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"
	};
	char sreg[8][5] = {
		"ES", "CS", "SS", "DS", "FS", "GS", "res.", "res."
	};

	switch (size_reg)
	{
	case R8:
	case RM8:
		change_reg(reg_name, reg8);
		break;
	case R16:
	case RM16:
		change_reg(reg_name, reg16);
		break;
	case R32:
	case RM32:
		change_reg(reg_name, reg32);
		break;
	case SREG:
		change_reg(reg_name, sreg);
		break;
	default:
		break;
	}
}

/* �t�A�Z���u�����ʂ��t�@�C���o�� */
int Print_disasm(FILE *dtfp, FILE *bfp, t_disasm *da, t_header *th, t_idata ti[]){
	int i, j;
	int size_code;
	int scale[4] = { 1, 2, 4, 8 };
	char data[50], reg_name[8][5];
	unsigned long ptr, rva;
	union{
		unsigned short b2;
		unsigned char b1[2];
	}bit16;
	union{
		unsigned long b4;
		unsigned char b1[4];
	}bit32;

	//�l�C�e�B�u�R�[�h�ȊO�̃f�[�^(IMAGE_DATA_DIRECTORY)����
	for (i = 0; i < 16; i++){
		if (da->flag_IDD[i]){
			fprintf(dtfp, "\n* %s (%08X - %08X)\n\n", th->IDD[i].Name, th->ImageBase + th->IDD[i].RVA, th->ImageBase + th->IDD[i].RVA + th->IDD[i].Size - 1);
		}
	}

	//�K�v�ɉ����� Reference of JUMP or CALL ���o��
	if (da->flag_ref == PRINT){   //reference�o�̓t���O
		for (ptr = 0; ptr < da->rtable.num; ptr++){
			if (da->addr_code == da->rtable.dst[ptr]){
				fprintf(dtfp, "\n* Referenced by (U)nconditional or (C)onditional Jump or (c)all at Address:\n");
				fprintf(dtfp, "| %08X", da->rtable.src[ptr]);
				if (da->rtable.flag[ptr] == UJMP){ fprintf(dtfp, "(U)"); }
				if (da->rtable.flag[ptr] == CJMP){ fprintf(dtfp, "(C)"); }
				if (da->rtable.flag[ptr] == CALL){ fprintf(dtfp, "(c)"); }
				for (ptr++; ptr < da->rtable.num; ptr++){
					if (da->addr_code == da->rtable.dst[ptr]){
						fprintf(dtfp, ", %08X", da->rtable.src[ptr]);
						if (da->rtable.flag[ptr] == UJMP){ fprintf(dtfp, "(U)"); }
						if (da->rtable.flag[ptr] == CJMP){ fprintf(dtfp, "(C)"); }
						if (da->rtable.flag[ptr] == CALL){ fprintf(dtfp, "(c)"); }
					}
				}
				fprintf(dtfp, "\n|\n");
			}
		}
	}

	//�������A�h���X���o��
	fprintf(dtfp, "%08X|   ", da->addr_code);

	//prefix���o��
	for (i = 0; i < da->ptr_pref; i++){
		fprintf(dtfp, "%02X:", da->pref[i]);
		for (j = 3; j < 30; j++){	//�󔒕����̒���
			fputc(' ', dtfp);
		}
		fprintf(dtfp, "| PREFIX %02X:\n", da->pref[i]);
		fprintf(dtfp, "%08X|   ", da->addr_code + (i + 1));
	}

	//�l�C�e�B�u�R�[�h�o��
	size_code = 0;
	for (i = 0; i < da->size_opc; i++){
		fprintf(dtfp, "%02X ", da->opc[i]);
		size_code += 3;
	}

	if (da->flag_modrm){   //ModR/M �A��
		fprintf(dtfp, "%02X ", da->modrm.hex);
		size_code += 3;
	}

	if (da->flag_sib){   //SIB �A��
		fprintf(dtfp, "%02X ", da->sib.hex);
		size_code += 3;
	}

	switch (da->size_disp)	//�f�B�X�v���[�X�����g �A��
	{
	case 8:
		fprintf(dtfp, "%02X ", da->disp8);
		size_code += 3;
		break;
	case 32:
		bit32.b4 = da->disp32;
		for (i = 0; i < 4; i++){
			fprintf(dtfp, "%02X", bit32.b1[i]);
			size_code += 2;
		}
		fputc(' ', dtfp);
		size_code++;
		break;
	}

	switch (da->size_imm)	//���l �A��
	{
	case 8:
		fprintf(dtfp, "%02X ", da->imm8);
		size_code += 3;
		break;
	case 16:
		bit16.b2 = da->imm16;
		for (i = 0; i < 2; i++){
			fprintf(dtfp, "%02X", bit16.b1[i]);
			size_code += 2;
		}
		fputc(' ', dtfp);
		size_code++;
		break;
	case 32:
		bit32.b4 = da->imm32;
		for (i = 0; i < 4; i++){
			fprintf(dtfp, "%02X", bit32.b1[i]);
			size_code += 2;
		}
		fputc(' ', dtfp);
		size_code++;
		break;
	}

	for (; size_code < 30; size_code++){	//�󔒕����̒���
		fputc(' ', dtfp);
	}

	//x86���߂��o��
	fprintf(dtfp, "| %-10s", da->instruction);

	//x86���߂̈������o��
	strcpy(data, "\0");
	for (i = 0; i < 3; i++){
		if (!da->operand[i]){ break; }

		if (i != 0 && da->operand[i] != -1){		//�����Ԃ̋�؂���o��
			fprintf(dtfp, ", ");
		}

		Set_regname(reg_name, R32);
		switch (da->operand[i])
		{
		case IMM8:
			fprintf(dtfp, "%02Xh", da->imm8);
			break;
		case IMM16:
			fprintf(dtfp, "%04Xh", da->imm16);
			break;
		case IMM32:
			fprintf(dtfp, "%08Xh", da->imm32);
			break;
		case RM8:
		case RM16:
		case RM32:
			if (da->flag_sib){	//SIB �A��
				fprintf(dtfp, "%s", data);
				switch (da->modrm.mod)
				{
				case 0:
					if (da->sib.base == 5){
						if (da->sib.index == 4){
							fprintf(dtfp, "[%08Xh]", da->disp32);
						}
						else{
							fprintf(dtfp, "[%s*%d+%08Xh]", reg_name[da->sib.index], scale[da->sib.scale], da->disp32);
						}
					}
					else{
						if (da->sib.index == 4){
							fprintf(dtfp, "[%s]", reg_name[da->sib.base]);
						}
						else{
							fprintf(dtfp, "[%s+%s*%d]", reg_name[da->sib.base], reg_name[da->sib.index], scale[da->sib.scale]);
						}
					}
					break;
				case 1:
					if (da->sib.index == 4){
						fprintf(dtfp, "[%s+%02Xh]", reg_name[da->sib.base], da->disp8);
					}
					else{
						fprintf(dtfp, "[%s+%s*%d+%02Xh]", reg_name[da->sib.base], reg_name[da->sib.index], scale[da->sib.scale], da->disp8);
					}
					break;
				case 2:
					if (da->sib.index == 4){
						fprintf(dtfp, "[%s+%08Xh]", reg_name[da->sib.base], da->disp32);
					}
					else{
						fprintf(dtfp, "[%s+%s*%d+%08Xh]", reg_name[da->sib.base], reg_name[da->sib.index], scale[da->sib.scale], da->disp32);
					}
					break;
				}
			}
			else{	//SIB �i�V
				switch (da->modrm.mod)
				{
				case 0:
					if (da->modrm.rm == 5){
						fprintf(dtfp, "%s[%08Xh]", data, da->disp32);
					}
					else{
						fprintf(dtfp, "%s[%s]", data, reg_name[da->modrm.rm]);
					}
					break;
				case 1:
					fprintf(dtfp, "%s[%s+%02Xh]", data, reg_name[da->modrm.rm], da->disp8);
					break;
				case 2:
					fprintf(dtfp, "%s[%s+%08Xh]", data, reg_name[da->modrm.rm], da->disp32);
					break;
				case 3:
					Set_regname(reg_name, da->operand[i]);
					fprintf(dtfp, "%s", reg_name[da->modrm.rm]);
					break;
				}
			}
			break;
		case REL8:
			fprintf(dtfp, "%08Xh", da->addr_code + da->offs + (char)da->imm8);
			break;
		case REL16:
			break;
		case REL32:
			fprintf(dtfp, "%08Xh", da->addr_code + da->offs + (long)da->imm32);
			break;
		case MOFFS8:
		case MOFFS16:
			break;
		case MOFFS32:
			fprintf(dtfp, "%s[%08Xh]", data, da->disp32);
			break;
		case DEF1:
			fprintf(dtfp, "1");
			break;
		case R8:
		case R16:
		case R32:
		case SREG:
			Set_regname(reg_name, da->operand[i]);
			fprintf(dtfp, "%s", reg_name[da->modrm.ro]);
			break;
		case EAX:
			fprintf(dtfp, "EAX");
			break;
		}
	}

	//�K�v�ɉ����Ē��߂��t�@�C���o��
	if (da->flag_ref == PRINT){   //reference�o�̓t���O
		if (da->size_disp == 32){
			rva = da->disp32 - th->ImageBase;
		}
		else if (da->size_imm == 32){
			rva = da->imm32 - th->ImageBase;
		}
		if (Print_function(dtfp, rva, ti) != 0){
			Print_string(dtfp, rva, bfp, th);
		}
	}
	
	fputc('\n', dtfp);	//���s

	return 0;
}

/* RVA����DLL���ƃC���|�[�g�֐������t�@�C���o�͂���֐� */
int Print_function(FILE *dtfp, unsigned long rva, t_idata ti[]){
	int i, j;

	for (i = 0;; i++){
		if (ti[i].OriginalFirstThunk == 0){ break; }
		for (j = 0;; j++){
			if (ti[i].ILT[j] == 0 || (ti[i].ILT[j] & 0x80000000) != 0){ break; }
			else if (ti[i].IAT_rva[j] == rva){
				fprintf(dtfp, "   | %s %s", ti[i].dll, ti[i].function[j]);
				return 0;
			}
		}
	}
	return -1;
}

/* RVA���當������t�@�C���o�͂���֐� */
int Print_string(FILE *dtfp, unsigned long rva, FILE *bfp, t_header *th){
	int i;
	long offs_log, offs_string;
	char c, str[200];
	wchar_t wc, wstr[200];

	offs_log = ftell(bfp);   //�����t�@�C���ʒu���L��
	//RVA����t�@�C���ʒu���擾
	for (i = 0; i < th->NumberOfSections; i++){
		if (th->ts[i].Characteristics == 0x40000040
			&& th->ts[i].VirtualAddress <= rva && rva <= th->ts[i].VirtualAddress + th->ts[i].VirtualSize){
			offs_string = rva - th->ts[i].VirtualAddress + th->ts[i].PointerToRawData;
			break;
		}
	}
	if (i == th->NumberOfSections){ return -1; }

	//IMAGE_DATA_DIRECTORY�����͑ΏۊO�Ƃ���
	for (i = 0; i < 16; i++){
		if (th->IDD[i].RVA <= rva && rva < th->IDD[i].RVA + th->IDD[i].Size){
			return -1;
		}
	}

	//ASCII
	fseek(bfp, offs_string, SEEK_SET);
	for (i = 0; i < 100; i++){
		fread(&c, 1, 1, bfp);
		if (c < 0x20 || 0x7e < c){ break; }
		str[i] = c;
	}
	if (i >= 4 && i != 100){
		str[i] = '\0';
		fprintf(dtfp, "   | ASCII \"%s\"", str);
		fseek(bfp, offs_log, SEEK_SET);
		return 0;
	}

	//UNICODE
	fseek(bfp, offs_string, SEEK_SET);
	for (i = 0; i < 100; i++){
		fread(&wc, 1, 2, bfp);
		if (wc < 0x0020 || 0x007e < wc){ break; }
		wstr[i] = wc;
	}
	if (i >= 4 && i != 100){
		wstr[i] = L'\0';
		fwprintf(dtfp, L"   | UNICODE \"%s\"", wstr);
		fseek(bfp, offs_log, SEEK_SET);
		return 0;
	}

	fseek(bfp, offs_log, SEEK_SET);
	return -1;
}

/* jump, call���߂�reference table�ݒ�p�֐� */
int Set_rtable(FILE *bfp, t_disasm *da, t_header *th, t_idata ti[]){
	int i;

	//jump, call���߂̑������J�E���g
	da->flag_print = 0;
	da->flag_ref = COUNT;
	da->rtable.num = 0;
	if (Disasm_LinearSweep(bfp, da, th, ti) == 1){
		printf("ERROR: Disasm_LinearSweep\n");
		return 1;
	}

	//rtable�\���̓��̔z��𓮓I�m�ۂ��A�K�؂Ȓl���Z�b�g
	da->flag_ref = SET;
	da->rtable.ptr = 0;
	da->rtable.dst = (unsigned long *)malloc(sizeof(unsigned long) * da->rtable.num);
	da->rtable.src = (unsigned long *)malloc(sizeof(unsigned long) * da->rtable.num);
	da->rtable.flag = (int *)malloc(sizeof(int) * da->rtable.num);
	if (da->rtable.dst == NULL || da->rtable.src == NULL || da->rtable.flag == NULL){
		printf("ERROR: malloc rtable");
		return 1;
	}
	if (Disasm_LinearSweep(bfp, da, th, ti) == 1){
		printf("ERROR: Disasm_LinearSweep\n");
		return 1;
	}

	return 0;
}

/* rtable�\���̓��̓��I�m�ۂ������������������֐� */
void Free_rtable(t_disasm *da){
	free(da->rtable.dst);
	free(da->rtable.src);
	free(da->rtable.flag);
}
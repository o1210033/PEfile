/* main.c */
/* PE�t�@�C���̏��擾�A�t�A�Z���u���A���ʏo�� */



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


//�t�@�C���p�X���擾�p
char *Get_filename(void);

//�t�A�Z���u�����ʏo�͊֘A�̊֐�
int Disasm_LinearSweep(FILE *dtfp, FILE *bfp, t_disasm *da, t_header *th, t_idata *ti);
void change_reg(char reg_name[8][5], char reg[8][5]);
void Set_regname(char reg_name[8][5], int size_reg);
int Print_disasm(FILE *dtfp, FILE *bfp, t_disasm *da, t_header *th, t_idata *ti);
int Print_function(FILE *dtfp, unsigned long rva, FILE *bfp, t_header *th, t_idata *ti);
int Print_string(FILE *dtfp, unsigned long rva, FILE *bfp, t_header *th);
int Print_RefDisasm(FILE *dtfp, FILE *bfp, t_disasm *da, t_header *th, t_idata *ti);



/* main�֐� */
int main(void){
	int i;
	FILE *bfp, *htfp, *dtfp, *itfp;

	/* PE�t�@�C�������擾���g���q�ȑO�̃p�X����ݒ� */
	char szFile[320], fname[320], htname[320], dtname[320], itname[320];
	strcpy(szFile, Get_filename(szFile));
	strcpy(fname, szFile);
	for (i = 0; i < 300; i++){
		if (szFile[i] == '.')
			szFile[i] = '\0';
	}
	
	/* PE�t�@�C���̃I�[�v������ */
	if ((bfp = fopen(fname, "rb")) == NULL){
		printf("ERROR: fopen PEfile\n");
		exit(1);
	}

	/* �w�b�_�����擾���t�@�C���o�� */
	//�w�b�_���o�̓t�@�C�����I�[�v��
	sprintf(htname, "%s_Header.txt", szFile);
	if ((htfp = fopen(htname, "w")) == NULL){
		printf("ERROR: fopen *_Header.txt\n");
		fclose(bfp);
		exit(1);
	}
	fprintf(htfp, "[Header]\n\n");
	//�w�b�_�����擾���t�@�C���o��
	t_header th = { 0 };
	if (Read_header(htfp, bfp, &th) != 0){
		printf("ERROR: Read_header\n");
		if (th.sh != NULL){ free(th.sh); }
		fclose(bfp);
		fclose(htfp);
		exit(1);
	}
	fclose(htfp);   //�w�b�_���o�̓t�@�C�����N���[�Y

	/* reference�i�V�̋t�A�Z���u�����ʂ��t�@�C���o�� */
	// �t�A�Z���u�����ʏo�̓t�@�C�����I�[�v��
	sprintf(dtname, "%s_Disasm.txt", szFile);
	if ((dtfp = fopen(dtname, "w")) == NULL){
		printf("ERROR: fopen *_Disasm.txt\n");
		free(th.sh);
		fclose(bfp);
		exit(1);
	}
	//reference�i�V�̋t�A�Z���u�����ʂ��t�@�C���o��
	t_disasm da = { 0 };
	if (Disasm_LinearSweep(dtfp, bfp, &da, &th, NULL) != 0){
		printf("ERROR: Disasm_LinearSweep (not reference)\n");
		free(th.sh);
		fclose(bfp);
		fclose(dtfp);
		exit(1);
	}
	fclose(dtfp);   //�t�A�Z���u�����ʏo�̓t�@�C�����N���[�Y

	/* �C���|�[�g�����擾���t�@�C���o�� */
	//�C���|�[�g���o�̓t�@�C�����I�[�v��
	sprintf(itname, "%s_Imports.txt", szFile);
	if ((itfp = fopen(itname, "w")) == NULL){
		printf("ERROR: fopen *_Imports.txt\n");
		free(th.sh);
		fclose(bfp);
		exit(1);
	}
	fprintf(itfp, "[IMPORTS]\n\n");
	//�C���|�[�g�����擾���t�@�C���o��
	t_idata *ti = Get_idata(bfp, &th);
	if (ti == NULL){   //ti�\���̂̎擾�Ɏ��s�����ꍇ
		printf("ERROR: Get_idata\n");
		free(th.sh);
		fclose(itfp);
		fclose(bfp);
		exit(1);
	}
	if (Print_idata(itfp, bfp, &th, ti) != 0){
		printf("ERROR: Print_idata\n");
		free(th.sh);
		free(ti);
		fclose(itfp);
		fclose(bfp);
		exit(1);
	}
	fclose(itfp);   //�C���|�[�g���o�̓t�@�C�����N���[�Y

	/* reference�A���̋t�A�Z���u�����ʂ��t�@�C���o�� */
	// �t�A�Z���u�����ʏo�̓t�@�C�����I�[�v��
	sprintf(dtname, "%s_RefDisasm.txt", szFile);
	if ((dtfp = fopen(dtname, "w")) == NULL){
		printf("ERROR: fopen *_RefDisasm.txt\n");
		free(th.sh);
		free(ti);
		fclose(bfp);
		exit(1);
	}
	//reference�A���̋t�A�Z���u�����ʂ��t�@�C���o��
	if (Print_RefDisasm(dtfp, bfp, &da, &th, ti) != 0){
		printf("ERROR: Print RefDisasm\n");
		free(th.sh);
		free(ti);
		fclose(bfp);
		fclose(dtfp);
		exit(1);
	}
	fclose(dtfp);   //�t�A�Z���u�����ʏo�̓t�@�C�����N���[�Y

	/* ���I�m�ۂ��������������PE�t�@�C���̃N���[�Y���� */
	free(th.sh);
	free(ti);
	fclose(bfp);

	return 0;
}


/* �I�[�v���t�@�C���_�C�A���O��p���ē����t�@�C������Ԃ��֐� */
char *Get_filename(void){
	char szFile[300] = {0};
	OPENFILENAME ofn = {0};

	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.lpstrFilter = "all file(*.*)\0*.*\0\0";
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = sizeof(szFile);
	ofn.Flags = OFN_FILEMUSTEXIST;

	if (GetOpenFileName(&ofn) == 0){
		printf("ERROR: GetOpenFileName\n");
		exit(1);
	}

	return szFile;
}


/* .text�Z�N�V�����̓ǂݍ��݁��t�A�Z���u���������t�@�C���o�͊֐� */
int Disasm_LinearSweep(FILE *dtfp, FILE *bfp, t_disasm *da, t_header *th, t_idata *ti){
	int i, j;
	unsigned char hex;
	unsigned long rva;
	unsigned long AddressOfCode = th->ImageBase + th->sh[th->ptr_text].VirtualAddress;
	unsigned long EndAddressOfCode = th->ImageBase + th->sh[th->ptr_text].VirtualAddress + th->sh[th->ptr_text].SizeOfRawData;

	
	/* da�\���̂�addr_code, offs�̏����� */
	da->addr_code = AddressOfCode;
	da->offs = 0;

	/* .text�Z�N�V�����̓ǂݍ��݁��t�A�Z���u���������t�@�C���o�� */
	fseek(bfp, th->sh[th->ptr_text].PointerToRawData, SEEK_SET);   //.text�Z�N�V�����̐擪�փV�[�N
	while (da->addr_code < EndAddressOfCode){   //.text�Z�N�V�����̍Ō�܂œǂݍ���
		//�l�C�e�B�u�R�[�h�ȊO�̃f�[�^(IMAGE_DATA_DIRECTORY)�����͋t�A�Z���u�����Ȃ�
		for (i = 0; i < 16; i++){ da->flag_IDD[i] = 0; }
		while (1){
			rva = da->addr_code - th->ImageBase;
			for (i = 0; i < 16; i++){
				if (th->IDD[i].RVA <= rva && rva < th->IDD[i].RVA + th->IDD[i].Size){
					da->addr_code += th->IDD[i].Size - (rva - th->IDD[i].RVA);
					fseek(bfp, th->sh[th->ptr_text].PointerToRawData + (da->addr_code - AddressOfCode), SEEK_SET);
					da->flag_IDD[i] = 1;   //�t�@�C���o�͗p�̃t���O�Z�b�g
					break;
				}
			}
			if (i == 16){ break; }
		}

		//�t�A�Z���u������
		if (Disasm(bfp, da) != 0){   //�t�A�Z���u�����s���A�I��
			printf("ERROR: Disasm\n");
			return -1; 
		}

		//�t�A�Z���u�����ʂ��t�@�C���o��
		if (dtfp != NULL){   //����dtfp��NULL�łȂ��ꍇ�̂݃t�@�C���o��
			Print_disasm(dtfp, bfp, da, th, ti);
		}

		//jump, call���ߗp��reference table �ݒ�p
		if (ti != NULL){   //����ti��NULL�łȂ��ꍇ�̂ݎ��s
			if ((da->instruction[0] == 'J' && strcmp(da->instruction, "JMPF") != 0) || strcmp(da->instruction, "CALL") == 0){
				if (da->flag_ref == COUNT){   //jump, call���߂̑������J�E���g
					da->num_rtable++;
				}
				else if (da->flag_ref == SET){   //rtable�\���̂�jump, call���߂̎w���E���A�h���X�Ɩ��ߎ�ނ��Z�b�g
					da->rtable[da->ptr_rtable].src = da->addr_code;
					if (da->operand[0] == REL8){
						da->rtable[da->ptr_rtable].dst = da->addr_code + da->offs + (char)da->imm8;
					}
					else if (da->operand[0] == REL32){
						da->rtable[da->ptr_rtable].dst = da->addr_code + da->offs + (long)da->imm32;
					}
					if (strcmp(da->instruction, "JMP") == 0){
						da->rtable[da->ptr_rtable].flag = UJMP;
					}
					else if (da->instruction[0] == 'J'){
						da->rtable[da->ptr_rtable].flag = CJMP;
					}
					else if (strcmp(da->instruction, "CALL") == 0){
						da->rtable[da->ptr_rtable].flag = CALL;
					}
					da->ptr_rtable++;
				}
			}
		}
	
		//Address�̍X�V
		da->addr_code += da->offs;
		da->offs = 0;
	}

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
int Print_disasm(FILE *dtfp, FILE *bfp, t_disasm *da, t_header *th, t_idata *ti){
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
		for (ptr = 0; ptr < da->num_rtable; ptr++){
			if (da->addr_code == da->rtable[ptr].dst){
				fprintf(dtfp, "\n* Referenced by (U)nconditional or (C)onditional Jump or (c)all at Address:\n");
				fprintf(dtfp, "| %08X", da->rtable[ptr].src);
				if (da->rtable[ptr].flag == UJMP){ fprintf(dtfp, "(U)"); }
				if (da->rtable[ptr].flag == CJMP){ fprintf(dtfp, "(C)"); }
				if (da->rtable[ptr].flag == CALL){ fprintf(dtfp, "(c)"); }
				for (ptr++; ptr < da->num_rtable; ptr++){
					if (da->addr_code == da->rtable[ptr].dst){
						fprintf(dtfp, ", %08X", da->rtable[ptr].src);
						if (da->rtable[ptr].flag == UJMP){ fprintf(dtfp, "(U)"); }
						if (da->rtable[ptr].flag == CJMP){ fprintf(dtfp, "(C)"); }
						if (da->rtable[ptr].flag == CALL){ fprintf(dtfp, "(c)"); }
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
		rva = th->SizeOfImage + 1;
		if (da->size_disp == 32){   //�f�B�X�v���[�X�����g�t�B�[���h��4�o�C�g�̂Ƃ�
			rva = da->disp32 - th->ImageBase;
		}
		else if (da->size_imm == 32){   //���l�t�B�[���h��4�o�C�g�̂Ƃ�
			rva = da->imm32 - th->ImageBase;
		}

		if (rva <= th->SizeOfImage){   //rva�̒l��RVA�͈͓̔��ł��邩�ǂ�������
			if (Print_function(dtfp, rva, bfp, th, ti) != 0){   //�C���|�[�g�֐��̒���
				Print_string(dtfp, rva, bfp, th);   //������̒���
			}
		}
	}
	
	fputc('\n', dtfp);	//���s

	return 0;
}


/* 
����rva��IAT���w���Ă���ꍇ���A�C���|�[�g�֐������킩��ꍇ�A
����DLL���ƃC���|�[�g�֐������t�@�C���o�͂���֐�
�����̏ꍇ��0���A���s�̏ꍇ��-1��Ԃ�
*/
int Print_function(FILE *dtfp, unsigned long rva, FILE *bfp, t_header *th, t_idata *ti){
	int i, j, k, len;
	char c1;
	long ord;
	unsigned long offs_log, offs, b4;
	unsigned long VA, PTRD;   //IMAGE_IMPORT_DESCRIPTOR��RVA�ƃt�@�C���ʒu


	for (i = 0; ti[i].FirstThunk != 0; i++){
		for (j = 0; j < ti[i].num_function; j++){
			if (rva == ti[i].FirstThunk + (j * 4)){   //����rva��IAT���w���Ă���ꍇ
				//IMAGE_IMPORT_DESCRIPTOR��RVA�ƃt�@�C���ʒu���擾
				VA = th->IDD[1].RVA;   //IMAGE_IMPORT_DESCRIPTOR��RVA��IMAGE_DATA_DIRECTORY�\���̂��擾
				for (k = 0; k < th->NumberOfSections; k++){   //RVA����ǂ̃Z�N�V�����ɂ���̂�����肵�A�t�@�C���ʒu���擾
					if (th->sh[k].VirtualAddress <= VA && VA <= th->sh[k].VirtualAddress + th->sh[k].VirtualSize){
						PTRD = VA - th->sh[k].VirtualAddress + th->sh[k].PointerToRawData;
						break;
					}
				}

				offs_log = ftell(bfp);   //�����t�@�C���ʒu���L��

				//offs��ILT��������IAT�̃t�@�C���ʒu���Z�b�g
				if (ti[0].OriginalFirstThunk != 0){   //ILT�����݂���ꍇ�AILT���Z�b�g
					offs = PTRD + (ti[i].OriginalFirstThunk - VA);
				}
				else{   //ILT�����݂��Ȃ��ꍇ�AIAT���Z�b�g
					offs = PTRD + (ti[i].FirstThunk - VA);
				}
				fseek(bfp, offs + (j * 4), SEEK_SET);
				fread(&b4, 1, 4, bfp);

				//�C���|�[�g�֐������킩��ꍇ�̂݁ADLL���ƃC���|�[�g�֐����o��
				if ((b4 & 0x80000000) != 0){   //�����w��̏ꍇ�A�I��
					return -1;
				}
				else{   //���O�o��
					//DLL���o��
					fprintf(dtfp, "   | ");
					fseek(bfp, PTRD + (ti[i].Name - VA), SEEK_SET);
					for (len = 0; len >= 0; len++){
						fread(&c1, 1, 1, bfp);
						fprintf(dtfp, "%c", c1);
						if (c1 == '\0'){ break; }   //DLL���̏I�[
					}
					fputc(' ', dtfp);
					//�C���|�[�g�֐����o��
					fseek(bfp, PTRD + (b4 - VA) + 2, SEEK_SET);
					for (len = 0; len >= 0; len++){
						fread(&c1, 1, 1, bfp);
						fprintf(dtfp, "%c", c1);
						if (c1 == '\0'){ break; }   //�C���|�[�g�֐����̏I�[
					}
				}

				fseek(bfp, offs_log, SEEK_SET);   //�����t�@�C���ʒu�ɃV�[�N
				return 0;
			}
		}
	}

	return -1;
}


/* 
����rva��ASCII��������UNICODE��������w���ꍇ�A���̕�������t�@�C���o�͂���֐� 
�����̏ꍇ0���A���s�̏ꍇ-1��Ԃ�
*/
int Print_string(FILE *dtfp, unsigned long rva, FILE *bfp, t_header *th){
	int i;
	long offs_log, offs_string;
	char c, str[200];
	wchar_t wc, wstr[200];


	offs_log = ftell(bfp);   //�����t�@�C���ʒu���L��

	/* ����rva�����������ꂽ�f�[�^���܂ރZ�N�V�������ł���΁A�t�@�C���ʒu���擾 */
	for (i = 0; i < th->NumberOfSections; i++){
			if (th->sh[i].VirtualAddress <= rva && rva <= th->sh[i].VirtualAddress + th->sh[i].VirtualSize){
				if (th->sh[i].Characteristics == 0x40000040){   //���������ꂽ�f�[�^���܂ރZ�N�V�����ł��邩�ǂ�������
					offs_string = rva - th->sh[i].VirtualAddress + th->sh[i].PointerToRawData;
					break;
				}
			}
	}
	if (i == th->NumberOfSections){ return -1; }   //����rva�������ɍ���Ȃ��ꍇ�A�I��

	/* ����rva���w���f�[�^��ASCII������ł��邩���肵�A�����ł���Ώo�� */
	fseek(bfp, offs_string, SEEK_SET);
	for (i = 0; i < 100; i++){
		fread(&c, 1, 1, bfp);
		if (c < 0x20 || 0x7e < c){ break; }
		str[i] = c;
	}
	if (i >= 4){
		str[i] = '\0';
		fprintf(dtfp, "   | ASCII \"%s\"", str);
		if (i == 100){ fprintf(dtfp, "..."); }
		fseek(bfp, offs_log, SEEK_SET);
		return 0;
	}

	/* ����rva���w���f�[�^��UNICODE������ł��邩���肵�A�����ł���Ώo�� */
	fseek(bfp, offs_string, SEEK_SET);
	for (i = 0; i < 100; i++){
		fread(&wc, 1, 2, bfp);
		if (wc < 0x0020 || 0x007e < wc){ break; }
		wstr[i] = wc;
	}
	if (i >= 4){
		wstr[i] = L'\0';
		fwprintf(dtfp, L"   | UNICODE \"%s\"", wstr);
		if (i == 100){ fprintf(dtfp, "..."); }
		fseek(bfp, offs_log, SEEK_SET);
		return 0;
	}

	fseek(bfp, offs_log, SEEK_SET);   //�����t�@�C���ʒu�ɃV�[�N
	return -1;
}


/* reference�A���̋t�A�Z���u�����ʂ��t�@�C���o�͂���֐� */
int Print_RefDisasm(FILE *dtfp, FILE *bfp, t_disasm *da, t_header *th, t_idata *ti){
	/* jump, call���߂̑������J�E���g */
	da->flag_ref = COUNT;
	da->num_rtable = 0;
	if (Disasm_LinearSweep(NULL, bfp, da, th, ti) != 0){
		printf("ERROR: Disasm_LinearSweep (da->flag_ref:COUNT)\n");
		return -1;
	}

	/* rtable�\���̂�jump, call���߂̑����������I�m�� */
	da->rtable = (t_rtable *)calloc(da->num_rtable, sizeof(t_rtable));
	if (da->rtable == NULL){
		printf("ERROR: calloc rtable\n");
		return -1;
	}

	/* rtable�\���̂�jump, call���߂̎w���E���A�h���X�Ɩ��ߎ�ނ��Z�b�g */
	da->flag_ref = SET;
	da->ptr_rtable = 0;
	if (Disasm_LinearSweep(NULL, bfp, da, th, ti) != 0){
		printf("ERROR: Disasm_LinearSweep (da->flag_ref:SET)\n");
		free(da->rtable);
		return -1;
	}

	/* reference�A���̋t�A�Z���u�����ʂ��t�@�C���o�� */
	da->flag_ref = PRINT;
	if (Disasm_LinearSweep(dtfp, bfp, da, th, ti) != 0){
		printf("ERROR: Disasm_LinearSweep (da->flag_ref:PRINT)\n");
		free(da->rtable);
		fclose(bfp);
		return -1;
	}

	/* ���I�m�ۂ���rtable�\���̂̃���������� */
	free(da->rtable);

	return 0;
}
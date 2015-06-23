#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "disasm.h"

/* Header����͂��ē������p�̍\���� */
typedef struct Header{
	char htname[256];
	unsigned long BaseOfCode;
	unsigned long ImageBase;
	unsigned long VirtualAddress;
	unsigned long SizeOfRawData;
	unsigned long PointerToRawData;
}t_header;

char *Get_filename(void);
int Read_header(FILE *bfp, t_header *th);
void change_reg(char reg_name[8][5], char reg[8][5]);
void Set_regname(char reg_name[8][5], int size_reg);
char *print_b1(unsigned char b1);
char *print_b2(unsigned short b2);
char *print_b4(unsigned long b4);



/* main�֐� */
int main(void){
	int i, n;

	unsigned char b1 = 0xff;
	char str[10];
	strcpy(str, print_b1(b1));
	printf("%s", str);
	exit(1);

	FILE *bfp, *tfp;
	t_header th;
	char szFile[256], fname[256], tname[256];

	/* �K�v�ȃt�@�C�������擾�A�ݒ� */
	//strcpy(szFile, "notepad(32bit)");
	strcpy(szFile, Get_filename(szFile));
	sprintf(fname, "%s.exe", szFile);
	sprintf(tname, "%s_Disasm.txt", szFile);
	sprintf(th.htname, "%s_Header.txt", szFile);

	printf("%s\n%s\n%s\n%s\n", szFile, fname, tname, th.htname);

	/* �t�@�C���̃I�[�v������ */
	if ((bfp = fopen(fname, "rb")) == NULL){
		printf("\a�t�@�C�����I�[�v���ł��܂���B\n");
		exit(1);
	}
	if ((tfp = fopen(tname, "w")) == NULL){
		printf("\a�t�@�C�����I�[�v���ł��܂���B\n");
		exit(1);
	}

	/* �w�b�_�[����t�A�Z���u���ɕK�v�ȏ����擾 */
	if (Read_header(bfp, &th) == 1){
		printf("\aFailed Read_header\n");
		exit(1);
	}

	/*�t�A�Z���u������*/
	t_disasm da;
	unsigned long addr_code = th.ImageBase + th.VirtualAddress;
	unsigned long offs = 0;
	int size_code;
	int scale[4] = { 1, 2, 4, 8 };
	char data[20];
	char reg_name[8][5];
	unsigned char hex, opc, bit8, modrm;
	union{
		unsigned short b2;
		unsigned char b1[2];
	}bit16;
	union{
		unsigned long b4;
		unsigned char b1[4];
	}bit32;

	while (((n = fread(&hex, 1, 1, bfp)) > 0) && offs < th.SizeOfRawData){
		//�A�h���X���o��
		fprintf(tfp, "%08X|   ", addr_code + offs);
		offs++;

		//�l�C�e�B�u�R�[�h���o�́����
		fprintf(tfp, "%02X", hex);
		size_code = 2;
		Init_disasm(&da);
		Check_pref(&da, hex);
		if (da.flag_pref){	//prefix �A��
			fputc(':', tfp);
			size_code++;
		}
		else{	//prefix �i�V
			fputc(' ', tfp);
			size_code++;
			Set_opc(&da, hex);
			for (da.ptr_opc = 1; da.ptr_opc < da.size_opc; da.ptr_opc++){
				fread(&hex, 1, 1, bfp);
				offs++;
				fprintf(tfp, "%02X ", hex);
				size_code += 3;
				Set_opc(&da, hex);
			}
		}
		if (da.flag_modrm){		//ModR/M �A��
			fread(&hex, 1, 1, bfp);
			offs++;
			fprintf(tfp, "%02X ", hex);
			size_code += 3;
			Set_modrm(&da, hex);
		}
		if (da.flag_sib){		//SIB �A��
			fread(&hex, 1, 1, bfp);
			offs++;
			fprintf(tfp, "%02X ", hex);
			size_code += 3;
			Set_sib(&da, hex);
		}
		switch (da.size_disp)	//�f�B�X�v���[�X�����g �A��
		{
		case 8:
			fread(&hex, 1, 1, bfp);
			offs++;
			fprintf(tfp, "%02X ", hex);
			size_code += 3;
			da.disp8 = hex;
			break;
		case 32:
			fread(&bit32.b1, 1, 4, bfp);
			offs += 4;
			for (i = 0; i < 4; i++){
				fprintf(tfp, "%02X", bit32.b1[i]);
			}
			fputc(' ', tfp);
			size_code += 9;
			da.disp32 = bit32.b4;
			break;
		}
		switch (da.size_imm)	//���l �A��
		{
		case 8:
			fread(&hex, 1, 1, bfp);
			offs++;
			fprintf(tfp, "%02X ", hex);
			size_code += 3;
			da.imm8 = hex;
			break;
		case 16:
			fread(&bit16.b1, 1, 2, bfp);
			offs += 2;
			for (i = 0; i < 2; i++){
				fprintf(tfp, "%02X", bit16.b1[i]);
			}
			fputc(' ', tfp);
			size_code += 5;
			da.imm16 = bit16.b2;
			break;
		case 32:
			fread(&bit32.b1, 1, 4, bfp);
			offs += 4;
			for (i = 0; i < 4; i++){
				fprintf(tfp, "%02X", bit32.b1[i]);
			}
			fputc(' ', tfp);
			size_code += 9;
			da.imm32 = bit32.b4;
			break;
		}
		for (; size_code < 25; size_code++){	//�󔒕����̒���
			fputc(' ', tfp);
		}

		//prefix or x86���߂��o��
		if (da.flag_pref){		//prefix �A��
			fprintf(tfp, "| PREFIX %s:", da.asm);
		}
		else{	//prefix �i�V�̏ꍇ�Ax86���߂��o��
			fprintf(tfp, "| %s ", da.asm);
			for (i = strlen(da.asm); i < 10; i++){	//�󔒕����̒���
				fputc(' ', tfp);
			}
		}

		//x86���߂̈������o��
		Set_regname(reg_name, 32);
		strcpy(data, "\0");
		for (i = 0; i < 3; i++){
			if (i != 0 && da.arg[i] != -1){		//�����Ԃ̋�؂���o��
				fputc(',', tfp);
			}

			switch (da.arg[i])
			{
			case IMM:	//���l
				switch (da.size_imm)
				{
				case 8:
					fprintf(tfp, "%02X", da.imm8);
					break;
				case 16:
					fprintf(tfp, "%04X", da.imm16);
					break;
				case 32:
					fprintf(tfp, "%08X", da.imm32);
					break;
				}
				break;
			case REG:	//���W�X�^
				fprintf(tfp, "%s", reg_name[da.reg_no]);
				break;
			case RO:	//ModR/M��r/o�t�B�[���h
				Set_regname(reg_name, da.size_ro);
				fprintf(tfp, "%s", reg_name[da.modrm.ro]);
				break;
			case RM:	//ModR/M��r/m�t�B�[���h
				if (da.flag_sib){	//SIB �A��
					fprintf(tfp, "%s", data);
					switch (da.modrm.mod)
					{
					case 0:
						if (da.sib.base == 5){
							if (da.sib.index == 4){
								fprintf(tfp, "[%08X]", da.disp32);
							}
							else{
								fprintf(tfp, "[%s*%d+%08X]", reg_name[da.sib.index], scale[da.sib.scale], da.disp32);
							}
						}
						else{
							if (da.sib.index == 4){
								fprintf(tfp, "[%s]", reg_name[da.sib.base]);
							}
							else{
								fprintf(tfp, "[%s+%s*%d]", reg_name[da.sib.base], reg_name[da.sib.index], scale[da.sib.scale]);
							}
						}
						break;
					case 1:
						if (da.sib.index == 4){
							fprintf(tfp, "[%s+%02X]", reg_name[da.sib.base], da.disp8);
						}
						else{
							fprintf(tfp, "[%s+%s*%d+%02X]", reg_name[da.sib.base], reg_name[da.sib.index], scale[da.sib.scale], da.disp8);
						}
						break;
					case 2:
						if (da.sib.index == 4){
							fprintf(tfp, "[%s+%08X]", reg_name[da.sib.base], da.disp32);
						}
						else{
							fprintf(tfp, "[%s+%s*%d+%08X]", reg_name[da.sib.base], reg_name[da.sib.index], scale[da.sib.scale], da.disp32);
						}
						break;
					}
				}
				else{	//SIB �i�V
					Set_regname(reg_name, da.size_rm);
					switch (da.modrm.mod)
					{
					case 0:
						if (da.modrm.rm == 5){
							fprintf(tfp, "%s[%08X]", data, da.disp32);
						}
						else{
							fprintf(tfp, "%s[%s]", data, reg_name[da.modrm.rm]);
						}
						break;
					case 1:
						fprintf(tfp, "%s[%s%s]", data, reg_name[da.modrm.rm], print_b1(da.disp8));
						break;
					case 2:
						fprintf(tfp, "%s[%s+%08X]", data, reg_name[da.modrm.rm], da.disp32);
						break;
					case 3:
						fprintf(tfp, "%s", reg_name[da.modrm.rm]);
						break;
					}
				}
				break;
			case REL:	//relative offset
				switch (da.size_imm)
				{
				case 8:
					fprintf(tfp, "%08X", addr_code + offs + (char)da.imm8);
					break;
				case 32:
					fprintf(tfp, "%08X", addr_code + offs + (long)da.imm32);
					break;
				}
				break;
			case MOFFS:		//moffs
				fprintf(tfp, "%s[%08X]", data, da.imm32);
				break;
			case DEF:
				fprintf(tfp, "%d", da.def);
				break;
			}
		}

		//flag_pref�̃��Z�b�g
		if (!da.flag_pref){
			for (i = 0; i < 5; i++)
				da.pref[i] = -1;
		}

		fputc('\n', tfp);	//���s
	}

	fclose(bfp);
	fclose(tfp);

	//�o�͌��ʃt�@�C�����������ŊJ��
	char cmdbuf[300];
	sprintf(cmdbuf, "notepad %s", th.htname);
	system(cmdbuf);
	sprintf(cmdbuf, "notepad %s", tname);
	system(cmdbuf);

	return 0;
}

/* �I�[�v���t�@�C���_�C�A���O��p���ē����t�@�C������Ԃ��֐� */
char *Get_filename(void){
	int i;
	OPENFILENAME ofn;
	char szFile[256];

	szFile[0] = '\0';
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.lpstrFilter = "all file(*.*)\0*.*\0\0";
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = sizeof(szFile);
	ofn.Flags = OFN_FILEMUSTEXIST;

	GetOpenFileName(&ofn);

	for (i = 0; i < 256; i++){
		if (szFile[i] == '.')
			szFile[i] = '\0';
	}

	return szFile;
}

/* �w�b�_����t�A�Z���u���ɕK�v�ȏ����擾���A�e�L�X�g�t�@�C���ɏo�͂���֐� */
int Read_header(FILE *bfp, t_header *th){
	unsigned long addr = 0;
	unsigned char c1;
	union{
		unsigned short b2;
		unsigned long b4;
		unsigned char b1[16];
	}code;

	FILE *htfp;
	if ((htfp = fopen(th->htname, "w")) == NULL){
		printf("\a�t�@�C�����I�[�v���ł��܂���B\n");
		return 1;
	}

	/*�t�A�Z���u���ɕK�v�ȏ����擾*/
	//IMAGE_DOS_HEADER
	fread(code.b1, 1, 2, bfp);
	addr += 2;
	fprintf(htfp, "e_magic:              %04X (\"%c%c\")\n", code.b2, code.b1[0], code.b1[1]);
	if (code.b2 != 0x5a4d){ exit(1); }

	while (addr < 0x3c){
		fread(&c1, 1, 1, bfp);
		addr++;
	}
	fread(code.b1, 1, 4, bfp);
	addr += 4;
	fprintf(htfp, "e_lfanew:             %08X\n\n", code.b4);
	unsigned long e_lfanew = code.b4;	//PE signature�ւ̃t�@�C���I�t�Z�b�g

	//PE signature
	while (addr < e_lfanew){
		fread(&c1, 1, 1, bfp);
		addr++;
	}
	fread(code.b1, 1, 4, bfp);
	addr += 4;
	fprintf(htfp, "Magic:                %08X (\"%s\")\n", code.b4, code.b1);
	if (code.b4 != 0x00004550){ return 1; }
	unsigned long fhead = addr;		//IMAGE_FILE_HEADER�ւ̃t�@�C���I�t�Z�b�g

	//IMAGE_FILE_HEADER
	fread(code.b1, 1, 2, bfp);
	addr += 2;
	fprintf(htfp, "Machine:              %04X", code.b2);
	if (code.b2 != 0x014c){ return 1; }
	else{ fprintf(htfp, " (Intel 386�ȍ~����т��̌݊��v���Z�b�T)\n"); }

	fread(code.b1, 1, 2, bfp);
	addr += 2;
	fprintf(htfp, "NumberOfSections:     %04X\n", code.b2);
	unsigned long NumberOfSections = code.b2;	//�Z�N�V�����̐�

	while (addr < fhead + 16){
		fread(&c1, 1, 1, bfp);
		addr++;
	}
	fread(code.b1, 1, 2, bfp);
	addr += 2;
	fprintf(htfp, "SizeOfOptionalHeader: %04X\n\n", code.b4);
	unsigned long ohead = addr + 2;		//IMAGE_OPTINAL_HEADER�ւ̃t�@�C���I�t�Z�b�g
	unsigned long shead = ohead + code.b4;		//IMAGE_SECTION_HEADER�ւ̃t�@�C���I�t�Z�b�g

	//IMAGE_OPTINAL_HEADER
	while (addr < ohead + 4){
		fread(&c1, 1, 1, bfp);
		addr++;
	}
	fread(code.b1, 1, 4, bfp);
	addr += 4;
	fprintf(htfp, "SizeOfCode:           %08X\n", code.b4);
	unsigned long SizeOfCode = code.b4;

	while (addr < ohead + 16){
		fread(&c1, 1, 1, bfp);
		addr++;
	}
	fread(code.b1, 1, 4, bfp);
	addr += 4;
	fprintf(htfp, "AddressOfEntryPoint:  %08X\n", code.b4);

	while (addr < ohead + 20){
		fread(&c1, 1, 1, bfp);
		addr++;
	}
	fread(code.b1, 1, 4, bfp);
	addr += 4;
	fprintf(htfp, "BaseOfCode:           %08X\n", code.b4);
	th->BaseOfCode = code.b4;

	while (addr < ohead + 28){
		fread(&c1, 1, 1, bfp);
		addr++;
	}
	fread(code.b1, 1, 4, bfp);
	addr += 4;
	fprintf(htfp, "ImageBase:            %08X\n\n", code.b4);
	th->ImageBase = code.b4;

	//IMAGE_SECTION_HEADER
	int flag_text;
	th->PointerToRawData = 0;
	while (NumberOfSections){
		flag_text = 0;

		while (addr < shead){
			fread(&c1, 1, 1, bfp);
			addr++;
		}
		fread(code.b1, 1, 8, bfp);
		addr += 8;
		code.b1[8] = '\0';
		fprintf(htfp, "[%s]\n", code.b1);
		if (!strcmp(code.b1, ".text")){ flag_text = 1; }

		while (addr < shead + 12){
			fread(&c1, 1, 1, bfp);
			addr++;
		}
		fread(code.b1, 1, 4, bfp);
		addr += 4;
		fprintf(htfp, "VirtualAddress:       %08X\n", code.b4);
		if (flag_text){ th->VirtualAddress = code.b4; }

		while (addr < shead + 16){
			fread(&c1, 1, 1, bfp);
			addr++;
		}
		fread(code.b1, 1, 4, bfp);
		addr += 4;
		fprintf(htfp, "SizeOfRawData:        %08X\n", code.b4);
		if (flag_text){ th->SizeOfRawData = code.b4; }

		fread(code.b1, 1, 4, bfp);
		addr += 4;
		fprintf(htfp, "PointerToRawData:     %08X\n", code.b4);
		if (flag_text){ th->PointerToRawData = code.b4; }

		while (addr < shead + 36){
			fread(&c1, 1, 1, bfp);
			addr++;
		}
		fread(code.b1, 1, 4, bfp);
		addr += 4;
		fprintf(htfp, "Characteristics:      %08X\n\n", code.b4);
	
		shead = addr;
		NumberOfSections--;
	}
	if (flag_text){ return 1; }
	
	//.text�Z�N�V�����̊J�n�ʒu�܂œǂݍ���
	while (addr < th->PointerToRawData){
		fread(&c1, 1, 1, bfp);
		addr++;
	}

	fclose(htfp);

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
	case 8:
		change_reg(reg_name, reg8);
		break;
	case 16:
		change_reg(reg_name, reg16);
		break;
	case 32:
		change_reg(reg_name, reg32);
		break;
	case SREG:
		change_reg(reg_name, sreg);
		break;
	default:
		break;
	}
}

/* ���l�𕄍��t�ŏo�� */
char *print_b1(unsigned char b1){
	char str[10];

	if ((char)b1 < 0){
		b1 = ~b1 + 1;
		sprintf(str, "-%02X", b1);
	}
	else{
		sprintf(str, "+%02X", b1);
	}
	return str;
}
char *print_b2(unsigned short b2){

}
char *print_b4(unsigned long b4){

}
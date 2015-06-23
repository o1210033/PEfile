#define IMM		1
#define REG		2
#define RO		3
#define RM		4
#define REL		5
#define MOFFS	6
#define DEF		7

#define SREG	-2

/* 逆アセンブルに必要な情報用の構造体 */
typedef struct Disasm{
	int flag_pref, flag_modrm, flag_sib;
	int arg[3];
	int ptr_opc;
	int size_opc, size_disp, size_imm;
	int size_rm, size_ro;

	char asm[20];
	int reg_no;
	unsigned char pref[5], opc[3];
	unsigned char disp8, imm8;
	unsigned short imm16;
	unsigned long disp32, imm32;
	int def;

	struct ModRM{
		int mod, ro, rm;
	} modrm;
	struct SIB{
		int scale, index, base;
	} sib;
}t_disasm;

void Init_disasm(t_disasm *da);
void Check_pref(t_disasm *da, unsigned char hex);
void Set_opc(t_disasm *da, unsigned char hex);
void Set_modrm(t_disasm *da, unsigned char hex);
void Set_sib(t_disasm *da, unsigned char hex);

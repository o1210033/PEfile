#define IMM8    1
#define IMM16   2
#define IMM32   3
#define R8      4
#define R16     5
#define R32     6
#define SREG    7
#define EAX     8
#define RM8     9
#define RM16    10
#define RM32    11
#define REL8    12
#define REL16   13
#define REL32   14
#define MOFFS8  15
#define MOFFS16 16
#define MOFFS32 17
#define DEF1    18

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

void Set_opc1(t_disasm *da);
void Set_opc2(t_disasm *da);
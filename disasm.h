//operand
#define IMM8    1
#define IMM16   2
#define IMM32   3
#define RM8     4
#define RM16    5
#define RM32    6
#define REL8    7
#define REL16   8
#define REL32   9
#define MOFFS8  10
#define MOFFS16 11
#define MOFFS32 12
#define M8      13
#define M16     14
#define M32     15

#define DEF1    30

#define R8      50
#define R16     51
#define R32     52
#define SREG    53
#define EAX     54

//FlagOfRtable
#define UJMP   1
#define CJMP   2
#define CALL   3

//flag_ref
#define COUNT   1
#define SET     2
#define PRINT   3


/* �t�A�Z���u���ɕK�v�ȏ��p�̍\���� */
typedef struct Disasm{
	char dtname[300];

	int flag_pref, flag_modrm, flag_sib;
	int size_opc, size_disp, size_imm;
	int ptr_pref, ptr_opc;
	int operand[3];
	char instruction[15];
	unsigned char pref[4], opc[3];
	unsigned char disp8, imm8;
	unsigned short imm16;
	unsigned long disp32, imm32;

	struct ModRM{
		int mod, ro, rm;
		unsigned long hex;
	} modrm;
	struct SIB{
		int scale, index, base;
		unsigned long hex;
	} sib;

	//�t�@�C���o�͗p
	int flag_print, flag_ref, flag_IDD[16];
	unsigned long addr_code, offs;
	struct ReferenceTable{
		unsigned long ptr, num;
		unsigned long *dst, *src;
		int *flag;
	}rtable;
}t_disasm;

/* disasm.c */
void Check_pref(t_disasm *da, unsigned char hex);
int Set_opc(t_disasm *da, unsigned char hex);
void Set_modrm(t_disasm *da, unsigned char hex);
void Set_sib(t_disasm *da, unsigned char hex);

/* opcode.c */
void Set_opc1(t_disasm *da);
void Set_opc2(t_disasm *da);
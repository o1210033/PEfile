/* IMAGE_DATA_DIRECTORY�\���̗p */
typedef struct IDD{
	char Name[20];
	unsigned long RVA;
	unsigned long Size;
}t_IDD;

/* �Z�N�V�������p�̍\���� */
typedef struct Section{
	unsigned long VirtualSize;
	unsigned long VirtualAddress;
	unsigned long SizeOfRawData;
	unsigned long PointerToRawData;
}t_section;

/* Header����͂��ē������p�̍\���� */
typedef struct Header{
	char htname[256];
	char itname[256];
	unsigned long BaseOfCode;
	unsigned long ImageBase;
	t_IDD IDD[16];
	t_section ts[10];
	unsigned long VirtualAddress;
	unsigned long SizeOfRawData;
	unsigned long PointerToRawData;
	struct NO{
		int text, idata;
	}no;
}t_header;

/* �C���|�[�g���p�̍\���� */
typedef struct Idata{
	unsigned long OriginalFirstThunk;
	unsigned long Name;
	unsigned long FirstThunk;

	unsigned long ILT_rva[256];   //ILT���g��RVA
	unsigned long ILT[256];   //ILT���ێ����Ă���RVA
	int size_ILT;   //ILT�̐�

	unsigned long IAT_rva[256];   //IAT���g��RVA
	unsigned long IAT[256];   //IAT���ێ����Ă���RVA
	int size_IAT;   //IAT�̐�

	char dll[64];   //DLL��
	long OrdinalNumber[256];
	short Hint[256];
	char function[256][64];   //�C���|�[�g�֐���
}t_idata;


int Read_header(FILE *bfp, t_header *th);
int Read_idata(FILE *bfp, t_header *th, t_idata ti[]);
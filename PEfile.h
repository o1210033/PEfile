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
	unsigned long Characteristics;
}t_section;

/* Header����͂��ē������p�̍\���� */
typedef struct Header{
	char htname[300];
	char itname[300];
	unsigned short NumberOfSections;
	unsigned long SizeOfCode;
	unsigned long AddressOfEntryPoint;
	unsigned long BaseOfCode;
	unsigned long ImageBase;
	unsigned long SizeOfImage;
	t_IDD IDD[16];
	t_section ts[10];
	int ptr_text;
}t_header;

/* �C���|�[�g���p�̍\���� */
typedef struct Idata{
	unsigned long OriginalFirstThunk;   //ILT��RVA
	unsigned long Name;   //DLL����RVA
	unsigned long FirstThunk;   //IAT��RVA

	int size_IAT;   //IAT�̃T�C�Y
	char dll[50];   //DLL��
	long OrdinalNumber[150];   //����
	short Hint[150];   //�q���g
	char function[150][50];   //�C���|�[�g�֐���
}t_idata;


int Read_header(FILE *bfp, t_header *th);
int Read_idata(FILE *bfp, t_header *th, t_idata ti[]);
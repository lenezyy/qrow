#define QROW_MAGIC  "qrow"
#define QROW_VERSION 1
#define MIN_CLUSTER_BITS 9
#define MAX_CLUSTER_BITS 21
#define MAX_VM_SECTOR_NUM  1024 //������̰��������������  2^20
#define RRTYPE 'R'
#define MAX_READ_SECTOR_NUM  8 //��������ȡ�����������  2^11
#define uint8_t unsigned char
#define uint32_t unsigned int
#define uint64_t unsigned long long
#define MAX_FILE_NAME_LENGTH 128

int is_record = 0;
int is_replay = 0;
uint64_t vm_total_sectors;//�����ô��ȡ�أ� 

struct QrowHeader 
{ 
    char format_name[8];  // ���̸�ʽ,Ĭ����qrow�ַ��� ,���ߵ�qrow_create������ȥ��ֵ������ 
    uint32_t version; // �汾
    uint32_t block_size; // block��С���ֽ�
    uint32_t block_bits; // block��λ��
    uint32_t sectors_per_block;//ÿ��block������������ 
    uint64_t total_blocks; // block�ĸ���
    uint64_t disk_size; // �����С���ֽ�
	uint64_t block_offset; //�����ļ���һ������block��ţ�Ĭ��ֵΪ 1 ����0����Ԫ����ͷ��Ϣռ�� 
	char img_name[MAX_FILE_NAME_LENGTH]; //�����ļ����Ƽ�·��(���ڿ��Կ��ǰ�·��ɾ����ֻ�����ļ�����) 
	char map_path[MAX_FILE_NAME_LENGTH];//�洢map������ļ�·�� 
};

//��ŵ�������Ҫ���ڶ�д���� 
struct QrowState 
{ 
    uint32_t block_size; // block��С���ֽ�
    uint32_t sectors_per_block;//ÿ��block������������ 
    uint64_t total_blocks; // block�ĸ���
	uint64_t block_offset; //�����ļ���һ������block���
	uint64_t byte_offset;//�����ļ���һ����д���ƫ���������ֽ�Ϊ��λ���������Ҳ�����Ǿֲ��ģ�ÿ�μ���ͺ�
	uint64_t sector_offset;//�����ļ���һ����д��������ţ���Ҫ���ڱ���������̺������������ӳ���ϵ����Ŵ�0��ʼ 
	uint64_t map[MAX_VM_SECTOR_NUM]; //���ڶ�д�����м�¼������̺������������ӳ���ϵ�������ֵ��Ҫ��ʼ��Ϊ0ô�����Ǵ�����ʱ��Ĭ����Ϊ��0 
	//���鳤���ǽṹ��д������ĳ���������涯̬������ 
	int img_file;//�򿪵Ĵ����ļ� 
	int log_file_fd;//�򿪵�log�ļ� 
	int map_file_fd;//�򿪵Ĵ洢map������ļ� 
};

struct QrowRRIo //��¼�׶ζ�������Ӧ�Ľṹ�� 
{ 
	uint64_t sector[MAX_READ_SECTOR_NUM];//��ʾ���ݿ�洢��������̾���sector��
};



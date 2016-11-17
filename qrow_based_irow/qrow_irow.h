/* IROW��Improved ROW����ʽ���豸����
 * liuhq 2012
 * IROW��ʽʹ��ROW���COW�Ķ���д�Ŀ�����ͬʱʹ��COD���ROW���ļ���Ƭ����
 * */

#define QROW_MAGIC (('Q' << 24) | ('R' << 16) | ('O' << 8) | 'W')
#define QROW_VERSION 1
#define MIN_CLUSTER_BITS 9
#define MAX_CLUSTER_BITS 21
#define MAX_FILE_NAME_LENGTH 128
#define MAX_VM_SECTOR_NUM  1024 //������̰��������������  2^20
//MAX_VM_SECTOR_NUM���������ζ��壿��������
#define RRTYPE 'R'
#define MAX_READ_SECTOR_NUM  8 //��������ȡ�����������  2^11
#define QROW_READ 1
#define QROW_WRITE 2
#define QROW_AIO_READ 3
#define QROW_AIO_WRITE 4

typedef struct __attribute__((packed)) 	QRowMeta
{ 
    uint32_t magic;  //ħ�� 
    uint32_t version; // �汾
    uint32_t cluster_size; // cluster��С���ֽ�
    uint32_t cluster_bits; // cluster��λ��
    uint32_t sectors_per_cluster;//ÿ��cluster������������ 
    uint64_t total_clusters; // cluster�ĸ���
    uint64_t disk_size; // �����С���ֽ�
	uint64_t cluster_offset; //�����ļ���һ������cluster��
	char img_file[MAX_FILE_NAME_LENGTH]; //�������� 
	char map_file[MAX_FILE_NAME_LENGTH];//�洢map������ļ�����
	char backing_file[MAX_FILE_NAME_LENGTH];//// base image����
}QRowMeta;


typedef struct ClusterCache {
	uint8_t *cache;
	int64_t cluster_num;
} ClusterCache;

typedef struct BDRVQrowState 
{ 
    BlockDriverState *qrow_img_file; //  qrow_img_file����״̬
	BlockDriverState *qrow_map_file;
	//BlockDriverState *qrow_log_file;
	uint32_t cluster_size;
	uint32_t cluster_bits; // cluster��λ��	
    uint32_t sectors_per_cluster;
    uint64_t total_clusters; 
	uint64_t disk_size; // �����С���ֽ�
	uint64_t cluster_offset; 
	uint64_t byte_offset;
	uint64_t sector_offset;
	uint64_t meta_cluster;//QRowMeta�ṹ��ռ��cluster����
	uint64_t map[MAX_VM_SECTOR_NUM]; 
	uint32_t map_is_dirty; // ���ڱ���map�Ƿ���map_file�ļ��е�һ��
	int open_flags; // ���̾���Ĵ򿪱�־
	//int img_file_fd;//�򿪵Ĵ����ļ� 
	//int log_file_fd;//�򿪵�log�ļ� 
	//int map_file_fd;//�򿪵Ĵ洢map������ļ�
	char *img_file;
	char *map_file;
	//char *log_file;
}BDRVQrowState;

typedef struct ClusterBuffer {
	uint8_t *buf;
	uint8_t *read_from_father;
} ClusterBuffer;

#define IROW_SNAPSHOT_OFFSET sizeof(IRowMeta)
#define MAX_MERGE_BUFFER 16 * 1024 * 1024 //ɾ�����պϲ�ʱ��󻺳�����С

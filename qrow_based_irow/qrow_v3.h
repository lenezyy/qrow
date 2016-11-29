/* QROW��ʽ���豸����
 * zyy 2016
 * */

#define QROW_MAGIC (('Q' << 24) | ('R' << 16) | ('O' << 8) | 'W')
#define QROW_VERSION 1
#define MAX_FILE_NAME_LENGTH 128
#define RRTYPE 'R'
#define QROW_READ 1
#define QROW_WRITE 2
#define QROW_AIO_READ 3
#define QROW_AIO_WRITE 4

typedef struct __attribute__((packed)) 	QRowMeta
{ 
    uint32_t magic;  //ħ�� 
    uint32_t version; // �汾
    uint64_t total_sectors; // cluster�ĸ���
    uint64_t disk_size; // �����С���ֽ�
	uint64_t sector_offset; //�����ļ���һ������sector��
	char meta_file[MAX_FILE_NAME_LENGTH]; //metaͷ��Ϣ���ڵ��ļ����� 
	char data_file[MAX_FILE_NAME_LENGTH];//��ž������ݵ��ļ����� 
	char map_file[MAX_FILE_NAME_LENGTH];//�洢map������ļ�����
	char backing_file[MAX_FILE_NAME_LENGTH];//// base image����
}QRowMeta;

typedef struct BDRVQrowState 
{ 
    BlockDriverState *qrow_meta_file; //  qrow_meta_file����״̬
	BlockDriverState *qrow_map_file;
	BlockDriverState *qrow_data_file;
	//BlockDriverState *qrow_log_file;
    uint64_t total_sectors; 
	uint64_t disk_size; // �����С���ֽ�
	uint64_t byte_offset;
	uint64_t sector_offset;
	uint64_t *map;//���������������������������ӳ���
	uint64_t map_size;//mapӳ�����
	uint32_t map_is_dirty; // ���ڱ���map�Ƿ���map_file�ļ��е�һ��
	int open_flags; // ���̾���Ĵ򿪱�־
	//int img_file_fd;//�򿪵Ĵ����ļ� 
	//int log_file_fd;//�򿪵�log�ļ� 
	//int map_file_fd;//�򿪵Ĵ洢map������ļ�
	char *meta_file;
	char *map_file;
	char *data_file;
	//char *log_file;
}BDRVQrowState;


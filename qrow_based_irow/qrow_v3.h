/* QROW格式块设备驱动
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
    uint32_t magic;  //魔数 
    uint32_t version; // 版本
    uint64_t total_sectors; // cluster的个数
    uint64_t disk_size; // 镜像大小，字节
	uint64_t sector_offset; //磁盘文件下一个可用sector号
	char meta_file[MAX_FILE_NAME_LENGTH]; //meta头信息所在的文件名称 
	char data_file[MAX_FILE_NAME_LENGTH];//存放镜像数据的文件名称 
	char map_file[MAX_FILE_NAME_LENGTH];//存储map数组的文件名称
	char backing_file[MAX_FILE_NAME_LENGTH];//// base image名称
}QRowMeta;

typedef struct BDRVQrowState 
{ 
    BlockDriverState *qrow_meta_file; //  qrow_meta_file驱动状态
	BlockDriverState *qrow_map_file;
	BlockDriverState *qrow_data_file;
	//BlockDriverState *qrow_log_file;
    uint64_t total_sectors; 
	uint64_t disk_size; // 镜像大小，字节
	uint64_t byte_offset;
	uint64_t sector_offset;
	uint64_t *map;//虚拟磁盘扇区到镜像物理扇区的映射表
	uint64_t map_size;//map映射表长度
	uint32_t map_is_dirty; // 用于表明map是否与map_file文件中的一致
	int open_flags; // 磁盘镜像的打开标志
	//int img_file_fd;//打开的磁盘文件 
	//int log_file_fd;//打开的log文件 
	//int map_file_fd;//打开的存储map数组的文件
	char *meta_file;
	char *map_file;
	char *data_file;
	//char *log_file;
}BDRVQrowState;


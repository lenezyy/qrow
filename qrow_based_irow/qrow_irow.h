/* IROW（Improved ROW）格式块设备驱动
 * liuhq 2012
 * IROW格式使用ROW解决COW的额外写的开销，同时使用COD解决ROW的文件碎片问题
 * */

#define QROW_MAGIC (('Q' << 24) | ('R' << 16) | ('O' << 8) | 'W')
#define QROW_VERSION 1
#define MIN_CLUSTER_BITS 9
#define MAX_CLUSTER_BITS 21
#define MAX_FILE_NAME_LENGTH 128
#define MAX_VM_SECTOR_NUM  1024 //虚拟磁盘包含的最大扇区数  2^20
//MAX_VM_SECTOR_NUM这个到底如何定义？？？？？
#define RRTYPE 'R'
#define MAX_READ_SECTOR_NUM  8 //读操作读取的最大扇区数  2^11
#define QROW_READ 1
#define QROW_WRITE 2
#define QROW_AIO_READ 3
#define QROW_AIO_WRITE 4

typedef struct __attribute__((packed)) 	QRowMeta
{ 
    uint32_t magic;  //魔数 
    uint32_t version; // 版本
    uint32_t cluster_size; // cluster大小，字节
    uint32_t cluster_bits; // cluster的位数
    uint32_t sectors_per_cluster;//每个cluster包括的扇区数 
    uint64_t total_clusters; // cluster的个数
    uint64_t disk_size; // 镜像大小，字节
	uint64_t cluster_offset; //磁盘文件下一个可用cluster号
	char img_file[MAX_FILE_NAME_LENGTH]; //镜像名称 
	char map_file[MAX_FILE_NAME_LENGTH];//存储map数组的文件名称
	char backing_file[MAX_FILE_NAME_LENGTH];//// base image名称
}QRowMeta;


typedef struct ClusterCache {
	uint8_t *cache;
	int64_t cluster_num;
} ClusterCache;

typedef struct BDRVQrowState 
{ 
    BlockDriverState *qrow_img_file; //  qrow_img_file驱动状态
	BlockDriverState *qrow_map_file;
	//BlockDriverState *qrow_log_file;
	uint32_t cluster_size;
	uint32_t cluster_bits; // cluster的位数	
    uint32_t sectors_per_cluster;
    uint64_t total_clusters; 
	uint64_t disk_size; // 镜像大小，字节
	uint64_t cluster_offset; 
	uint64_t byte_offset;
	uint64_t sector_offset;
	uint64_t meta_cluster;//QRowMeta结构体占的cluster个数
	uint64_t map[MAX_VM_SECTOR_NUM]; 
	uint32_t map_is_dirty; // 用于表明map是否与map_file文件中的一致
	int open_flags; // 磁盘镜像的打开标志
	//int img_file_fd;//打开的磁盘文件 
	//int log_file_fd;//打开的log文件 
	//int map_file_fd;//打开的存储map数组的文件
	char *img_file;
	char *map_file;
	//char *log_file;
}BDRVQrowState;

typedef struct ClusterBuffer {
	uint8_t *buf;
	uint8_t *read_from_father;
} ClusterBuffer;

#define IROW_SNAPSHOT_OFFSET sizeof(IRowMeta)
#define MAX_MERGE_BUFFER 16 * 1024 * 1024 //删除快照合并时最大缓冲区大小

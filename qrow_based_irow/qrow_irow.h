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

typedef struct BDRVIrowState { //
    BlockDriverState *irow_meta; // irow meta 驱动状态
    BlockDriverState *irow_btmp; // irow bitmap驱动状态
    BlockDriverState *irow_irvd; // irow 虚拟磁盘镜像驱动状态
    uint64_t disk_size; // 字节
    uint64_t bitmap_size; // 字节
    uint32_t cluster_size; // 字节
    uint32_t cluster_bits; // cluster位数
    uint64_t total_clusters; // 磁盘镜像的cluster总数
    uint32_t sectors_per_cluster; // 一个cluster中的sector数量
    uint32_t nb_snapshots; // 快照的个数
    uint32_t vm_state_size; // 虚拟机状态大小
    uint32_t copy_on_demand; // 按需拷贝标志
    int open_flags; // 磁盘镜像的打开标志
    IRowSnapshot *snapshots; // sanpshot数组，数组中元素的个数为nb_snapshots个
    uint32_t snapshots_is_dirty; // 用于表明snapshots数组是否于meta文件中的一致
    uint8_t *bitmap; // bitmap 缓存
    uint32_t bitmap_is_dirty; // 用于表明bitmap是否与btmp文件中的一致
    uint32_t vmstate_is_saved; // 用于表明是否保存过vmstate而没有截断文件
    uint32_t complete_image; // 用于表明是否所有的cluster均在当前镜像中
    char *meta_file; // meta文件
    char *current_btmp_file; // 当前bitmap文件，特指虚拟磁盘当前的bitmap文件
    char *father_btmp_file; // 打开的bitmap文件对应的"父亲"bitmap文件
    char *opened_btmp_file; // 打开的bitmap文件，可以和当前bitmap文件不同，例如打开"父亲"bitmap文件时
    char *irvd_file; // 打开的bitmap文件对应的磁盘镜像文件
} BDRVIrowState;

//存放的数据主要用于读写操作 
typedef struct BDRVQrowState 
{ 
    uint32_t cluster_size; 
    uint32_t sectors_per_cluster;
    uint64_t total_clusters; 
	uint64_t cluster_offset; 
	uint64_t byte_offset;
	uint64_t sector_offset;
	uint64_t map_file[MAX_VM_SECTOR_NUM]; 
	int img_file_fd;//打开的磁盘文件 
	int log_file_fd;//打开的log文件 
	int map_file_fd;//打开的存储map数组的文件 
}BDRVQrowState;

typedef struct ClusterBuffer {
	uint8_t *buf;
	uint8_t *read_from_father;
} ClusterBuffer;

#define IROW_SNAPSHOT_OFFSET sizeof(IRowMeta)
#define MAX_MERGE_BUFFER 16 * 1024 * 1024 //删除快照合并时最大缓冲区大小

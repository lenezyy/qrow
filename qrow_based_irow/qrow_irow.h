/* IROW（Improved ROW）格式块设备驱动
 * liuhq 2012
 * IROW格式使用ROW解决COW的额外写的开销，同时使用COD解决ROW的文件碎片问题
 * */

#define IROW_MAGIC (('I' << 24) | ('R' << 16) | ('O' << 8) | 'W')
#define IROW_VERSION 1

#define IROW_SNAPHEADER_MAGIC (('S' << 24) | ('N' << 16) | ('A' << 8) | 'P')

#define MIN_CLUSTER_BITS 9
#define MAX_CLUSTER_BITS 21
#define MAX_FILE_NAME_LENGTH 256

#define IROW_READ 1
#define IROW_WRITE 2
#define IROW_AIO_READ 3
#define IROW_AIO_WRITE 4

//#define IROW_CRYPT_NONE 0
//#define IROW_CRYPT_AES  1

typedef struct __attribute__((packed)) IRowMeta { // irow meta文件头
    uint32_t magic; // 魔数
    uint32_t version; // 版本
    uint32_t copy_on_demand; // 按需拷贝标记
    uint32_t nb_snapshots; // 快照的个数
    uint32_t cluster_size; // cluster大小，字节
    uint32_t cluster_bits; // cluster的位数
    uint32_t sectors_per_cluster; // 一个cluster中的sector数量
    uint64_t total_clusters; // cluster的个数
    uint64_t disk_size; // 镜像大小，字节
    char current_btmp[MAX_FILE_NAME_LENGTH]; // 当前bitmap文件
    char backing_file[MAX_FILE_NAME_LENGTH]; // base image名称
} IRowMeta;

typedef struct __attribute__((packed)) IRowSnapshotHeader {
	uint32_t snap_magic; // snapshot header的魔数
	char id_str[128]; // 快照的id，每个快照有唯一的id
	char name[256]; // 名称，或者可以理解为说明，不同快照的name可以相同
	char btmp_file[MAX_FILE_NAME_LENGTH]; // 该快照对应的btmp文件
	char irvd_file[MAX_FILE_NAME_LENGTH]; // 该快照对应的irvd文件
	char father_btmp_file[MAX_FILE_NAME_LENGTH]; // "父亲"对应的btmp文件
	uint32_t vm_state_size;
	uint32_t date_sec; // 距离1970年1月1日00：00：00的秒数
	uint32_t date_nsec; // 日期的纳秒数，精确到1000，实际是用微秒数＊1000得到的
	uint64_t vm_clock_nsec; // VM启动后的纳秒数
	uint32_t nb_children; // 孩子快照个数
	uint32_t is_deleted; // 是否已删除标志
} IRowSnapshotHeader;

typedef struct IRowSnapshot {
	char *id_str;
	char *name;
	char *btmp_file;
	char *irvd_file;
	char *father_btmp_file;
	uint32_t vm_state_size;
	uint32_t date_sec; // 距离1970年1月1日00：00：00的秒数
	uint32_t date_nsec; // 日期的纳秒数，精确到1000，实际是用微秒数＊1000得到的
	uint64_t vm_clock_nsec; // VM启动后的纳秒数
	uint32_t nb_children; // 孩子快照个数
	uint32_t is_deleted; // 是否已删除标志
} IRowSnapshot;

typedef struct IRowCreateState {
	uint64_t disk_size;
	uint32_t cluster_size;
	uint32_t cluster_bits;
	uint32_t copy_on_demand;
	char *meta_file; // meta文件
	char *father_btmp_file; // 打开的bitmap文件对应的"父亲"bitmap文件
	char *btmp_file; // 要创建的bitmap文件
	char *irvd_file; // 要创建的bitmap文件对应的irvd文件
	char *time_value; // 创建该结构题的时间16进制字符串（粗略的可以认为是创建磁盘镜像的时间），用做文件名的一部分
	char *backing_file; // base image文件名
} IRowCreateState;

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

typedef struct ClusterBuffer {
	uint8_t *buf;
	uint8_t *read_from_father;
} ClusterBuffer;

#define IROW_SNAPSHOT_OFFSET sizeof(IRowMeta)
#define MAX_MERGE_BUFFER 16 * 1024 * 1024 //删除快照合并时最大缓冲区大小

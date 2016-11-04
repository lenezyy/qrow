#define QROW_MAGIC  "qrow"
#define QROW_VERSION 1
#define MIN_CLUSTER_BITS 9
#define MAX_CLUSTER_BITS 21
#define MAX_VM_SECTOR_NUM  1024 //虚拟磁盘包含的最大扇区数  2^20
#define RRTYPE 'R'
#define MAX_READ_SECTOR_NUM  8 //读操作读取的最大扇区数  2^11
#define uint8_t unsigned char
#define uint32_t unsigned int
#define uint64_t unsigned long long
#define MAX_FILE_NAME_LENGTH 128

int is_record = 0;
int is_replay = 0;
uint64_t vm_total_sectors;//这个怎么获取呢？ 

struct QrowHeader 
{ 
    char format_name[8];  // 磁盘格式,默认是qrow字符串 ,或者到qrow_create里面再去赋值？？？ 
    uint32_t version; // 版本
    uint32_t block_size; // block大小，字节
    uint32_t block_bits; // block的位数
    uint32_t sectors_per_block;//每个block包括的扇区数 
    uint64_t total_blocks; // block的个数
    uint64_t disk_size; // 镜像大小，字节
	uint64_t block_offset; //磁盘文件下一个可用block块号，默认值为 1 ，第0个被元数据头信息占用 
	char img_name[MAX_FILE_NAME_LENGTH]; //磁盘文件名称及路径(后期可以考虑把路径删除，只保留文件名称) 
	char map_path[MAX_FILE_NAME_LENGTH];//存储map数组的文件路径 
};

//存放的数据主要用于读写操作 
struct QrowState 
{ 
    uint32_t block_size; // block大小，字节
    uint32_t sectors_per_block;//每个block包括的扇区数 
    uint64_t total_blocks; // block的个数
	uint64_t block_offset; //磁盘文件下一个可用block块号
	uint64_t byte_offset;//磁盘文件下一个可写入的偏移量，以字节为单位。这个变量也可以是局部的，每次计算就好
	uint64_t sector_offset;//磁盘文件下一个可写入的扇区号，主要用于保存虚拟磁盘和物理磁盘数据映射关系，编号从0开始 
	uint64_t map[MAX_VM_SECTOR_NUM]; //用于读写过程中记录虚拟磁盘和物理磁盘数据映射关系，数组的值需要初始化为0么？还是创建的时候默认设为了0 
	//数组长度是结构体写死还是某个函数里面动态分配呢 
	int img_file;//打开的磁盘文件 
	int log_file_fd;//打开的log文件 
	int map_file_fd;//打开的存储map数组的文件 
};

struct QrowRRIo //记录阶段读操作对应的结构体 
{ 
	uint64_t sector[MAX_READ_SECTOR_NUM];//表示数据块存储在物理磁盘具体sector号
};



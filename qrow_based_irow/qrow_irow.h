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

typedef struct BDRVIrowState { //
    BlockDriverState *irow_meta; // irow meta ����״̬
    BlockDriverState *irow_btmp; // irow bitmap����״̬
    BlockDriverState *irow_irvd; // irow ������̾�������״̬
    uint64_t disk_size; // �ֽ�
    uint64_t bitmap_size; // �ֽ�
    uint32_t cluster_size; // �ֽ�
    uint32_t cluster_bits; // clusterλ��
    uint64_t total_clusters; // ���̾����cluster����
    uint32_t sectors_per_cluster; // һ��cluster�е�sector����
    uint32_t nb_snapshots; // ���յĸ���
    uint32_t vm_state_size; // �����״̬��С
    uint32_t copy_on_demand; // ���追����־
    int open_flags; // ���̾���Ĵ򿪱�־
    IRowSnapshot *snapshots; // sanpshot���飬������Ԫ�صĸ���Ϊnb_snapshots��
    uint32_t snapshots_is_dirty; // ���ڱ���snapshots�����Ƿ���meta�ļ��е�һ��
    uint8_t *bitmap; // bitmap ����
    uint32_t bitmap_is_dirty; // ���ڱ���bitmap�Ƿ���btmp�ļ��е�һ��
    uint32_t vmstate_is_saved; // ���ڱ����Ƿ񱣴��vmstate��û�нض��ļ�
    uint32_t complete_image; // ���ڱ����Ƿ����е�cluster���ڵ�ǰ������
    char *meta_file; // meta�ļ�
    char *current_btmp_file; // ��ǰbitmap�ļ�����ָ������̵�ǰ��bitmap�ļ�
    char *father_btmp_file; // �򿪵�bitmap�ļ���Ӧ��"����"bitmap�ļ�
    char *opened_btmp_file; // �򿪵�bitmap�ļ������Ժ͵�ǰbitmap�ļ���ͬ�������"����"bitmap�ļ�ʱ
    char *irvd_file; // �򿪵�bitmap�ļ���Ӧ�Ĵ��̾����ļ�
} BDRVIrowState;

//��ŵ�������Ҫ���ڶ�д���� 
typedef struct BDRVQrowState 
{ 
    uint32_t cluster_size; 
    uint32_t sectors_per_cluster;
    uint64_t total_clusters; 
	uint64_t cluster_offset; 
	uint64_t byte_offset;
	uint64_t sector_offset;
	uint64_t map_file[MAX_VM_SECTOR_NUM]; 
	int img_file_fd;//�򿪵Ĵ����ļ� 
	int log_file_fd;//�򿪵�log�ļ� 
	int map_file_fd;//�򿪵Ĵ洢map������ļ� 
}BDRVQrowState;

typedef struct ClusterBuffer {
	uint8_t *buf;
	uint8_t *read_from_father;
} ClusterBuffer;

#define IROW_SNAPSHOT_OFFSET sizeof(IRowMeta)
#define MAX_MERGE_BUFFER 16 * 1024 * 1024 //ɾ�����պϲ�ʱ��󻺳�����С

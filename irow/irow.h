/* IROW��Improved ROW����ʽ���豸����
 * liuhq 2012
 * IROW��ʽʹ��ROW���COW�Ķ���д�Ŀ�����ͬʱʹ��COD���ROW���ļ���Ƭ����
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

typedef struct __attribute__((packed)) IRowMeta { // irow meta�ļ�ͷ
    uint32_t magic; // ħ��
    uint32_t version; // �汾
    uint32_t copy_on_demand; // ���追�����
    uint32_t nb_snapshots; // ���յĸ���
    uint32_t cluster_size; // cluster��С���ֽ�
    uint32_t cluster_bits; // cluster��λ��
    uint32_t sectors_per_cluster; // һ��cluster�е�sector����
    uint64_t total_clusters; // cluster�ĸ���
    uint64_t disk_size; // �����С���ֽ�
    char current_btmp[MAX_FILE_NAME_LENGTH]; // ��ǰbitmap�ļ�
    char backing_file[MAX_FILE_NAME_LENGTH]; // base image����
} IRowMeta;

typedef struct __attribute__((packed)) IRowSnapshotHeader {
	uint32_t snap_magic; // snapshot header��ħ��
	char id_str[128]; // ���յ�id��ÿ��������Ψһ��id
	char name[256]; // ���ƣ����߿������Ϊ˵������ͬ���յ�name������ͬ
	char btmp_file[MAX_FILE_NAME_LENGTH]; // �ÿ��ն�Ӧ��btmp�ļ�
	char irvd_file[MAX_FILE_NAME_LENGTH]; // �ÿ��ն�Ӧ��irvd�ļ�
	char father_btmp_file[MAX_FILE_NAME_LENGTH]; // "����"��Ӧ��btmp�ļ�
	uint32_t vm_state_size;
	uint32_t date_sec; // ����1970��1��1��00��00��00������
	uint32_t date_nsec; // ���ڵ�����������ȷ��1000��ʵ������΢������1000�õ���
	uint64_t vm_clock_nsec; // VM�������������
	uint32_t nb_children; // ���ӿ��ո���
	uint32_t is_deleted; // �Ƿ���ɾ����־
} IRowSnapshotHeader;

typedef struct IRowSnapshot {
	char *id_str;
	char *name;
	char *btmp_file;
	char *irvd_file;
	char *father_btmp_file;
	uint32_t vm_state_size;
	uint32_t date_sec; // ����1970��1��1��00��00��00������
	uint32_t date_nsec; // ���ڵ�����������ȷ��1000��ʵ������΢������1000�õ���
	uint64_t vm_clock_nsec; // VM�������������
	uint32_t nb_children; // ���ӿ��ո���
	uint32_t is_deleted; // �Ƿ���ɾ����־
} IRowSnapshot;

typedef struct IRowCreateState {
	uint64_t disk_size;
	uint32_t cluster_size;
	uint32_t cluster_bits;
	uint32_t copy_on_demand;
	char *meta_file; // meta�ļ�
	char *father_btmp_file; // �򿪵�bitmap�ļ���Ӧ��"����"bitmap�ļ�
	char *btmp_file; // Ҫ������bitmap�ļ�
	char *irvd_file; // Ҫ������bitmap�ļ���Ӧ��irvd�ļ�
	char *time_value; // �����ýṹ���ʱ��16�����ַ��������ԵĿ�����Ϊ�Ǵ������̾����ʱ�䣩�������ļ�����һ����
	char *backing_file; // base image�ļ���
} IRowCreateState;

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

typedef struct ClusterBuffer {
	uint8_t *buf;
	uint8_t *read_from_father;
} ClusterBuffer;

#define IROW_SNAPSHOT_OFFSET sizeof(IRowMeta)
#define MAX_MERGE_BUFFER 16 * 1024 * 1024 //ɾ�����պϲ�ʱ��󻺳�����С

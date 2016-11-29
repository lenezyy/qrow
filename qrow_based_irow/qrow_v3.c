/* QROW��ʽ���豸����
 * zyy 2016
 * */
#include "qemu-common.h"
#include "block_int.h"
#include "module.h"
#include "block/qrow_v3.h"

#include <linux/falloc.h>

#define QROW_DEBUG

#ifdef QROW_DEBUG
#define QROW_DEBUG_BEGIN_STR "\n----------------------------------------\n"
#define QROW_DEBUG_END_STR "\n========================================\n"

#define QROW_DEBUG_DETAIL

#ifdef QROW_DEBUG_DETAIL

//#define QROW_DEBUG_OPEN
//#define QROW_DEBUG_SET_BIT
#define QROW_DEBUG_ASSERT_CLUSTERS
//#define QROW_DEBUG_SNAPSHOT_DELETE
//#define QROW_DEBUG_READ
#define QROW_DEBUG_WRITE
//#define QROW_DEBUG_AIO_READV
//#define QROW_DEBUG_AIO_WRITEV


static void dump_QEMUIOVector(QEMUIOVector *qiov) {
	int i;
	printf("niov %d, nalloc %d, size %zd\n", qiov->niov, qiov->nalloc, qiov->size);
	for(i = 0; i < qiov->nalloc; i++) {
		printf("#%d I/O vector base %p, len %zd\n",i ,qiov->iov[i].iov_base, qiov->iov[i].iov_len);
		//dump_mem(qiov->iov[i].iov_base, qiov->iov[i].iov_len, "");
	}
}

#endif

#endif


static int qrow_probe(const uint8_t *buf, int buf_size, const char *filename)
{ // ���ħ�����汾�����
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_probe()\n");
	printf("buf_size: %d, filename: %s\n", buf_size, filename);
#endif

	const QRowMeta *qrow_meta = (const void *)buf;

    if (buf_size >= sizeof(QRowMeta) &&
        be32_to_cpu(qrow_meta->magic) == QROW_MAGIC &&
        be32_to_cpu(qrow_meta->version) == QROW_VERSION){
#ifdef QROW_DEBUG
	printf("return 100" QROW_DEBUG_END_STR);
#endif
        return 100;
    }
    else {
#ifdef QROW_DEBUG
	printf("return 0" QROW_DEBUG_END_STR);
#endif
        return 0;
    }
}

static int qrow_update_map_file(BDRVQrowState *bqrows) {

	int ret = 0;
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_update_map_file()\n");
	printf("map_is_dirty %d\n", bqrows->map_is_dirty);
#endif
	if(bqrows->map_is_dirty) {
		if(bdrv_pwrite(bqrows->qrow_map_file, 0, bqrows->map, bqrows->map_size*sizeof(uint64_t) ) != bqrows->map_size*sizeof(uint64_t)) {
			fprintf(stderr, "Failed to write the qrow map data to %s\n", bqrows->map_file);
			ret = -1;
			goto end;
		}
		bqrows->map_is_dirty = 0;
		// bdrv_pwrite�ǰ�sectorд�룬�ļ�������sector�Ļ���Ҫ�ض�
		ret = bdrv_truncate(bqrows->qrow_map_file, bqrows->map_size*sizeof(uint64_t));
		
	}
	
end:
#ifdef QROW_DEBUG
	printf("qrow_update_map_file()return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int qrow_update_meta_file(BDRVQrowState *bqrows) {
	QRowMeta meta;
	int ret = 0;
	if(bdrv_pread (bqrows->qrow_meta_file, 0, &meta, sizeof(meta)) != sizeof(meta)) {
			fprintf (stderr, "Failed to read the meta data from %s\n", bqrows->meta_file);
			ret = -1;
			goto end;
	}
	meta.sector_offset = cpu_to_be64(bqrows->sector_offset);
	if(bdrv_pwrite(bqrows->qrow_meta_file, 0, &meta, sizeof(meta)) != sizeof(meta)) {
		fprintf (stderr, "Failed to write the meta data to %s\n", bqrows->meta_file);
		ret = -1;
		goto end;
	}

end:
#ifdef QROW_DEBUG
	printf("qrow_update_meta()return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}


static void qrow_close(BlockDriverState *bs) {

	BDRVQrowState *s = bs->opaque;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_close\n");
#endif
	if(s->map) {
#ifdef QROW_DEBUG
		printf("free map \n");
#endif
		qemu_free(s->map);
		s->map = NULL;
	}
	if(s->meta_file) {
#ifdef QROW_DEBUG
		printf("free meta_file (%s)\n", s->meta_file);
#endif
		qemu_free(s->meta_file);
		s->meta_file = NULL;
	}
	if(s->data_file) {
#ifdef QROW_DEBUG
		printf("free data_file (%s)\n", s->data_file);
#endif
		qemu_free(s->data_file);
		s->data_file = NULL;
	}
	if(s->map_file) {
#ifdef QROW_DEBUG
		printf("free map_file (%s)\n", s->map_file);
#endif
		qemu_free(s->map_file);
		s->map_file = NULL;
	}
/*  log_file
	if(s->log_file) {
#ifdef QROW_DEBUG
		printf("free log_file (%s)\n", s->log_file);
#endif
		qemu_free(s->log_file);
		s->log_file = NULL;
	}
*/
	if(s->qrow_meta_file) {
#ifdef QROW_DEBUG
		printf("delete qrow_meta_file\n");
#endif
		bdrv_delete(s->qrow_meta_file);
		s->qrow_meta_file = NULL;
	}
	
	if(s->qrow_data_file) {
#ifdef QROW_DEBUG
		printf("delete qrow_data_file\n");
#endif
		bdrv_delete(s->qrow_data_file);
		s->qrow_data_file = NULL;
	}
	if(s->qrow_map_file) {
#ifdef QROW_DEBUG
		printf("delete qrow_map_file\n");
#endif
		bdrv_delete(s->qrow_map_file);
		s->qrow_map_file = NULL;
	}
	
/*
	if(s->qrow_log_file) {
#ifdef QROW_DEBUG
		printf("delete qrow_log_file\n");
#endif
		bdrv_delete(s->qrow_log_file);
		s->qrow_log_file = NULL;
	}
*/

#ifdef QROW_DEBUG
	printf("qrow_close() return" QROW_DEBUG_END_STR);
#endif
}
static int qrow_open_data_file(BDRVQrowState *bqrows, int flags) {

	int ret = 0;
#ifdef IROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open_data_file()\n");
#endif
	// ��data_file�ļ�
	if(bqrows->data_file == NULL || bqrows->data_file[0] == '\0') {
		fprintf (stderr, "Void data file name\n");
		ret = -1;
		goto end;
	}
	bqrows->qrow_data_file = bdrv_new ("");
	ret = bdrv_file_open(&bqrows->qrow_data_file, bqrows->data_file, flags);
	if (ret < 0) {
		ret = -1;
		goto end;
	}
	
end:
#ifdef IROW_DEBUG
	printf("qrow_open_data_file() return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}
static int qrow_open_map_file(BDRVQrowState *bqrows, int flags) {

	int ret = 0;
#ifdef IROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open_map_file()\n");
#endif
	// ��map_file�ļ�
	if(bqrows->map_file == NULL || bqrows->map_file[0] == '\0') {
		fprintf (stderr, "Void map file name\n");
		ret = -1;
		goto end;
	}
	bqrows->qrow_map_file = bdrv_new ("");
	ret = bdrv_file_open(&bqrows->qrow_map_file, bqrows->map_file, flags);
	if (ret < 0) {
		ret = -1;
		goto end;
	}
	bqrows->map = qemu_mallocz(bqrows->map_size*sizeof(uint64_t));
	if(bdrv_pread(bqrows->qrow_map_file, 0, bqrows->map, bqrows->map_size*sizeof(uint64_t)) != bqrows->map_size*sizeof(uint64_t)) {
		fprintf(stderr, "Failed to read map_file from %s\n", bqrows->map_file);
		ret = -1;
		goto end;
	}
	bqrows->map_is_dirty = 0;
	ret = 0;	
end:
#ifdef IROW_DEBUG
	printf("qrow_open_map_file() return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}
static int qrow_open_meta_file(BlockDriverState *bs, BDRVQrowState *bqrows, const char *filename, int flags) {
	int ret = 0;
	QRowMeta meta;
#ifdef 	QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open_meta_file()\n");
#endif

	bqrows->qrow_meta_file = bdrv_new ("");
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open_meta_file() 00\n");
	//��raw�ķ�ʽ�򿪾����ļ��Ļ������յ��õľ���qemu_open() ����������open()
	ret = bdrv_file_open(&bqrows->qrow_meta_file, filename, flags);
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open_meta_file() 01\n");
	if (ret < 0) {
		fprintf (stderr, "Failed to open %s\n", filename);
		goto end;
	}
	if (bdrv_pread (bqrows->qrow_meta_file, 0, &meta, sizeof(meta)) != sizeof(meta)) {
		fprintf (stderr, "Failed to read the QROW meta data from %s\n", filename);
		ret = -1;
		goto end;
	}
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open_meta_file() 02\n");
	be32_to_cpus(&meta.magic);
	be32_to_cpus(&meta.version);
	be64_to_cpus(&meta.total_sectors);
	be64_to_cpus(&meta.disk_size);
	be64_to_cpus(&meta.sector_offset);
#ifdef IROW_DEBUG_DETAIL
	printf("meta.magic: %x\n", meta.magic);
	printf("meta.version: %x\n", meta.version);
	printf("meta.total_sectors: 0x%" PRIx64 "(%" PRId64 ")\n", meta.total_sectors, meta.total_sectors);
	printf("meta.disk_size: 0x%" PRIx64 "(%" PRId64 "M)\n", meta.disk_size, meta.disk_size / (1024 * 1024));
	printf("meta.sector_offset: 0x%\n", meta.sector_offset);
#endif

	if(meta.magic != QROW_MAGIC || meta.version != QROW_VERSION) {
		fprintf (stderr, "Invalid magic number or version number!\n");
		ret = -1;
		goto end;
	}
	bqrows->total_sectors = meta.total_sectors;
	bqrows->disk_size = meta.disk_size;
	bs->total_sectors = meta.total_sectors;
	/* //û�취ʹ��lseek�������
	int fd = open(filename, O_RDWR|O_BINARY, 0333);//�򿪴����ļ�
	if (fd < 0) 
	{
		printf("Can not open %s\n", filename);
		return 0;
	}
	uint64_t cur_disk_size = lseek(fd, 0, SEEK_END);//�Ȼ�ȡ�ļ���С
	lseek(fd, 0, SEEK_SET);//����дλ���ƶ����ļ���ͷ�� 
	uint64_t cur_cluster_offset = (cur_disk_size % s->cluster_size == 0) ? (cur_disk_size / s->cluster_size) : (cur_disk_size / s->cluster_size+1);
	s->cluster_offset = (s->cluster_offset < cur_cluster_offset) ? cur_cluster_offset : s->cluster_offset;
	*/
	bqrows->sector_offset = meta.sector_offset;
	bqrows->byte_offset = bqrows->sector_offset * BDRV_SECTOR_SIZE;
	bqrows->map_size = meta.disk_size / BDRV_SECTOR_SIZE;
	bqrows->meta_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
	strncpy(bqrows->meta_file, filename, MAX_FILE_NAME_LENGTH);
	bqrows->map_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
	strncpy(bqrows->map_file, meta.map_file, MAX_FILE_NAME_LENGTH);
	bqrows->data_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
	strncpy(bqrows->data_file, meta.data_file, MAX_FILE_NAME_LENGTH);
	strncpy(bs->backing_file, meta.backing_file, sizeof(bs->backing_file));
	//log_file��û�����ģ�
	
#ifdef IROW_DEBUG
	printf("backing_file \"%s\"\n", bs->backing_file);
#endif
end:
#ifdef IROW_DEBUG
	printf("qrow_open_meta_file() return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}
static int qrow_open(BlockDriverState *bs, const char *filename, int flags) {
    BDRVQrowState *s = bs->opaque;
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open()\n");
	//printf("filename: %s, flags: %d\n", filename, flags);
#endif
#ifdef QROW_DEBUG_OPEN
	printf("press Enter to continue...\n");
	getchar();
#endif
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open() 00\n");
	s->open_flags = flags;
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open() 01\n");
	//��meta_file����ȡԪ������Ϣ
	if(qrow_open_meta_file(bs, s, filename, flags) < 0) {
    	fprintf (stderr, "Failed to open %s\n", filename);
    	goto fail;
    }
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open() 02\n");
	// �ٴ�map_file�ļ�
    if(qrow_open_map_file(s, flags) < 0) {
    	goto fail;
    }
    
    // �ٴ�data_file�ļ�
    if(qrow_open_data_file(s, flags) < 0) {
    	goto fail;
    }
#ifdef QROW_DEBUG 
    printf("qrow_open return 0" QROW_DEBUG_END_STR);
#endif
    return 0;

fail:
#ifdef QROW_DEBUG 
	printf("qrow_open return -1" QROW_DEBUG_END_STR);
#endif
	qrow_close (bs);
	return -1;
}

static int qrow_read(BlockDriverState *bs, int64_t sector_num, uint8_t *buf, int nb_sectors) {
	int ret = 0;
	BDRVQrowState *s = bs->opaque;
	uint64_t sector_offset;
	int64_t i = sector_num;
	int j = 0, k = 0;
	for (; k < nb_sectors; i++,k++) 
	{
		sector_offset = s->map[i];//��map�����л�ȡ���������������ϵĴ洢������
		//bqrows->map[i]Ϊ0ʱ��Ҫô�Ǳ�ʾ���̾����metaԪ����ռ�ݵĵ�һ��sector��Ҫô��ʾ����������������Ϊ��
		if(sector_offset == 0) //�ô�������Ϊ��(0)����Ϊheader����
		{
			continue; 
		} 
		else
		{
		 	if(bdrv_pread(s->qrow_data_file, sector_offset*BDRV_SECTOR_SIZE, buf+j*BDRV_SECTOR_SIZE, BDRV_SECTOR_SIZE) != BDRV_SECTOR_SIZE) {
				fprintf (stderr, "Failed to read the  data from %s\n", s->data_file);
				ret = -1;
				goto end;
			}
			j++;				
		}			
	}		
	end:
#ifdef IROW_DEBUG
	printf("qrow_read return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;

}
static int qrow_write(BlockDriverState *bs, int64_t sector_num, const uint8_t *buf, int nb_sectors) {
	BDRVQrowState *s = bs->opaque;
	int64_t sector_offset;
	int ret = 0;
	
	if (s->sector_offset >= s->total_sectors){ //��������
		fprintf (stderr, "img is full!\n");
		ret = -1;
		goto end;
	}
	if (s->sector_offset + nb_sectors > s->total_sectors){ //д�����򳬳��������Χ
		fprintf (stderr, "Invalid nb_sectors!\n");
		ret = -1;
		goto end;
	}
	if(bdrv_pwrite(s->qrow_data_file,s->byte_offset, buf, nb_sectors*BDRV_SECTOR_SIZE) != nb_sectors*BDRV_SECTOR_SIZE) {
		fprintf(stderr, "Failed to write \n");
		ret = -1;
		goto end;
	}
	sector_offset = s->sector_offset;
	
	int64_t i = sector_num;
	int j = 0;
	for ( ; j < nb_sectors; i++, j++) //����map�����ֵ��������������̺��������̵�����ӳ���ϵ 
	{
			s->map[i] = sector_offset;
			sector_offset++;
	}
	s->map_is_dirty = 1;
	// ����map_file�ļ������map�����ֵ
	if(qrow_update_map_file(s) < 0) {
		fprintf (stderr, "Failed to update map_file. (%s)\n", s->map_file);
		ret = -1;
		goto end;
	}
	
	s->sector_offset += nb_sectors;
	s->byte_offset = s->sector_offset * BDRV_SECTOR_SIZE;
	// ����meta_file�ļ������meta����offset��ֵ
	if(qrow_update_meta_file(s) < 0) {
		fprintf (stderr, "Failed to update meta_file. (%s)\n", s->meta_file);
		ret = -1;
		goto end;
	}

end:
	
#ifdef QROW_DEBUG
	printf("qrow_write return %d" QROW_DEBUG_END_STR, ret);
#endif

	return ret;
}

static int qrow_generate_filename(char *dest, const char *prefix, const char *suffix) {
	// dst = prefix-body.suffix
	if(strlen(prefix) + strlen(suffix) + 1 >= MAX_FILE_NAME_LENGTH) {
		fprintf(stderr, "Invalid filename length, max is %d\n", MAX_FILE_NAME_LENGTH);
		return -1;
	}
	strcpy(dest, prefix);
	strcat(dest, ".");
	strcat(dest, suffix);
	return 0;
}

static int qrow_create(const char *filename, QEMUOptionParameter *options) {
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_create()\n");
#endif
	QRowMeta meta;
	uint64_t disk_size;
	char *backing_file = NULL;
	int ret = 0;
	// ��������
	//printf(QROW_DEBUG_BEGIN_STR "We are in qrow_create() 00\n");
	while (options && options->name) {
		if (!strcmp(options->name, BLOCK_OPT_SIZE)) {
				disk_size= options->value.n;
			}else if (!strcmp(options->name, BLOCK_OPT_BACKING_FILE)) {
	            backing_file = options->value.s;
			} 
	        options++;
	}
	//	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_create() 01\n");
	//�жϲ���
	if (disk_size == 0) 
	{
		fprintf(stderr, "Invalid disk_size\n");
		ret = -1;
		goto end;
	}
	if(filename[0] == '\0') {
	   fprintf(stderr, "Void img file name\n");
	   ret = -1;
	   goto end;
   	} 
	//printf(QROW_DEBUG_BEGIN_STR "We are in qrow_create() 02\n");
	// �����Ԫ����ͷ��Ҫ��������Ϣ
    memset(&meta, 0, sizeof(meta));
    meta.magic = cpu_to_be32(QROW_MAGIC);	
	meta.version = cpu_to_be32(QROW_VERSION);
	meta.disk_size = cpu_to_be64(disk_size);
   	meta.total_sectors = cpu_to_be64(disk_size/BDRV_SECTOR_SIZE); // ���̾����ܵ�sector����
	meta.sector_offset = cpu_to_be64(0);//��ʼλ��Ϊ0 
    strncpy(meta.meta_file, filename, MAX_FILE_NAME_LENGTH);
    //printf(QROW_DEBUG_BEGIN_STR "We are in qrow_create() 05\n");
    if(backing_file != NULL) {
   		strncpy(meta.backing_file, backing_file, MAX_FILE_NAME_LENGTH);//���������ô�ã����� 
   	}
	//printf(QROW_DEBUG_BEGIN_STR "We are in qrow_create() 055\n");
	if(qrow_generate_filename(meta.map_file, meta.meta_file, "map") < 0) { // map_file�ļ�
   		ret = -1;
   		goto end;
   	}
   	if(qrow_generate_filename(meta.data_file, meta.meta_file, "data") < 0) { // map_file�ļ�
   		ret = -1;
   		goto end;
   	}
   	
	//��Ԫ����д�뵽meta�ļ��� 
	int fd;	
	fd = open(meta.meta_file, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY,0644);
	//printf(QROW_DEBUG_BEGIN_STR "We are in qrow_create() 06 %d\n",fd);
	if (fd < 0) 
	{
		fprintf(stderr, "Can not open %s\n", meta.meta_file);
		ret = -1;
		goto end;
	}

	//printf(QROW_DEBUG_BEGIN_STR "We are in qrow_create()  07\n");
	
	uint64_t writeByets = write(fd, &meta, sizeof(meta)); 
	if(writeByets != sizeof(meta))
	{
		fprintf(stderr, "Can not write meta \n");
		ret = -1;
		goto end;
	}
	
	if(close(fd) != 0) {
		fprintf(stderr, "Can not close %s\n", meta.meta_file);
   		ret = -1;
		goto end;
   	}

	//��������ʼ��map_file�ļ�
	int map_file_fd;
	
	uint64_t *map = NULL;
	uint64_t map_size = disk_size/BDRV_SECTOR_SIZE;
	map = qemu_mallocz(map_size*sizeof(uint64_t));
	memset(map, 0, map_size*sizeof(uint64_t));
	map_file_fd = open(meta.map_file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
   	if(map_file_fd < 0) {
		fprintf(stderr, "Can not open %s\n", meta.map_file);
		ret = -1;
		goto end;
	}
	write(map_file_fd, map,map_size*sizeof(uint64_t));

	if(close(map_file_fd) != 0) {
		fprintf(stderr, "Can not close %s\n", meta.map_file);
		ret = -1;
		goto end;
	}
	
	//������data_file�ļ�
	int data_file_fd;
	data_file_fd = open(meta.data_file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
   	if(data_file_fd < 0) {
		fprintf(stderr, "Can not open %s\n", meta.data_file);
		ret = -1;
		goto end;
	}
	if(fallocate(data_file_fd, FALLOC_FL_KEEP_SIZE, 0, disk_size) < 0) {
		;//fprintf(stderr, "Can not preallocate disk space for %s\n(Preallocation is not supported on ext3)\n", cs->irvd_file);
	}
	if (ftruncate(data_file_fd, disk_size) != 0) {
		fprintf(stderr, "Can not truncate %s to %" PRId64 " bytes\n", meta.data_file, disk_size);
		ret = -1;
	}

	if(close(data_file_fd) != 0) {
		fprintf(stderr, "Can not close %s\n", meta.data_file);
		ret = -1;
		goto end;
	}
	
end:
#ifdef QROW_DEBUG
	printf("qrow_create() return %d" QROW_DEBUG_END_STR, ret);
#endif
	if(map != NULL)
	{
		qemu_free(map);
		map = NULL;
	}
	
	return ret;
}

static void qrow_flush(BlockDriverState *bs) {
	BDRVQrowState *s = bs->opaque;

	bdrv_flush(s->qrow_meta_file);
	//bdrv_flush(s->qrow_map_file);
	//bdrv_flush(s->qrow_data_file);
	//bdrv_flush(s->qrow_log_file);
}

typedef struct QRowAIOCB {
    BlockDriverAIOCB common;
    int64_t sector_num;
    QEMUIOVector *qiov;
    int nb_sectors;
    BlockDriverAIOCB *irvd_aiocb;

} QRowAIOCB;

static void qrow_aio_cancel(BlockDriverAIOCB *blockacb)
{
	QRowAIOCB *acb = (QRowAIOCB *)blockacb;
    if (acb->irvd_aiocb)
        bdrv_aio_cancel(acb->irvd_aiocb);
    qemu_aio_release(acb);
}

static AIOPool qrow_aio_pool = {
    .aiocb_size         = sizeof(QRowAIOCB),
    .cancel             = qrow_aio_cancel,
};


static QRowAIOCB* qrow_aio_setup(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    QRowAIOCB *acb;

    acb = qemu_aio_get(&qrow_aio_pool, bs, cb, opaque);
    if (!acb)
        return NULL;
    acb->irvd_aiocb = NULL;
    acb->sector_num = sector_num;
    acb->qiov = qiov;
    acb->nb_sectors = nb_sectors;
    return acb;
}

static void qrow_aio_readv_cb(void *opaque, int ret) {
	QRowAIOCB *acb = opaque;
	BlockDriverState *bs = acb->common.bs;
	BDRVQrowState *bqrows = bs->opaque;
	void *buf = NULL;
	
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_aio_readv_cb()\n");
#endif
	if(ret < 0) {
		fprintf(stderr, "aio_readv failed\n");
		goto end;
	}
	uint64_t sector_offset;
	buf = qemu_mallocz(acb->qiov->size);
	qemu_iovec_to_buffer(acb->qiov, buf);
	int64_t i = acb->sector_num;
	int j = 0, k = 0;
	for (; k < acb->nb_sectors; i++,k++)  
	{
		sector_offset = bqrows->map[i];//��map�����л�ȡ���������������ϵĴ洢������
		//bqrows->map[i]Ϊ0ʱ��Ҫô�Ǳ�ʾ���̾����metaԪ����ռ�ݵĵ�һ��sector��Ҫô��ʾ����������������Ϊ��
		if(sector_offset == 0) //�ô�������Ϊ��(0)
		{
			continue; 
		} 
		else
		{
		 	if(bdrv_pread(bqrows->qrow_data_file, sector_offset*BDRV_SECTOR_SIZE, buf+j*BDRV_SECTOR_SIZE, BDRV_SECTOR_SIZE) != BDRV_SECTOR_SIZE) {
				fprintf (stderr, "Failed to read the  data from %s\n", bqrows->data_file);
				ret = -1;
				goto end;
			}
			j++;				
		}				
	}		
	qemu_iovec_from_buffer(acb->qiov, buf, acb->qiov->size);		
	end:
		if(buf != NULL) {
			qemu_free(buf);
			buf = NULL;
		}
	    acb->common.cb(acb->common.opaque, ret);
	    qemu_aio_release(acb);
#ifdef QROW_DEBUG
   printf("qrow_aio_readv_cb() return" QROW_DEBUG_END_STR);
#endif
}

static BlockDriverAIOCB *qrow_aio_readv(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque) {
    QRowAIOCB *acb;
    BDRVQrowState *bqrows = bs->opaque;
    BlockDriver *drv;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_aio_readv()\n");
	printf("sector_num %" PRId64 ", nb_sectors %d\n", sector_num, nb_sectors);
#endif
#ifdef QROW_DEBUG_DETAIL
	dump_QEMUIOVector(qiov);
#endif
#ifdef QROW_DEBUG_AIO_READV
	printf("press Enter to continue...\n");
	getchar();
#endif

    acb = qrow_aio_setup(bs, sector_num, qiov, nb_sectors, cb, opaque);
    if (!acb)
        return NULL;
	drv = bqrows->qrow_data_file->drv;
	//ע�������sector_num�����ǳ�������Ҫ�ط�
	acb->irvd_aiocb = drv->bdrv_aio_readv(bqrows->qrow_data_file, sector_num, qiov, nb_sectors, qrow_aio_readv_cb, acb);
	if(acb->irvd_aiocb == NULL){
		qemu_aio_release(acb);
#ifdef QROW_DEBUG
   printf("qrow_aio_readv() return NULL" QROW_DEBUG_END_STR);
#endif
		return NULL;
	}


#ifdef QROW_DEBUG
   printf("qrow_aio_readv() return %p" QROW_DEBUG_END_STR, &acb->common);
#endif
   return &acb->common;
}

static BlockDriverAIOCB *qrow_aio_writev(BlockDriverState *bs,
    int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
    BlockDriverCompletionFunc *cb, void *opaque) {
	BDRVQrowState *s = bs->opaque;
	BlockDriverAIOCB *ret = NULL;
	BlockDriver *drv;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_aio_writev()\n");
	printf("sector_num %" PRId64 ", nb_sectors %d", sector_num, nb_sectors);
#endif
#ifdef QROW_DEBUG_DETAIL
	dump_QEMUIOVector(qiov);
#endif
#ifdef QROW_DEBUG_AIO_WRITEV
	printf("press Enter to continue...\n");
	getchar();
#endif
	int64_t sector_offset;
	if (s->sector_offset >= s->total_sectors){ //��������
		fprintf (stderr, "img is full!\n");
		goto end;
	}
	if (s->sector_offset + nb_sectors > s->total_sectors){ //д�����򳬳��������Χ
		fprintf (stderr, "Invalid nb_sectors!\n");
		goto end;
	}
	//����map����
	sector_offset = s->sector_offset;
	int64_t i = sector_num;
	int j = 0;
	//for (int j = 0; j < nb_sectors; i++, j++) //����map�����ֵ��������������̺��������̵�����ӳ���ϵ 
	for (; j < nb_sectors; i++, j++)//��linux�б���ʱ˵������for�н��г�ʼ�� 
	{
			s->map[i] = sector_offset;
			sector_offset++;
	}
	s->map_is_dirty = 1;
	
	drv = s->qrow_meta_file->drv;
	ret = drv->bdrv_aio_writev(s->qrow_data_file, s->sector_offset, qiov, nb_sectors, cb, opaque );
	if(ret == NULL) {
	   goto end;
	}
	
	
	// ����map_file�ļ������map�����ֵ
	if(qrow_update_map_file(s) < 0) {
		fprintf (stderr, "Failed to update map_file. (%s)\n", s->map_file);
		goto end;
	}
	
	s->sector_offset += nb_sectors;
	s->byte_offset = s->sector_offset * BDRV_SECTOR_SIZE;
	// ����meta_file�ļ������meta����offset��ֵ
	if(qrow_update_meta_file(s) < 0) {
		fprintf (stderr, "Failed to update meta_file. (%s)\n", s->meta_file);
		goto end;
	}
end:
	
#ifdef QROW_DEBUG
   printf("qrow_aio_writev() return %p" QROW_DEBUG_END_STR, ret);
#endif
   return ret;
}

static BlockDriverAIOCB *qrow_aio_flush(BlockDriverState *bs,
        BlockDriverCompletionFunc *cb, void *opaque) {
	BDRVQrowState *s = bs->opaque;
	BlockDriverAIOCB *ret = NULL;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_aio_flush()\n");
#endif

	ret = bdrv_aio_flush(s->qrow_meta_file, cb, opaque);

#ifdef QROW_DEBUG
	printf("qrow_aio_flush() return %p\n" QROW_DEBUG_END_STR, ret);
#endif

	return ret;
}

static int qrow_get_info(BlockDriverState *bs, BlockDriverInfo *bdi) {
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_get_info()\n");
#endif
	//BDRVQrowState *s = bs->opaque;
	//bdi->cluster_size = s->cluster_size;
	//bdi->vm_state_offset = qrow_vm_state_offset(s);
#ifdef QROW_DEBUG
	printf("return from qrow_get_info()" QROW_DEBUG_END_STR);
#endif
	return 0;
}


static int64_t qrow_get_length(BlockDriverState *bs) {
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_get_lenght()\n");
#endif
	BDRVQrowState *bqrows = bs->opaque;
	int64_t ret;
	ret = bqrows->disk_size;
#ifdef QROW_DEBUG
	printf("qrow_get_lenght() return %" PRId64 QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static QEMUOptionParameter qrow_create_options[] = {
    {
        .name = BLOCK_OPT_SIZE,
        .type = OPT_SIZE,
        .help = "Virtual disk size"
    },
    {
        .name = BLOCK_OPT_BACKING_FILE,
        .type = OPT_STRING,
        .help = "File name of a base image"
    },
    /*
    {
        .name = "copy_on_demand",
        .type = OPT_FLAG,
        .help = "copy clusters to current irvd when needed"
    },
	*/
    { NULL }
};

static BlockDriver bdrv_qrow = {
    .format_name	= "qrow",
    .instance_size	= sizeof(BDRVQrowState),
    .bdrv_probe		= qrow_probe,
    .bdrv_open		= qrow_open,
    .bdrv_read		= qrow_read,
    .bdrv_write		= qrow_write,
    .bdrv_close		= qrow_close,
    .bdrv_create	= qrow_create,
    .bdrv_flush		= qrow_flush,

    .bdrv_aio_readv		= qrow_aio_readv,
    .bdrv_aio_writev	= qrow_aio_writev,
    .bdrv_aio_flush		= qrow_aio_flush,
 
    .bdrv_get_info	= qrow_get_info,
    .bdrv_getlength = qrow_get_length,
    .create_options = qrow_create_options,

};

static void bdrv_qrow_init(void)
{
    bdrv_register(&bdrv_qrow);
}

block_init(bdrv_qrow_init);
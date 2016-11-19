/* qrow（Improved ROW）格式块设备驱动
 * liuhq 2012
 * qrow格式使用ROW解决COW的额外写的开销，同时使用COD解决ROW的文件碎片问题
 * */

#include "qemu-common.h"
#include "block_int.h"
#include "module.h"
#include "block/qrow.h"

#include <linux/falloc.h>

//#define QROW_DEBUG

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

static int get_bits_from_size(size_t size)
{ // 如果size=2^n，那么返回n，否则返回－1
    int ret = 0;
    if (size == 0) {
        return -1;
    }
    while (size != 1) {
    	if (size & 1) {// 不是2的幂
    		return -1;
        }
        size >>= 1;
        ret++;
    }
    return ret;
}

static int qrow_probe(const uint8_t *buf, int buf_size, const char *filename)
{ // 检测魔数、版本并打分
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

static int qrow_update_map_file(BDRVqrowState *bqrows) {

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
		// bdrv_pwrite是按sector写入，文件不是整sector的话需要截断
		ret = bdrv_truncate(bqrows->qrow_map_file, bqrows->map_size*sizeof(uint64_t));
		
	}
	
end:
#ifdef QROW_DEBUG
	printf("qrow_update_map_file()return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int qrow_update_img_file(BDRVqrowState *bqrows) {
	QRowMeta meta;
	int ret = 0;
	if(bdrv_pread (bqrows->qrow_img_file, 0, &meta, sizeof(meta)) != sizeof(meta)) {
			fprintf (stderr, "Failed to read the meta data from %s\n", bqrows->qrow_img_file);
			ret = -1;
			goto end;
	}
	meta.cluster_offset = cpu_to_be64(bqrows->cluster_offset);
	if(bdrv_pwrite(bqrows->qrow_img_file, 0, &meta, sizeof(meta)) != sizeof(meta)) {
		fprintf (stderr, "Failed to write the meta data to %s\n", bqrows->img_file);
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
	if(s->img_file) {
#ifdef QROW_DEBUG
		printf("free img_file (%s)\n", s->img_file);
#endif
		qemu_free(s->img_file);
		s->img_file = NULL;
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
	if(s->qrow_img_file) {
#ifdef QROW_DEBUG
		printf("delete qrow_img_file\n");
#endif
		bdrv_delete(s->qrow_img_file);
		s->qrow_img_file = NULL;
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

static int qrow_open_map_file(BDRVIrowState *bqrows, int flags) {

	int ret = 0;
#ifdef IROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open_map_file()\n");
#endif
	// 打开map_file文件
	if(bqrows->map_file == NULL || bqrows->map_file[0] == '\0') {
		fprintf (stderr, "Void btmp file name\n");
		ret = -1;
		goto end;
	}
	bqrows->qrow_map_file = bdrv_new ("");
	ret = bdrv_file_open(&bqrows->qrow_map_file, bqrows->map_file, flags);
	if (ret < 0) {
		ret = -1;
		goto end;
	}
	bqrows->map = qemu_malloc(bqrows->map_size*sizeof(uint64_t));
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
static int qrow_open_img_file(BlockDriverState *bs, BDRVQrowState *bqrows, const char *filename, int flags) {
	int ret = 0;
	QRowMeta meta;


#ifdef IROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open_img_file()\n");
#endif

	bqrows->qrow_img_file = bdrv_new ("");
	//用raw的方式打开镜像文件的话，最终调用的就是qemu_open() 里面正常的open()
	ret = bdrv_file_open(&bqrows->qrow_img_file, filename, flags);
	if (ret < 0) {
		fprintf (stderr, "Failed to open %s\n", filename);
		goto end;
	}
	if (bdrv_pread (bqrows->qrow_img_file, 0, &meta, sizeof(meta)) != sizeof(meta)) {
		fprintf (stderr, "Failed to read the QROW meta data from %s\n", filename);
		ret = -1;
		goto end;
	}
	be32_to_cpus(&meta.magic);
	be32_to_cpus(&meta.version);
	be32_to_cpus(&meta.cluster_size);
	be32_to_cpus(&meta.cluster_bits);
	be32_to_cpus(&meta.sectors_per_cluster);
	be64_to_cpus(&meta.total_clusters);
	be64_to_cpus(&meta.disk_size);
	be64_to_cpus(&meta.cluster_offset);
#ifdef IROW_DEBUG_DETAIL
	printf("meta.magic: %x\n", meta.magic);
	printf("meta.version: %x\n", meta.version);
	printf("meta.cluster_size: 0x%x(%dK)\n", meta.cluster_size, meta.cluster_size / 1024);
	printf("meta.cluster_bits: %d\n", meta.cluster_bits);
	printf("meta.total_clusters: 0x%" PRIx64 "(%" PRId64 ")\n", meta.total_clusters, meta.total_clusters);
	printf("meta.sectors_per_cluster: %d\n", meta.sectors_per_cluster);
	printf("meta.disk_size: 0x%" PRIx64 "(%" PRId64 "M)\n", meta.disk_size, meta.disk_size / (1024 * 1024));
	printf("meta.cluster_offset: 0x%\n", meta.cluster_offset);
#endif

	if(meta.magic != IROW_MAGIC || meta.version != IROW_VERSION) {
		fprintf (stderr, "Invalid magic number or version number!\n");
		ret = -1;
		goto end;
	}
	// 判断cluster大小是否合法
	if((meta.cluster_bits < MIN_CLUSTER_BITS) || (meta.cluster_bits > MAX_CLUSTER_BITS)) {
		fprintf (stderr, "Invalid cluster_bits!\n");
		ret = -1;
		goto end;
	}
	// 判断cluster_size和cluster_bits是否匹配
	if(meta.cluster_bits != get_bits_from_size(meta.cluster_size)) {
		fprintf (stderr, "cluster_size and cluster_bits do not match!\n");
		ret = -1;
		goto end;
	}
	// 判断total_clusters和disk_size是否匹配
	if(meta.total_clusters != ((meta.disk_size + meta.cluster_size - 1) >> meta.cluster_bits)) {
		fprintf (stderr, "total_clusters and disk_size do not match!\n");
		ret = -1;
		goto end;
	}
	// 判断sectors_per_cluster是否合法
	if(meta.sectors_per_cluster != (meta.cluster_size >> BDRV_SECTOR_BITS)) {
		fprintf (stderr, "Invalid sectors_per_cluster!\n");
		ret = -1;
		goto end;
	}
	bqrows->cluster_size = meta.cluster_size;
	bqrows->cluster_bits = meta.cluster_bits;
	bqrows->total_clusters = meta.total_clusters;
	bqrows->sectors_per_cluster = meta.sectors_per_cluster;
	bqrows->disk_size = meta.disk_size;
	bs->total_sectors = meta.disk_size / BDRV_SECTOR_SIZE;
	/* //没办法使用lseek这个函数
	int fd = open(filename, O_RDWR|O_BINARY, 0333);//打开磁盘文件
	if (fd < 0) 
	{
		printf("Can not open %s\n", filename);
		return 0;
	}
	uint64_t cur_disk_size = lseek(fd, 0, SEEK_END);//先获取文件大小
	lseek(fd, 0, SEEK_SET);//将读写位置移动到文件开头处 
	uint64_t cur_cluster_offset = (cur_disk_size % s->cluster_size == 0) ? (cur_disk_size / s->cluster_size) : (cur_disk_size / s->cluster_size+1);
	s->cluster_offset = (s->cluster_offset < cur_cluster_offset) ? cur_cluster_offset : s->cluster_offset;
	*/
	bqrows->cluster_offset = meta.cluster_offset；
	bqrows->byte_offset = bqrows->cluster_offset * bqrows->cluster_size;
	bqrows->sector_offset = bqrows->cluster_offset * bqrows->sectors_per_cluster;
	bqrows->meta_cluster = if(sizeof(meta) % meta.cluster_size == 0 )? (sizeof(meta) / meta.cluster_size): (sizeof(meta) / meta.cluster_size + 1);
	bqrows->map_size = meta.disk_size / BDRV_SECTOR_SIZE;
	bqrows->img_file = qemu_malloc(MAX_FILE_NAME_LENGTH);
	strncpy(bqrows->img_file, filename, MAX_FILE_NAME_LENGTH);
	bqrows->map_file = qemu_malloc(MAX_FILE_NAME_LENGTH);
	strncpy(bqrows->map_file, meta.map_file, MAX_FILE_NAME_LENGTH);
	strncpy(bs->backing_file, meta.backing_file, sizeof(bs->backing_file));
	//log_file还没处理的，
	
#ifdef IROW_DEBUG
	printf("backing_file \"%s\"\n", bs->backing_file);
#endif
end:
#ifdef IROW_DEBUG
	printf("qrow_open_img_file() return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}
static int qrow_open(BlockDriverState *bs, const char *filename, int flags) {
    BDRVQrowState *s = bs->opaque;
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open()\n");
	printf("filename: %s, flags: %d\n", filename, flags);
#endif
#ifdef QROW_DEBUG_OPEN
	printf("press Enter to continue...\n");
	getchar();
#endif

	s->open_flags = flags;
	
	//打开img_file，获取元数据信息
	if(qrow_open_img_file(bs, s, filename, flags) < 0) {
    	fprintf (stderr, "Failed to open %s\n", filename);
    	goto fail;
    }
	
	// 再打开map_file文件
    if(qrow_open_map_file(s, flags) < 0) {
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

static int qrow_write(BlockDriverState *bs, int64_t sector_num, const uint8_t *buf, int nb_sectors) {
	BDRVQrowState *s = bs->opaque;
	int64_t nb_clusters, sector_offset;
	int ret = 1;
	
	if (s->cluster_offset >= s->total_clusters){ //磁盘已满
		fprintf (stderr, "img is full!\n");
		ret = -1;
		goto end;
	}
	nb_clusters = (nb_sectors % s->sectors_per_cluster == 0) ? (nb_sectors / s->sectors_per_cluster) : (nb_sectors / s->sectors_per_cluster + 1);
	if (s->cluster_offset + nb_clusters > s->total_clusters){ //写入区域超出磁盘最大范围
		fprintf (stderr, "Invalid nb_sectors!\n");
		ret = -1;
		goto end;
	}
	if(bdrv_pwrite(s->qrow_img_file,s->byte_offset, buf, nb_sectors*BDRV_SECTOR_SIZE) != nb_sectors*BDRV_SECTOR_SIZE) {
		fprintf(stderr, "Failed to write \n");
		ret = -1;
		goto end;
	}
	sector_offset = s->sector_offset;
	for (int64_t i = sector_num, j = 1; j <= nb_sectors; i++, j++) //更新map数组的值，即更新虚拟磁盘和物理磁盘的数据映射关系 
	{
			s->map[i] = sector_offset;
			sector_offset++;
	}
	s->map_is_dirty = 1;
	// 更新map_file文件里面的map数组的值
	if(qrow_update_map_file(s) < 0) {
		fprintf (stderr, "Failed to update map_file. (%s)\n", s->map_file);
		ret = -1;
		goto end;
	}
	
	s->cluster_offset += nb_clusters;
	s->byte_offset = s->cluster_offset * s->cluster_size;
	s->sector_offset = s->cluster_offset * s->sectors_per_cluster;
	// 更新img_file文件里面的meta关于offset的值
	if(qrow_update_img_file(s) < 0) {
		fprintf (stderr, "Failed to update img_file. (%s)\n", s->img_file);
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
	uint32_t cluster_size = 4096;
	char *backing_file = NULL;
	char *map_file = NULL;
	uint64_t meta_size;
	uint64_t cluster_offset;
	int ret = 0;
	// 解析参数
	while (options && options->name) {
		if (!strcmp(options->name, BLOCK_OPT_SIZE)) {
				disk_size= options->value.n;
			} else if (!strcmp(options->name, BLOCK_OPT_CLUSTER_SIZE)) {
				cluster_size = options->value.n;	
			} else if (!strcmp(options->name, BLOCK_OPT_BACKING_FILE)) {
	            backing_file = options->value.s;
			} 
	        options++;
	}
	
	//判断参数
	if (disk_size == 0) 
	{
		fprintf(stderr, "Invalid disk_size\n");
		ret = -1;
		goto end;
	}
	if(cluster_size == 0) {
		fprintf(stderr, "Invalid cluster_size\n");
		ret = -1;
		goto end;
	}
	if(filename[0] == '\0') {
	   fprintf(stderr, "Void img file name\n");
	   ret = -1;
	   goto end;
   	} 
	
	uint32_t cluster_bits = get_bits_from_size(cluster_size); // 获取cluster_bits
	if ((cluster_bits < MIN_CLUSTER_BITS) || (cluster_bits > MAX_CLUSTER_BITS)) {
    	fprintf(stderr, "cluster size must be a power of two between %d and %dB\n",
            1 << MIN_CLUSTER_BITS,
            1 << MAX_CLUSTER_BITS);
        ret =  -1;
    	goto end;
    	
    } 
	  
	// 计算出元数据头需要的所有信息
    memset(&meta, 0, sizeof(meta));
    meta.magic = cpu_to_be32(QROW_MAGIC);	
	meta.version = cpu_to_be32(QROW_VERSION);
	meta.disk_size = cpu_to_be64(disk_size);
	meta.cluster_size = cpu_to_be32(cluster_size);
    meta.cluster_bits = cpu_to_be32(cluster_bits);
   	meta.total_clusters = cpu_to_be64((disk_size + cluster_size -1) >> cluster_bits); // 磁盘镜像总的cluster数量
   	meta.sectors_per_cluster = cpu_to_be32(cluster_size >> BDRV_SECTOR_BITS);
	meta_size = sizeof(meta);
	if( meta_size > 0 )
	{
		cluster_offset = if(meta_size % cluster_size == 0) ? (meta_size / cluster_size) : (meta_size / cluster_size + 1);
	}
	meta.cluster_offset = cpu_to_be64(cluster_offset);//元数据存放在镜像的最开始位置 
    strncpy(meta.img_file, filename, MAX_FILE_NAME_LENGTH);
    strncpy(meta.backing_file, backing_file, MAX_FILE_NAME_LENGTH);//这个具体怎么用？？？ 
	if(qrow_generate_filename(meta.map_file, meta.img_file, "map") < 0) { // map_file文件
   		ret = -1;
   		goto end;
   	}
   	
	//将元数据写入到镜像文件中 
	int fd;	
	fd = open(meta.img_file, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY,0644);
	
	if (fd < 0) 
	{
		fprintf(stderr, "Can not open %s\n", meta.img_file);
		ret = -1;
		goto end;
	}
	//下面两个if语句实现了为稀疏文件meta.img_file预分配disk_size大小的空间
	if(fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, disk_size) < 0) {
		fprintf(stderr, "Can not preallocate disk space for %s\n", meta.img_file);
		ret = -1;
		goto end;
	}
	if (ftruncate(fd, disk_size) != 0) {
		fprintf(stderr, "Can not truncate %s to %" PRId64 " bytes\n", meta.img_file, disk_size);
		ret = -1;
		goto end;
	}
	
	uint64_t writeByets = write(fd, &meta, sizeof(meta)); 
	if(writeByets != sizeof(meta))
	{
		fprintf(stderr, "Can not write meta \n");
		ret = -1;
		goto end;
	}
	
	if(close(fd) != 0) {
		fprintf(stderr, "Can not close %s\n", meta.img_file);
   		ret = -1;
		goto end;
   	}
	
	//创建并初始化map_file文件
	int map_file_fd;
	
	uint64_t *map = NULL;
	uint64_t map_size = disk_size/BDRV_SECTOR_SIZE;
	map = qemu_malloc(map_size*sizeof(uint64_t));
	memset(map, 0, map_size*sizeof(uint64_t));
	map_file_fd = open(meta.map_file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
   	if(fd < 0) {
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

	bdrv_flush(s->qrow_img_file);
	//bdrv_flush(s->qrow_map_file);
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


static qrowAIOCB *qrow_aio_setup(BlockDriverState *bs,
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
	buf = qemu_malloc(acb->qiov->size);
	qemu_iovec_to_buffer(acb->qiov, buf);
	for (int64_t i = acb->sector_num, j = 0; i < (acb->nb_sectors + acb->sector_num); i++) 
	{
		sector_offset = bqrows->map[i];//从map数组中获取数据在物理磁盘上的存储扇区号
		//bqrows->map[i]为0时，要么是表示磁盘镜像的meta元数据占据的第一个sector，要么表示该虚拟扇区的数据为空
		if(sector_offset < (bqrows->meta_cluster*bqrows->sectors_per_cluster)) //该磁盘内容为空(0)或者为header部分
		{
			continue; 
		} 
		else
		{
		 	if(bdrv_pread(bqrows->qrow_img_file, sector_offset*BDRV_SECTOR_SIZE, buf+j*BDRV_SECTOR_SIZE, BDRV_SECTOR_SIZE) != BDRV_SECTOR_SIZE) {
				fprintf (stderr, "Failed to read the  data from %s\n", bqrows->img_file);
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
	drv = bqrows->qrow_img_file->drv;
	/*
		调试不成功可能可以改成
		acb->irvd_aiocb = drv->bdrv_aio_readv(bqrows->qrow_img_file, bqrows->sector_offset, qiov, nb_sectors, qrow_aio_readv_cb, acb);
	*/
	acb->irvd_aiocb = drv->bdrv_aio_readv(bqrows->qrow_img_file, sector_num, qiov, nb_sectors, qrow_aio_readv_cb, acb);
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
	int64_t nb_clusters, sector_offset;
	if (s->cluster_offset >= s->total_clusters){ //磁盘已满
		fprintf (stderr, "img is full!\n");
		goto end;
	}
	nb_clusters = if(nb_sectors % s->sectors_per_cluster == 0) ? (nb_sectors / s->sectors_per_cluster) : (nb_sectors / s->sectors_per_cluster + 1);
	if (s->cluster_offset + nb_clusters > s->total_clusters){ //写入区域超出磁盘最大范围
		fprintf (stderr, "Invalid nb_sectors!\n");
		goto end;
	}
	//更新map缓存
	sector_offset = s->sector_offset;
	for (int64_t i = sector_num, j = 1; j <= nb_sectors; i++, j++) //更新map数组的值，即更新虚拟磁盘和物理磁盘的数据映射关系 
	{
			s->map[i] = sector_offset;
			sector_offset++;
	}
	s->map_is_dirty = 1;
	
	drv = s->qrow_img_file->drv;
	ret = drv->bdrv_aio_writev(s->qrow_img_file, s->sector_offset, qiov, nb_sectors, cb, opaque );
	if(ret == NULL) {
	   goto end;
	}
	
	
	// 更新map_file文件里面的map数组的值
	if(qrow_update_map_file(s) < 0) {
		fprintf (stderr, "Failed to update map_file. (%s)\n", s->map_file);
		goto end;
	}
	
	s->cluster_offset += nb_clusters;
	s->byte_offset = s->cluster_offset * s->cluster_size;
	s->sector_offset = s->cluster_offset * s->sectors_per_cluster;
	// 更新img_file文件里面的meta关于offset的值
	if(qrow_update_img_file(s) < 0) {
		fprintf (stderr, "Failed to update img_file. (%s)\n", s->img_file);
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

	ret = bdrv_aio_flush(s->qrow_img_file, cb, opaque);

#ifdef QROW_DEBUG
	printf("qrow_aio_flush() return %p\n" QROW_DEBUG_END_STR, ret);
#endif

	return ret;
}

static int qrow_get_info(BlockDriverState *bs, BlockDriverInfo *bdi) {
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_get_info()\n");
#endif
	BDRVQrowState *s = bs->opaque;
	bdi->cluster_size = s->cluster_size;
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
        .name = BLOCK_OPT_CLUSTER_SIZE,
        .type = OPT_SIZE,
        .help = "qrow cluster size"
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

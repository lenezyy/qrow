以下版本是针对qemu-kvm-0.12.5的
qrow_irow_v1.c 是原始的，镜像文件以cluster为单位
qrow_irow_v2.c 是镜像文件以sector为单位
qrow_irow_v3.c 不记得在qrow_irow_v2.c上做了什么改进了。。。（读取速度非常慢）
qrow_irow_v4.c 对qrow_read 和qrow_aio_read 操作进行了优化，先将需要读取的扇区号保存在temp_map数组中，对temp_map数组排序（增序），然后按照增序的结果从镜像中读取数据保存在tmp_buf中，最后按照原始的顺序将tmp_buf中的数据复制到buf中（读取速度非常慢）
qrow_v5-0.12.5.c 对qrow_read 和qrow_aio_read 操作进行了优化，先将需要读取的扇区号和对应的index保存在QrowReadState数组中对应的结构体中，对QrowReadState数组按照readState_ptr->sector_num排序（增序），然后按照增序的结果从镜像中读取数据并保存buf对应的位置中


以下版本是针对qemu-kvm-0.14.0的
qrow_v5.c 是qrow_v5-0.12.5.c的copy，可以正常运行
qrow_v6.c 结合记录重放进行修改，加了一些打印功能
qrow_v7.h 对mate成员做了删减，修改后的代码，可以更加灵活的操作镜像文件，镜像文件可以到处复制后仍可照常使用
qrow_v8.c 在v7的代码上删除了打印功能
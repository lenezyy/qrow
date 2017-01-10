#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../libkvm.h"

#include "runtime.h"

static int my_outb (void *opaque, uint16_t addr, uint8_t data)
{
    if (addr == IO_PORT_PSEUDO_SERIAL)
	{
	if(data == EOF || data == 255)
		ctrl_c(0);
		
        if (isprint(data) || data == '\n')
		//fprintf(stderr,"OUT:%c\n",data);
		fprintf(stderr, "%c",data);
        else
		//fprintf(stderr,"OUT:%c\n",data);
		fprintf(stderr, "%c",data);
	}
    else
        printf("OUT: %x, %d\n", addr, data);
    fflush (NULL);

    return 0;
}



static int my_inb(void *opaque, int16_t addr, uint8_t *data)
{
	char ch;
	fprintf(stderr,"IN:");
	if(addr == IO_PORT_PSEUDO_SERIAL)
	{	
		//while((ch =getchar()) == '\n')
		ch = getchar()	;	
		*(char *)data = ch;
	}
	else
	{
		printf("not implemented for port %d \n",addr);	
		*data = 0;
	}
	
	return 0; 


}

static int my_inw(void *opaque, uint16_t addr, uint16_t *data)
                     { puts ("inw"); return 0; }

static int my_inl(void *opaque, uint16_t addr, uint32_t *data)
                     { puts ("inl"); return 0; }

static int my_outw(void *opaque, uint16_t addr, uint16_t data)
                     { puts ("outw"); return 0; }

static int my_outl (void *opaque, uint16_t addr, uint32_t data)
                     { puts ("outl"); return 0; }

static int my_mmio_read(void *opaque, int vcpu)
                     { return 0; }

static int my_mmio_write(void *opaque, int vcpu)
                     { return 0; }
static int my_debug(void *opaque, int vcpu)
                     { return 0; }
static int my_halt(void *opaque, int vcpu)
                     { return 0; }
static int my_io_window(void *opaque, int vcpu)
                     { return 0; }
static int my_try_push_interrupts(void *opaque, int vcpu)
                     { return 0; }
static int my_try_push_nmi(void *opaque, int vcpu)
                     { return 0; }
static int my_post_kvm_run(void *opaque, int vcpu)
                     { return 0; }
static int my_pre_kvm_run(void *opaque, int vcpu)
                     { return 0; }
static int my_tpr_access(void *opaque, int vcpu)
                     { return 0; }
static struct kvm_callbacks my_callbacks = {
    .inb                 = my_inb,
    .inw                 = my_inw,
    .inl                 = my_inl,
    .outb                = my_outb,
    .outw                = my_outw,
    .outl                = my_outl,
    .mmio_read           = my_mmio_read,
    .mmio_write          = my_mmio_write,
    .debug               = my_debug,
    .halt                = my_halt,
    .io_window           = my_io_window,
    .try_push_interrupts = my_try_push_interrupts,
    .push_nmi        = my_try_push_nmi,  // added in kvm-77
    .post_kvm_run        = my_post_kvm_run,
    .pre_kvm_run         = my_pre_kvm_run,
    .tpr_access          = my_tpr_access
};


/* callback definitions as shown in Listing 2 go here */

void load_file(void *mem, const char *filename)
{
    int  fd;
    int  nr;

    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "Cannot open %s", filename);
        perror("open");
        exit(1);
    }
    while ((nr = read(fd, mem, 4096)) != -1  &&  nr != 0)
        mem += nr;

    if (nr == -1) {
        perror("read");
        exit(1);
    }
    close(fd);
}

#define MEMORY_SIZE     (0x1000000)     /* 16 Mb */
#define FIRST_VCPU      (0)

int main(int argc, char *argv[])
{
    kvm_context_t  kvm;
    void           *memory_area;


    /* Second argument is an opaque, we don't use it yet */
    kvm = kvm_init(&my_callbacks, NULL);
    if (!kvm) {
        fprintf(stderr, "KVM init failed");
        exit(1);
    }
    if (kvm_create(kvm, MEMORY_SIZE, &memory_area) != 0) {
        fprintf(stderr, "VM creation failed");
        exit(1);
    }
#ifndef KVM_VERSION_LESS_THAN_65
    if (kvm_create_vcpu(kvm, FIRST_VCPU)) {
        fprintf(stderr, "VCPU creation failed");
        exit(1);
    }
#endif
    memory_area = kvm_create_phys_mem(kvm, 0, MEMORY_SIZE, 0, 1);
    load_file(memory_area + 0xf0000, argv[1]);

	struct kvm_record_arg args;
	strcpy(args.filename,"/home/kumaran/MTP/logs/testing.log");
	args.log_buf = malloc(1<<20);
	
	if(argc == 2)
		kvm_start_record(kvm, &args);
	else if(argc == 3)
		kvm_start_replay(kvm, &args);
	


    kvm_run(kvm, FIRST_VCPU,NULL);

    return 0;
}

//(void) signal(SIGINT,trap_kill);
//
void ctrl_c(int sig)
{

        printf("Ctrl+c trap here sd;");
        exit(0);

}



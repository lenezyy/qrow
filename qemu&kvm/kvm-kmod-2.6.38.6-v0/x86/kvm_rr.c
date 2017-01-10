
#include <asm/vmx.h>
#include <asm/msr.h>
//#include <asm/kvm_rr.h>
#include <linux/fcntl.h>
#include "../include/linux/kvm_host.h"
#include <linux/kvm.h>
#include "../include/asm-x86/kvm_rr.h"




// global buffer that will be used by recording VCPU
// to formulate log record
//
// right now we only target non SMP so safe to go with lock


//char log_buf[KVM_MAX_LOG_SIZE];



int is_kvm_rr_msr(u32 msr)
{
	// just be cautious even for global ctrl and status
	switch(msr)
	{
		case KVM_RR_IA32_PMC1:
		case KVM_RR_PEFR_ENT_SEL1:
		case KVM_RR_IA32_PERF_GLOBAL_STATUS:
		case KVM_RR_IA32_PERF_GLOBAL_CTRL:
		case KVM_RR_IA32_PERF_GLOBAL_OVF_CTRL:
		case KVM_RR_IA32_DEBUGCTL: 
			return 1;
		default:
			return 0;

	}

	return 0;
}

void init_kvm_rr_msr(struct msr_autosave_rr *msr_rr)
{
	
	int i;
	// setup exit guest store area
	for( i=0; i<KVM_RR_NR_MSRS; i++)
	{
		msr_rr->exit_store_guest[i].index = rr_msr_map[i];
		msr_rr->exit_store_guest[i].reserved = 0;
		msr_rr->exit_store_guest[i].value = 0;
	}
	
	// setup exit host load area
	for( i=0; i<KVM_RR_NR_MSRS; i++)
	{
		msr_rr->exit_load_host[i].index = rr_msr_map[i];
		msr_rr->exit_load_host[i].reserved = 0;
		msr_rr->exit_load_host[i].value = 0;
	}

	// setup entry guest load area
	for( i=0; i<KVM_RR_NR_MSRS; i++)
        {
                msr_rr->entry_load_guest[i].index = rr_msr_map[i];
                msr_rr->entry_load_guest[i].reserved = 0;
                msr_rr->entry_load_guest[i].value = 0;
        }

	
}

// this enable/config the PMC's for counting during VM recoding
// this will be called before first vm entry after enabling 
// recording and before copy_guest_store_to_load()
int config_msr_rr_state(struct msr_autosave_rr *msr_rr)
{


	msr_rr->is_counting = 1;
	//msr_rr->exit_store_guest[KVM_RR_IA32_PMC1_IDX].value = 0x0;
	// branch instruction retired
	msr_rr->exit_store_guest[KVM_RR_PEFR_ENT_SEL1_IDX].value = 0x5304c4;
	
	// we need to enable only PMC1
	msr_rr->exit_store_guest[KVM_RR_IA32_PERF_GLOBAL_CTRL_IDX].value = 0x2;

	
	
	// KVM_RR_IA32_PERF_GLOBAL_STATUS is RO so nothing to do
	// we hope we won't face any overflow during recording 
	// phase (HAVE TO REMOVE THIS ASSUMPTION LATER)
	
	// so no change for KVM_RR_IA32_PERF_GLOBAL_OVF_CTRL
	
	// no change in KVM_RR_IA32_DEBUGCTL for now 
	//
	

}

void inline clear_ovf_bit_pmc1()
{
	wrmsrl(KVM_RR_IA32_PERF_GLOBAL_OVF_CTRL, 0x2);
}
int inline check_ovf_bit_pmc1()
{
	u64 val;
	rdmsrl(KVM_RR_IA32_PERF_GLOBAL_STATUS, val);
	return val & 0x2;
}




u64 read_pmc1()
{
	unsigned eax =0x0;
        unsigned edx =0x0;
        unsigned msr_addr = KVM_RR_IA32_PMC1 ; //0x38f;

        __asm__ __volatile__ ("mov %2, %%ecx\n\t"
        "rdmsr\n\t"
        "mov %%eax, %0\n\t"
        "mov %%edx, %1\n\t"
        : "=&r" (eax), "=&r" (edx)
        : "r"(msr_addr)
        : "eax", "ecx", "edx"); /* eax, ecx, edx clobbered */



        unsigned long long result = ((unsigned long long)edx << 32) | eax;
	return result;
}

#ifdef CONFIG_X86_64 
u64 read_dr2()
{
	u64 ret;
	__asm__ __volatile__ (
	"mov %%dr2, %0\n\t"
	: "=&r" (ret)
	//: 
	//: 
	);
	return ret;

}
u64 read_dr6()
{
	u64 ret;
	__asm__ __volatile__ (
	"mov %%dr6, %0\n\t"
	: "=&r" (ret)
	//: 
	//: 
	);
	return ret;

}
void write_dr2(u64 val)
{
	__asm__ __volatile__ (
	"mov %0, %%dr2\n\t"
	:
	: "r" (val)
	//: 
	);
}
void write_dr6(u64 val)
{
	__asm__ __volatile__ (
	"mov %0, %%dr6\n\t"
	:
	: "r" (val)
	//: 
	);
}
	
#else 
u32 read_dr2()
{
	
	u32 ret;
	__asm__ __volatile__ (
	"mov %%dr2, %0\n\t"
	: "=&r" (ret)
	:
	: );
	return ret;
}
u32 read_dr6()
{
	
	u32 ret;
	__asm__ __volatile__ (
	"mov %%dr6, %0\n\t"
	: "=&r" (ret)
	:
	: );
	return ret;
}
void write_dr2(u32 val)
{
	__asm__ __volatile__ (
	"mov %0, %%dr2\n\t"
	:
	: "r" (val)
	: );
}
void write_dr6(u32 val)
{
	__asm__ __volatile__ (
	"mov %0, %%dr6\n\t"
	:
	: "r" (val)
	: );
}
#endif

// this will save the require host msr state 
// into VMCS specified mem area, these values will be
// restored upon vm exit.
// SHOULD BE CALLED BEFORE VM ENTRY
void save_host_msr_rr_state(struct msr_autosave_rr *msr_rr)
{

	int i;
	for(i=0; i<KVM_RR_NR_MSRS; i++)
	{
		rdmsrl(rr_msr_map[i],msr_rr->exit_load_host[i].value);	
		//kvm_debug(" msr addr %x val %llx \n",rr_msr_map[i],\
				msr_rr->exit_load_host[i].value);
	}

}

// this will save the stored guest msrs into VMCS area which
// will be used to load when vm entry happens
// SHOULD BE CALLED BEFORE VM ENTRY
void copy_guest_store_to_load(struct msr_autosave_rr *msr_rr)
{

	memcpy(&msr_rr->entry_load_guest,&msr_rr->exit_store_guest,\
			sizeof(msr_rr->exit_store_guest));		
			
}


// this function will set the prev record's
// next_rec_type field to NEXT_REC_INTR
// should be called before the write_log() of 
// interrupt record

void inline kvm_rr_next_rec_intr(struct kvm_vcpu *vcpu)
{
	u8 *next_rec_type = vcpu->run->ring_buffers[vcpu->run->ring_buf_kvm_ptr]+vcpu->prev_log_data_offset;
	*next_rec_type = NEXT_REC_INTR;
}

// this function will set the prev record's
// next_rec_type field to NEXT_REC_PKT
// should be called before the write_log() of
// pkt is called
void inline kvm_rr_next_rec_req(struct kvm_vcpu *vcpu)
{
	u8 *next_rec_type = vcpu->run->ring_buffers[vcpu->run->ring_buf_kvm_ptr]+vcpu->prev_log_data_offset;
	*next_rec_type = NEXT_REC_REQ;

}


// removes the entire list, called when vcpu is freed
void kvm_rr_remove_pending_reqs(struct kvm_vcpu *vcpu)
{
	struct kvm_rr_reqs_list *req,*temp;
	// take precautionary lock, no should actual add when
	// this is called 
	spin_lock(&vcpu->pending_reqs_lock);

	req =  vcpu->pending_reqs;
	while(req)
	{
		temp = req->next;

		kvm_debug("removing reqs from pending list %x\n",req);
		kfree(req);
		req = temp;
	}
	vcpu->pending_reqs = NULL;

	spin_unlock(&vcpu->pending_reqs_lock);


}

int kvm_rr_add_to_pending_reqs(struct kvm_vcpu  *vcpu, struct  kvm_rr_rec_request *req)
{


	// when we record this  COMPLETE BIT is
	// not set, we add these record to log file
	// we will set the corresponding COMPLETE BIT
	
	struct kvm_rr_reqs_list *req_list_element;
	req_list_element = (struct kvm_rr_reqs_list *)kmalloc(sizeof(struct kvm_rr_reqs_list),GFP_KERNEL);
	kvm_debug("adding reqs to pending list %x gpa %x type %d \n", \
				req_list_element,req->gpa,req->req_type);
	req_list_element->next = NULL;
	
	req_list_element->gpa = req->gpa;
	req_list_element->size = req->size;
	req_list_element->req_type = req->req_type;

	// take the pending_pkts_lock before adding this new pkt to 
	// the pending list
	spin_lock(&vcpu->pending_reqs_lock);

	req_list_element->next = vcpu->pending_reqs;
	vcpu->pending_reqs = req_list_element;

	spin_unlock(&vcpu->pending_reqs_lock);
	
}


int kvm_rr_req_handle(struct kvm_vcpu *vcpu, struct kvm_rr_reqs_list *req)
{

	gfn_t gfn;
	int offset;
	unsigned long hva;
	unsigned int *rfd_sts;

	if(vcpu->is_recording)
	{
		struct kvm_rr_req *req_log = (struct kvm_rr_req *)kmalloc(sizeof(struct kvm_rr_req), GFP_KERNEL);
		
		if(req->size > KVM_RR_REQ_MAX)
		{
			// should not occur
			kvm_err("big req than buffer size %d\n",req->size);
			//vcpu->is_recording = 0;
			return 0;
		}
	
		// copy from rfd to log
		kvm_debug_log("LOG_REQ %lu:%llu,%llx,%llx:size %d addr %x %d\n",\
	               vcpu->num_recs,vcpu->rr_ts.br_count,vcpu->rr_ts.rcx,vcpu->rr_ts.rip,req->size,\
				 req->gpa,sizeof(struct kvm_rr_req));
		if(vcpu->log_offset == -1 && vcpu->is_recording)
		{
			struct kvm_rr_hdr hdr_log;
			hdr_log.next_rec_type = 0;
			// recording just started , write file header first
			write_log(KVM_RR_HEADER, vcpu, sizeof(struct kvm_rr_hdr), &hdr_log);
		}
		req_log->next_rec_type  = 0;
		req_log->gpa = req->gpa;
		req_log->size = req->size;
		
		// update the prev rec's next rec type as PKT
		kvm_rr_next_rec_req(vcpu);

		gfn = req->gpa >> PAGE_SHIFT;
		hva = gfn_to_hva(vcpu->kvm, gfn);
		offset = offset_in_page(req->gpa);

		if(req->req_type == REC_TYPE_RX_PKT)
		{
			rfd_sts = hva+offset;
			*rfd_sts = (*rfd_sts | (1<<15));
			kvm_debug("rfd_sts %x\n",*rfd_sts);
		}

		memcpy(req_log->data, hva+offset, req_log->size);
			
		write_log(KVM_RR_REQ, vcpu, (sizeof(struct kvm_rr_req) - (KVM_RR_REQ_MAX - req->size)), (void *)req_log);
		kfree(req_log);
		//reset counter to zero .. next event is relative 
		// from here
		vcpu->rr_ts.br_count = 0;
			
	} // end of recording
	else if(vcpu->is_replaying)
	{
		struct kvm_rr_req *req_log = NULL;
		int ret;
		ret = read_log(vcpu);	
		if(ret <= 0 || ret != KVM_RR_REQ)
		{
			// disable replaying , undefined behavior
			kvm_err("is out of sync %d expecting KVM_RR_REQ,\
					 got %d\n", ret != KVM_RR_REQ, ret);
			vcpu_disable_rply(vcpu);
              	}
		else
		{
			// just copy the input data from log file
			req_log = get_log_data_ptr(vcpu);
		}
		if(!req_log)
		{
			// disable replaying , undefined behavior
			kvm_err("couldn't get data ptr\n");
			vcpu_disable_rply(vcpu);
		}
		else
		{
			
			vcpu->next_rec_type = req_log->next_rec_type;
			// copy to the place where user space would have
			// copied 
			gfn = req_log->gpa >> PAGE_SHIFT;
			hva = gfn_to_hva(vcpu->kvm, gfn);
			offset = offset_in_page(req_log->gpa);
	
			memcpy(hva+offset, req_log->data, req_log->size);
			kvm_debug_log("RPLY_REQ %lu:%llu,%llx,%llx:size %d addr %x %d\n",\
	               vcpu->num_recs,vcpu->rr_ts.br_count,vcpu->rr_ts.rcx,vcpu->rr_ts.rip,req_log->size,\
				 req_log->gpa,sizeof(struct kvm_rr_req));
	
			vcpu->rr_ts.br_count = 0;
		
		}

	}// end of replay	

}

// this function will write the pending pkts to log file
// and set the COMPLETE_BIT on rfd. And also free the pending pkts
// data structure
int kvm_rr_rec_reqs(struct kvm_vcpu *vcpu)
{

		
	struct kvm_rr_reqs_list *list=NULL,*temp;

	
	if(!vcpu->is_recording)
	{
		// we should have empty list
		if(vcpu->pending_reqs)
			kvm_err("Not recording but list is non-empty\n");
		
		return 0;
	}


	// take the pending pkts lock and store
	// that list in a local variable, so lock can be 
	// release for further pkts addition, which guest see
	// in the next iteration.
	spin_lock(&vcpu->pending_reqs_lock);
	
	list = vcpu->pending_reqs;
	vcpu->pending_reqs = NULL;
	
	spin_unlock(&vcpu->pending_reqs_lock);
	
	while(list)
	{
		
		kvm_rr_req_handle(vcpu, list);
		temp = list;
		list = temp->next;
		kvm_debug("removing reqs from peding list %x\n",temp);
		kfree(temp);

	}	

}

int kvm_rr_rply_reqs(struct kvm_vcpu *vcpu)
{
	
	while(vcpu->next_rec_type == NEXT_REC_REQ)
	{
		kvm_rr_req_handle(vcpu,NULL);
	}
	return 0;
}


// this will return the pointer to payload in the
// current log record. Caller should make sure 
// proper log record is being pointed by log_offset
// in vcpu struct

void *get_log_data_ptr(struct kvm_vcpu *vcpu)
{

	u8 log_type; 
	struct kvm_run *run = vcpu->run;
	char *buf = run->ring_buffers[run->ring_buf_kvm_ptr];

	log_type = (buf+vcpu->log_offset)[0];
	//zyy
	printk(KERN_ALERT "get_log_data_ptr() log_type:%d\n",log_type);
	//end
	switch(log_type)
	{
		case KVM_RR_PIO_IN:
		case KVM_RR_RDTSC:
		case KVM_RR_MMIO_IN:
		case KVM_RR_HEADER:
		case KVM_RR_REGS_SET:
		case KVM_RR_REQ:
			// account only type and length
			return (void *)(buf+vcpu->log_offset+3);
		case KVM_RR_EXT_INT:
			return (void *)(buf+vcpu->log_offset+\
						3+sizeof(struct kvm_rr_ts));
		default:
			kvm_err("Invalid log type %u\n",log_type);
	}
	return NULL;	
}

// reads record by record and sets the offset in log_buf in
// vcpu->log_offset. 
// returns log type 
// returns 0 if incomplete block is found / log file is exhausted
// and considered to be the end of replaying
// returns -1 if any error

// log_rec_len will be used to store the record len.
u8  read_log(struct kvm_vcpu *vcpu)
{
	int ret;
	struct kvm_run *run = vcpu->run;
	u16 *data_len;
	u8 log_type;
	char *buf = run->ring_buffers[run->ring_buf_kvm_ptr];

	if(vcpu->log_offset == -1)
	{
		vcpu->log_offset = 0;		
		vcpu->log_rec_len = 0;
		//zyy
		vcpu->log_offset_readed=0;
		//end
	}

	// advance the offset to the end of prev log rec
	vcpu->log_offset += vcpu->log_rec_len;
	
	//zyy
	vcpu->log_offset_readed+=vcpu->log_rec_len;
	printk(KERN_ALERT "read_log() log_offset_readed:%llu\n",vcpu->log_offset_readed);
	//end

	// skip fill chars till the block is done
	if( (buf+vcpu->log_offset)[0] == 0\
			 || vcpu->log_offset >= KVM_MAX_LOG_SIZE)
	{
		// either filler block is found or block is completed
		// read new block
		run->invalid_exit_reason = 1;
		run->ring_buf_kvm_ptr = (run->ring_buf_kvm_ptr + 1)% KVM_RR_RING_BUF_SIZE; 
		buf = run->ring_buffers[run->ring_buf_kvm_ptr];	
		run->used_buffers--;
		if(!run->used_buffers)
		{
			kvm_err("Buffer underflow or Log file exhausted\n");
			return 0;
		}
		//zyy
		vcpu->log_offset_readed+=(KVM_MAX_LOG_SIZE-vcpu->log_offset);
		//end
		vcpu->log_offset = 0;
		vcpu->log_rec_len = 0;
	}
		
	log_type = (buf+vcpu->log_offset)[0];
	//zyy
	printk(KERN_ALERT "read_log() log_type:%d\n",log_type);
	//end

	data_len = (buf+vcpu->log_offset+1);

	vcpu->log_rec_len = *data_len;
	switch(log_type)
	{
		case KVM_RR_PIO_IN:
		case KVM_RR_RDTSC:
		case KVM_RR_MMIO_IN:
		case KVM_RR_HEADER:
		case KVM_RR_REGS_SET:
		case KVM_RR_REQ:
			// account only type and length
			vcpu->log_rec_len += 3;
			break;
		case KVM_RR_EXT_INT:
			//account for ts , type and lenght
			vcpu->log_rec_len += (3 + sizeof(struct kvm_rr_ts));
			break;
		default:
			kvm_err("Invalid log type %d\n",log_type);
			return -1;
	}
	// just for cross checking count num of recs. 
	vcpu->num_recs++;
	kvm_err(" %d ", log_type);
	return  log_type;
}


// this function will take log type, vcpu(for timestamp), data_length  and
// void pointer to data, pointer will be deferenced according 
// to log type. 
//
// 0 - success
// 1 - failure
int write_log(u8 log_type, struct kvm_vcpu *vcpu, u16 data_len, 
				void *data )
{

	struct kvm_rr_ts *ts = &vcpu->rr_ts;
	size_t count = KVM_RR_LOG_SIZE(data_len);
	int ret;
	int offset = 0,fil_size;
	int flag=0;

	struct kvm_run *run=vcpu->run;
	char *buf = run->ring_buffers[run->ring_buf_kvm_ptr];

	if(!vcpu->is_recording)	
		return 0;

	if(vcpu->log_offset == -1)
	{
		//reset the flag
		vcpu->log_offset = 0;
		goto log_copy;
	}


	offset = vcpu->log_offset % KVM_MAX_LOG_SIZE;
	// check if new block has to be created or not

	int old_no_blocks = vcpu->log_offset / KVM_MAX_LOG_SIZE;
	int new_no_blocks = (vcpu->log_offset + KVM_RR_LOG_DATA \
				+ data_len) / KVM_MAX_LOG_SIZE ;	 
	if( new_no_blocks > old_no_blocks )
	{
		// fill the log buffer with enough zeros to complete
		// the old block
		kvm_debug("new block fil %d %llu \n", fil_size, vcpu->log_offset+fil_size);
		fil_size = KVM_MAX_LOG_SIZE - (vcpu->log_offset % KVM_MAX_LOG_SIZE);
	
		memset(run->ring_buffers[run->ring_buf_kvm_ptr]+offset, 0, fil_size);
		
		run->invalid_exit_reason = 1;
		run->ring_buf_kvm_ptr = ((run->ring_buf_kvm_ptr+1)%KVM_RR_RING_BUF_SIZE);
		buf = run->ring_buffers[run->ring_buf_kvm_ptr];
		run->used_buffers++;
		if(run->used_buffers == KVM_RR_RING_BUF_SIZE)
		{
			kvm_err("buffer overflow \n");
			vcpu->is_recording = 0;
			return 1;
		}

		// update the new file position
		vcpu->log_offset += fil_size;
		offset = 0;
		
	}

log_copy:
	vcpu->num_recs++;	
	switch(log_type)
	{
		case KVM_RR_RDTSC:
		{
			// has data 
			// it is alway synchronous, i.e. we can rely on 
			// CPU execution to generate this at the right time
			// rather than we stopping it. So no time stamp is
			// required for this event.

			//
			memcpy(buf+offset+KVM_RR_LOG_TYPE, (void *)(&log_type),\
							sizeof(u8));
			memcpy(buf+offset+KVM_RR_LOG_DATA_LEN, (void *)(&data_len),\
							sizeof(u16));
			memcpy(buf+offset+KVM_RR_LOG_TS, data, data_len);

			vcpu->prev_log_data_offset = offset+KVM_RR_LOG_TS;

			count -= sizeof(struct kvm_rr_ts); 
		
			vcpu->log_offset += count;
			return 0;
		}
		case KVM_RR_PIO_IN:
		case KVM_RR_REQ:
		{
			//
			memcpy(buf+offset+KVM_RR_LOG_TYPE, (void *)(&log_type),\
							sizeof(u8));
			memcpy(buf+offset+KVM_RR_LOG_DATA_LEN, (void *)(&data_len),\
                                                        sizeof(u16));
	
			memcpy(buf+offset+KVM_RR_LOG_TS, data, data_len);

			vcpu->prev_log_data_offset = offset+KVM_RR_LOG_TS;

			count -= sizeof(struct kvm_rr_ts);

			vcpu->log_offset += count;
			return 0;
		}	
		case KVM_RR_MMIO_IN:
		{
			memcpy(buf+offset+KVM_RR_LOG_TYPE, (void *)(&log_type),\
							sizeof(u8));
			memcpy(buf+offset+KVM_RR_LOG_DATA_LEN, (void *)(&data_len),\
                                                        sizeof(u16));
			
			memcpy(buf+offset+KVM_RR_LOG_TS, data, data_len);

			vcpu->prev_log_data_offset = offset+KVM_RR_LOG_TS;

			count -= sizeof(struct kvm_rr_ts);
		
			vcpu->log_offset += count;
			return 0;
		}
		case KVM_RR_REGS_SET:
		{
			memcpy(buf+offset+KVM_RR_LOG_TYPE, (void *)(&log_type),\
							sizeof(u8));
			memcpy(buf+offset+KVM_RR_LOG_DATA_LEN, (void *)(&data_len),\
                                                        sizeof(u16));
		
			memcpy(buf+offset+KVM_RR_LOG_TS, data, data_len);

			vcpu->prev_log_data_offset = offset+KVM_RR_LOG_TS;

			count -= sizeof(struct kvm_rr_ts);
		
			vcpu->log_offset += count;
			return 0;
		}
	
		case KVM_RR_EXT_INT:
		{
			// we need to record the time stamp !
			
			memcpy(buf+offset+KVM_RR_LOG_TYPE, (void *)(&log_type),\
							sizeof(u8));
			memcpy(buf+offset+KVM_RR_LOG_DATA_LEN, (void *)(&data_len),\
                                                        sizeof(u16));
			memcpy(buf+offset+KVM_RR_LOG_TS, (void *)ts,\
                                                         sizeof(struct kvm_rr_ts));
			
			memcpy(buf+offset+KVM_RR_LOG_DATA, data, data_len);
	
			vcpu->prev_log_data_offset = offset+KVM_RR_LOG_DATA;

			vcpu->log_offset += count;
			return 0;

		}
		case KVM_RR_HEADER:
		{
			memcpy(buf+offset+KVM_RR_LOG_TYPE, (void *)(&log_type),\
							sizeof(u8));		
			memcpy(buf+offset+KVM_RR_LOG_DATA_LEN, (void *)(&data_len),\
                                                        sizeof(u16));
			
			memcpy(buf+offset+KVM_RR_LOG_TS, data, data_len);
			
			vcpu->prev_log_data_offset = offset+KVM_RR_LOG_TS;

			count -= sizeof(struct kvm_rr_ts);

			vcpu->log_offset += count;
			return 0;
		}


		defualt:
		{
			kvm_err("invalid log type \n");
			return 1;
		}

	}

}

	
	

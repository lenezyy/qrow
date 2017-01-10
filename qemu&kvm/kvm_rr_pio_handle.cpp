//·½°¸Ò»£¬½«Á½ÖÖ¼ÇÂ¼Çé¿öºÏ²¢µ½Ò»¸öº¯ÊýÖÐ 
//ÖØÐÂ¶¨ÒåÒ»¸ö½á¹¹Ìå

kvm_rr.h
#define LOG_TYPE_DATA 	0
#define LOG_TYPE_ADDR	1
struct kvm_rr_pio_in
{
	u8 next_rec_type;
	u8 log_type;//0±íÊ¾ÊÇ¼ÇÂ¼Êý¾Ý£¬1±íÊ¾¼ÇÂ¼µØÖ·
	char pad[6]; 
	union{
		char data[KVM_RR_PIO_DATA_MAX];
		struct  
		{
			u16 nb_sectors;
			char pad[6]; 
			u64 sector_num;
			// u64 sector_num[KVM_MAX];			
		} pio_in_ide;
		
	};

};

int kvm_rr_pio_handle(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	//pio_rr_log.count = vcpu->arch.pio.count;
	//pio_rr_log.port = vcpu->arch.pio.port;
	//pio_rr_log.size = vcpu->arch.pio.size;
	if(vcpu->is_recording)
	{
		
		if((vcpu->arch.pio.count * vcpu->arch.pio.size) > KVM_RR_PIO_DATA_MAX)
		{
			kvm_debug("error...\n");
			vcpu->is_recording = 0;
			return 0;
		}
		if(vcpu->log_offset == -1 && vcpu->is_recording)
		{
			struct kvm_rr_hdr hdr_log;
			hdr_log.next_rec_type = 0;
			// recording just started , write file header first
			write_log(KVM_RR_HEADER, vcpu, sizeof(struct kvm_rr_hdr), &hdr_log);
		}
		struct kvm_rr_pio_in pio_rr_log;
		pio_rr_log.next_rec_type = 0;
		if(vcpu->run->pio_rr.sector_num >= 0 && vcpu->run->pio_rr.nb_sectors >= 1 && (vcpu->arch.pio.count * vcpu->arch.pio.size == 512))
		{
			
			pio_rr_log.log_type = LOG_TYPE_ADDR;
			pio_rr_log.pio_in_ide.sector_num = vcpu->run->pio_rr.sector_num;
			pio_rr_log.pio_in_ide.nb_sectors = vcpu->run->pio_rr.nb_sectors;
			//zyy
			vcpu->run->pio_rr.sector_num = -1;
			vcpu->run->pio_rr.nb_sectors = 0;
			//Ïë°ì·¨È¥ÄÄÀï³õÊ¼»¯Ò»ÏÂÕâÁ½¸öÖµ£¬²»È»²»ºÃ¸ã 
			//zyy
			write_log(KVM_RR_PIO_IN,vcpu,\
			(sizeof(pio_rr_log.pio_in_ide) + 8), \
						(void *)&pio_rr_log);
		}
		else
		{

			pio_rr_log.log_type = LOG_TYPE_DATA;
			memcpy(pio_rr_log.data,vcpu->arch.pio_data, \
				vcpu->arch.pio.count * vcpu->arch.pio.size);
			kvm_debug_log("LOG_IOIN %lu:%llu,%llx,%llx:port %d data %x count %d %d",\
	               vcpu->num_recs,vcpu->rr_ts.br_count,vcpu->rr_ts.rcx,vcpu->rr_ts.rip,vcpu->arch.pio.port,\
					 *(int *)(vcpu->arch.pio_data),vcpu->arch.pio.count,sizeof(struct kvm_rr_pio_in));
			write_log(KVM_RR_PIO_IN,vcpu,\
			(vcpu->arch.pio.count * vcpu->arch.pio.size + 8), \
						(void *)&pio_rr_log);
		}	
		// reset counter to zero .. next event is relative 
		// from here
		vcpu->rr_ts.br_count = 0;
		
		// record pending pkts
		kvm_rr_rec_reqs(vcpu);

	}// end of recording 
	else if(vcpu->is_replaying)
	{
		
		struct kvm_rr_pio_in *pio_rr_log = NULL;
		int ret;
		ret = read_log(vcpu);	
		//kvm_err("%d \n", ret);
		if(ret <= 0 || ret != KVM_RR_PIO_IN)
		{
			// disable replaying , undefined behavior
			kvm_err("is out of sync %d expecting KVM_RR_PIO_IN,\
					 got %d\n", ret != KVM_RR_PIO_IN, ret);
			vcpu_disable_rply(vcpu);
			return 0;
        }
		else
		{
			// just copy the input data from log file
			pio_rr_log = get_log_data_ptr(vcpu);
		}
		if(!pio_rr_log)
		{
			// disable replaying , undefined behavior
			kvm_err("couldn't get data ptr\n");
			vcpu_disable_rply(vcpu);
			return 0;
		}
		else
		{
			
			vcpu->next_rec_type = pio_rr_log->next_rec_type;
			u8 log_type = pio_rr_log->log_type;
			if(log_type == LOG_TYPE_DATA)
			{
				// copy to the place where user space would have
				// copied 
				memcpy(vcpu->arch.pio_data, pio_rr_log->data, \
				vcpu->arch.pio.count * vcpu->arch.pio.size);	
				kvm_debug_log("RPLY_PIO  %lu:%llu,%llx,%llx:port %d data %x count %d",\
	                      vcpu->num_recs,vcpu->rr_ts.br_count,vcpu->rr_ts.rcx,vcpu->rr_ts.rip,vcpu->arch.pio.port,\          
                                                *(int *)(vcpu->arch.pio_data),vcpu->arch.pio.count);
                vcpu->rr_ts.br_count = 0;
				kvm_rr_rply_reqs(vcpu);
				return 1;
			}
			else
			{
				vcpu->run->pio_rr.sector_num = pio_rr_log->pio_in_ide.sector_num;
				vcpu->run->pio_rr.nb_sectors = pio_rr_log->pio_in_ide.nb_sectors;
				//½ÓÏÂÀ´ÐèÒªÍË³öµ½qemu²ã¶ÁÈ¡Êý¾Ý¡£¡£¡£¡£
				/* ÏÂÃæÁ½ÐÐ´úÂëÒ²²»ÔìÒª²»Òª£¬ÔõÑù´¦ÀíÁË 
					vcpu->rr_ts.br_count = 0;
					kvm_rr_rply_reqs(vcpu); 
				*/
				return -1;
			}
		

		
		
		}

	}// end of replay
	
	return 1;//Ã»ÓÐ¼ÇÂ¼ÖØ·Å 

}


static int emulator_pio_in_emulated(int size, unsigned short port, void *val,
			     unsigned int count, struct kvm_vcpu *vcpu)
{
	// kvm rr
	struct kvm *kvm_run;
	// data coming from user space
	// end kvm rr
	if (vcpu->arch.pio.count)	
		goto data_avail;

	trace_kvm_pio(0, port, size, count);
	//»Ø·ÅµÄÊ±ºò£¬ÊÇÖ±½ÓÌøµ½ÁËdata availÖ´ÐÐÃ´å ²»ÐèÒªÔÙÌøµ½qemu´¦ÀíÁË°É£¬ºóÆÚÐèÒªÑéÖ¤Ò»ÏÂ

	vcpu->arch.pio.port = port;
	vcpu->arch.pio.in = 1;
	vcpu->arch.pio.count  = count;
	vcpu->arch.pio.size = size;

	if (!kernel_pio(vcpu, vcpu->arch.pio_data)) 
	{

	data_avail:
		// kvm rr
		// record the data which is presented by kernel instead of 
		// user space
		kvm_run = vcpu->run;
		int ret =  kvm_rr_pio_handle(vcpu,kvm_run);
		if (ret == 1)
		{
			memcpy(val, vcpu->arch.pio_data, size * count);
			vcpu->arch.pio.count = 0;
			return 1;
		}
		else 
		{
			if  (ret == -1)
			{
				//ÒªÈ¥qemuÄÃÊý¾ÝÁË¡£¡£¡£ 
			}
			else
			//Ö¤Ã÷ kvm_rr_pio_handle()³ö´íÁË¡£¡£¡£¡£Ã»¿´µ½Ô­´úÂë×ö³öÈÎºÎÓ¦¶Ô´ëÊ© 
		}
		
		// end kvm rr 
		
	}

	vcpu->run->exit_reason = KVM_EXIT_IO;
	vcpu->run->io.direction = KVM_EXIT_IO_IN;
	vcpu->run->io.size = size;
	vcpu->run->io.data_offset = KVM_PIO_PAGE_OFFSET * PAGE_SIZE;
	vcpu->run->io.count = count;
	vcpu->run->io.port = port;
	return 0;
}

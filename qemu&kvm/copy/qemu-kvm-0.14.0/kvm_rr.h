#ifndef __KVM_RR_H_

int kvm_get_vmfd(void);
int kvm_recording(void);
int kvm_replaying(void);

int next_log_br_cont(int fd);
int update_log_rec(int fd, int next_intr_offset);
int update_next_br_count(const char * log_file_name);

#endif



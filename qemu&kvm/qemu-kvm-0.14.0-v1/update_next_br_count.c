
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>


#define KVM_MAX_LOG_SIZE (1<<20)

#define DEBUG_ON 1

#define dbg(...) \
	if( DEBUG_ON ) \
	{ \
		printf(__VA_ARGS__); \
		fflush(stdout); \
	} 




static int r_fd_offset = -1;
static int w_fd_offset = -1;


static char r_buf[KVM_MAX_LOG_SIZE];
static char w_buf[KVM_MAX_LOG_SIZE];

//int next_log_br_count(int fd);
//int update_log_rec(int fd, int next_intr_offset);
//int update_next_br_count(const char * log_file_name);


// kvm rr 

int update_next_br_count(const char * log_file_name)
{
	
	int r_fd = open(log_file_name, O_RDONLY);
	int w_fd = open(log_file_name, O_RDWR); 

	int offset;

	if(r_fd < 0 || w_fd < 0)
	{
		dbg("ERR: Couldn't open log file for updating\n");
		exit(0);
	}

	
	//br_count = next_log_br_count(r_fd);
	dbg("Updating next br counts ...\n");	
	while (1)
	{
		offset = next_log_br_count(r_fd);
		
		update_log_rec(w_fd, offset);

		if(!offset)				
			break;
	}

	// close the files 
	close(r_fd);
	close(w_fd);

	return 0;
}

int  update_log_rec(int fd, int next_intr_offset)
{

	int ret;

	if(w_fd_offset == -1)
	{
		// read new block 
read_write_new:
		// before read new write the updated block
		if(w_fd_offset != -1)
		{
			ret = lseek(fd, -KVM_MAX_LOG_SIZE, SEEK_CUR);
			if(ret < 0)
			{
				dbg("ERR: couldn't not seek\n");
				return -1;
			}	
			ret = write(fd, w_buf, KVM_MAX_LOG_SIZE);
			if(!ret || ret < 0)
			{
				dbg("ERR: counldn't write to file\n");
				return -1;
			}
		}

		ret = read(fd, w_buf, KVM_MAX_LOG_SIZE);
		if (!ret)
		{
			return 0;
		}
		else if (ret < 0)
		{
			dbg("ERR: Couldn't read from file");
		}
		else if(ret < KVM_MAX_LOG_SIZE)
		{
			// ignore the partial block 
			return 0;
		}
		
		w_fd_offset = 0;
	}
	//zyy
	//while( (w_buf+w_fd_offset)[0] < 4 && w_fd_offset < KVM_MAX_LOG_SIZE ) 	
	while(( (w_buf+w_fd_offset)[0] < 4||(w_buf+w_fd_offset)[0]>5) && w_fd_offset < KVM_MAX_LOG_SIZE ) 	
	{
	
		if((w_buf+w_fd_offset)[0] == 0)		
		{	
			// fill chars, continue
			goto read_write_new;
		}

		w_fd_offset += 1;
	
		short *data_len = w_buf+w_fd_offset;
	
		w_fd_offset += 2;
	
		w_fd_offset += *data_len;
		
	}

	if( w_fd_offset >= KVM_MAX_LOG_SIZE)
	{
		// counldn't find EXT_INT record in this block
		goto read_write_new;
	}
	//zyy
	if((w_buf+w_fd_offset)[0]>7)
	
	{
		dbg("ERR:rec_type is wrong\n");
		return -1;
	}
	//zyy end
	//br_count = w_buf+w_fd_offset+2+1;

	// update the br diff

	if( (w_buf+w_fd_offset)[0] == 4)
	{
		if(next_intr_offset)
			memcpy(w_buf+w_fd_offset+1+2+24+8, r_buf+next_intr_offset, 24);
		else
			memset(w_buf+w_fd_offset+1+2+24+8, 0, 24);
		//*(unsigned int *)(w_buf+w_fd_offset+1+2+24+4) =\
					 (next_br_count - *br_count);
		w_fd_offset += (1+2+24+8+24);
	}
	else
	{
		if(next_intr_offset)
			//memcpy(w_buf+w_fd_offset+1+2, r_buf+next_intr_offset, 24);
			//zyy
			memcpy(w_buf+w_fd_offset+1+2+8, r_buf+next_intr_offset, 24);
			//zyy

		else
			//zyy
			//memset(w_buf+w_fd_offset+1+2, 0, 24);
			memset(w_buf+w_fd_offset+1+2+8, 0, 24);
		//*(unsigned long long *)(w_buf+w_fd_offset+1+2) =\
					next_br_count; 
		//w_fd_offset += (1+2+24);
		w_fd_offset += (1+2+8+24);
	}

	if(!next_intr_offset)
		goto read_write_new;
	// 1 - type 2- len 24 - time stamp 4 - next br 4 - intr

	return 0;


}

// returns log

// returns log
// returns log
int  next_log_br_count(int fd)
{
	
	int ret;
	int offset;

	if(r_fd_offset == -1)
	{
		// read new block 
read_new:
		ret = read(fd, r_buf, KVM_MAX_LOG_SIZE);
		if (!ret)
		{
			return 0;
		}
		else if (ret < 0)
		{
			dbg("ERR: Couldn't read from file");
		}
		else if(ret < KVM_MAX_LOG_SIZE)
		{
			// ignore the partial block 
			return 0;
		}
		
		r_fd_offset = 0;
	}

	while( (r_buf+r_fd_offset)[0] != 4 && r_fd_offset < KVM_MAX_LOG_SIZE ) 	
	{
	
		if((r_buf+r_fd_offset)[0] == 0)		
		{	
			// fill chars, continue
			goto read_new;
		}

		r_fd_offset += 1;
	
		short *data_len = r_buf+r_fd_offset;
	
		r_fd_offset += 2;
	
		r_fd_offset += *data_len;
		
	}

	if( r_fd_offset >= KVM_MAX_LOG_SIZE)
	{
		// counldn't find EXT_INT record in this block
		goto read_new;
	}

	offset = r_fd_offset+2+1;
	
	// 1 - type 2- len 24 - time stamp 4 - next br 4 - intr
	r_fd_offset += (1+2+24+8+24);

	return offset;


}

// end kvm rr


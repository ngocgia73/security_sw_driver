#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/types.h>



#define IOC_MAGIC  'e'
#define ES_ENCRYPT      _IOWR(IOC_MAGIC, 5, __u8)
#define ES_DECRYPT      _IOWR(IOC_MAGIC, 6, __u8) 

#define SIZE_1K             (1  << 10)
#define SIZE_64K            (64 << 10)
#define SIZE_1M             (1  << 20)
#define SIZE_2M             (2  << 20)
#define SIZE_4M             (4  << 20)

#define DMA_BUFFER_SIZE     SIZE_64K

static int get_enc_input_data(unsigned int data_input)
{
    if(!data_input)
        return 0;

    *(unsigned int *)(data_input)      = 0xe2bec16b;
    *(unsigned int *)(data_input + 4)  = 0x969f402e;
    *(unsigned int *)(data_input + 8)  = 0x117e3de9;
    *(unsigned int *)(data_input + 12) = 0x2a179373;
    *(unsigned int *)(data_input + 16) = 0x578a2dae;
    *(unsigned int *)(data_input + 20) = 0x9cac031e;
    *(unsigned int *)(data_input + 24) = 0xac6fb79e;
    *(unsigned int *)(data_input + 28) = 0x518eaf45;
    *(unsigned int *)(data_input + 32) = 0x461cc830;
    *(unsigned int *)(data_input + 36) = 0x11e45ca3;
    *(unsigned int *)(data_input + 40) = 0x19c1fbe5;
    *(unsigned int *)(data_input + 44) = 0xef520a1a;
    *(unsigned int *)(data_input + 48) = 0x45249ff6;
    *(unsigned int *)(data_input + 52) = 0x179b4fdf;
    *(unsigned int *)(data_input + 56) = 0x7b412bad;
    *(unsigned int *)(data_input + 60) = 0x10376ce6;

    return 64;
}

static int get_dec_input_data(unsigned int data_input)
{
    if(!data_input)
        return 0;

    *(unsigned int *)(data_input)      = 0xe2bec16b + 1;
    *(unsigned int *)(data_input + 4)  = 0x969f402e + 1;
    *(unsigned int *)(data_input + 8)  = 0x117e3de9 + 1;
    *(unsigned int *)(data_input + 12) = 0x2a179373 + 1;
    *(unsigned int *)(data_input + 16) = 0x578a2dae + 1;
    *(unsigned int *)(data_input + 20) = 0x9cac031e + 1;
    *(unsigned int *)(data_input + 24) = 0xac6fb79e + 1;
    *(unsigned int *)(data_input + 28) = 0x518eaf45 + 1;
    *(unsigned int *)(data_input + 32) = 0x461cc830 + 1;
    *(unsigned int *)(data_input + 36) = 0x11e45ca3 + 1;
    *(unsigned int *)(data_input + 40) = 0x19c1fbe5 + 1;
    *(unsigned int *)(data_input + 44) = 0xef520a1a + 1;
    *(unsigned int *)(data_input + 48) = 0x45249ff6 + 1;
    *(unsigned int *)(data_input + 52) = 0x179b4fdf + 1;
    *(unsigned int *)(data_input + 56) = 0x7b412bad + 1;
    *(unsigned int *)(data_input + 60) = 0x10376ce6 + 1;

    return 64;
}

int main(int argc, char **argv)
{
	int fd;
	int i,j ;
	int test_length = 0;
	unsigned int data_in;
	unsigned int data_out;
	fd = open("/dev/aes_des_d0", O_RDWR);
	if(fd == 0)
	{
		printf("open device file failed %d\n",fd);
		return -1;
	}
	data_in = (unsigned int)mmap(NULL, DMA_BUFFER_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd,0);
	data_out = data_in + DMA_BUFFER_SIZE/2;
	if(data_in == -1)
	{
		printf("mmap failed\n");
		close(fd);
		return -2;
	}
	printf("data_in 0x%08X\n",data_in);
	printf("data_out 0x%08X\n",data_out);
	
	printf("=======do encrypt=======\n");
	test_length = get_enc_input_data(data_in);
	if(test_length == 0)
	{
		printf("failed to get_enc_input_data\n");
		return -4;
	}

	printf("====user space: data_in====\n");
	for(i = 0; i<4; i++)
	{
		for(j=0; j<4; j++)
			printf("0x%08X ",*(unsigned int *)(data_in + (i*4 +j)*4));
		printf("\n");
	}
	if(ioctl(fd, ES_ENCRYPT, NULL) < 0)
	{
		printf("get en_crypt data failed\n");
		return -3;
	}
	printf("====user space  :data_out===\n");

	for(i = 0; i<4; i++)
	{
		for(j=0; j<4; j++)
			printf("0x%08X ",*(unsigned int *)(data_out + (i*4 +j)*4));
		printf("\n");
	}
	printf("====do decrypt=====\n");
	test_length = get_dec_input_data(data_in);
	if(test_length == 0)
	{
		printf("failed to get_dec_input_data\n");
		return -5;
	}

	printf("====user space: data_in====\n");
	for(i = 0; i<4; i++)
	{
		for(j=0; j<4; j++)
			printf("0x%08X ",*(unsigned int *)(data_in + (i*4 +j)*4));
		printf("\n");
	}
	if(ioctl(fd, ES_DECRYPT, NULL) < 0)
	{
		printf("get de_crypt data failed\n");
		return -6;
	}
	printf("====user space  :data_out===\n");

	for(i = 0; i<4; i++)
	{
		for(j=0; j<4; j++)
			printf("0x%08X ",*(unsigned int *)(data_out + (i*4 +j)*4));
		printf("\n");
	}

	munmap((char *)data_in, DMA_BUFFER_SIZE);
	close(fd);
	return 0;
}

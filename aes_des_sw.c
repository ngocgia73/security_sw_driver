/*
 * author: giann <ngocgia73@gmail.com>
 * des   : simple encrypt/decrypt driver used mmap
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/interrupt.h>
#include <linux/major.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <asm/uaccess.h>
#include <linux/dma-mapping.h>
#include <asm/cacheflush.h>
#include <linux/platform_device.h>
#include <linux/semaphore.h>
#include <linux/ioport.h>
#include <asm/io.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/ioctl.h>

#define SIZE_64K            (64 << 10)
#define DMA_BUFFER_SIZE     SIZE_64K

#define DEVICE_NAME 	"aes_des_sw"
#define MODULE_NAME 	"sw_security"

// Use 'e' as magic number
#define IOC_MAGIC  'e'
#define ES_ENCRYPT 	_IOWR(IOC_MAGIC, 5, __u8)
#define ES_DECRYPT 	_IOWR(IOC_MAGIC, 6, __u8)
static dev_t dev_num;
static struct class *cls;
static struct device *dev;
static struct cdev *my_cdev;
// names used to display in /sys/class
const char * class_name = "aes_des_sc";

static struct semaphore sema;
static void *info_va_tmp = NULL;
struct sec_file_data {
	void 		*info_va;
	dma_addr_t 	info_pa;
	int 		info_size;
};

static int i = 0;
static int j = 0;
static int ae_sw_open(struct inode *inode, struct file *fp)
{
	printk(KERN_INFO "entering %s\n",__func__);
	struct sec_file_data *p_data = kzalloc(sizeof(struct sec_file_data), GFP_KERNEL);
	if(IS_ERR(p_data))
	{
		printk(KERN_ERR "can't alloc memory for p_data\n");
		return -ENOMEM;
	}
	// store data to private_data
	fp->private_data = p_data;
	return 0;
}

static int ae_sw_close(struct inode *inode, struct file *fp)
{
	printk(KERN_INFO "entering %s\n",__func__);
	struct sec_file_data *p_data = fp->private_data;
	if(p_data->info_va)
	{
		free_pages((unsigned int)p_data->info_va, get_order(p_data->info_size));
		p_data->info_va = NULL;
	}
	kfree(p_data);
	fp->private_data = NULL;
	info_va_tmp = NULL;
	return 0;
}

static ssize_t ae_sw_read(struct file *fp, char __user *buf, size_t len, loff_t *off)
{
	printk(KERN_INFO "entering %s\n",__func__);
	return 0;
}

static ssize_t ae_sw_write(struct file *fp, const char __user *buf, size_t len, loff_t *off)
{
	printk(KERN_INFO "entering %s\n",__func__);
	return 0;
}

static void do_encrypt(void)
{
	down(&sema);
	// do something
	// usually this part done by hardware 
	// in here just simulate by simple software
	printk(KERN_INFO "=======kernel space : do encrypt========\n");
	for(i = 0 ; i < 4; i++)
	{
		for(j = 0 ; j < 4; j++)
			printk(KERN_INFO "0x%08X \n",*(unsigned int *)(info_va_tmp + (i*4 + j)*4));
		printk(KERN_INFO "\n");
	}
	// take data_in + 1 then put it in data_out
	
	for(i = 0 ; i < 4; i++)
	{
		for(j = 0 ; j < 4; j++)
				*(unsigned int *)(info_va_tmp + (DMA_BUFFER_SIZE/2)+(i*4 + j)*4) = *(unsigned int*)(info_va_tmp+(i*4 +j)*4) + 1; 
	}
	up(&sema);

}

static void do_decrypt(void)
{
	down(&sema);
	// do something
	// usually this part done by hardware 
	// in here just simulate by simple software
	printk(KERN_INFO "=======kernel space : do decrypt========\n");
	for(i = 0 ; i < 4; i++)
	{
		for(j = 0 ; j < 4; j++)
			printk(KERN_INFO "0x%08X \n",*(unsigned int *)(info_va_tmp + (i*4 + j)*4));
		printk(KERN_INFO "\n");
	}
	// take data_in -1  then put it in data_out
	
	for(i = 0 ; i < 4; i++)
	{
		for(j = 0 ; j < 4; j++)
				*(unsigned int *)(info_va_tmp + (DMA_BUFFER_SIZE/2)+(i*4 + j)*4) = *(unsigned int*)(info_va_tmp+(i*4 +j)*4) - 1; 
	}
	up(&sema);

}

static long ae_sw_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	printk(KERN_INFO "entering %s\n",__func__);
	switch(cmd)
	{
		case ES_DECRYPT:
			do_decrypt();
			break;
		case ES_ENCRYPT:
			do_encrypt();
			break;
		default:
			break;
	}
	return 0;
}

static int ae_sw_mmap(struct file *fp, struct vm_area_struct *vma)
{
	printk(KERN_INFO "entering %s\n",__func__);
	int ret = 0;
	struct sec_file_data *p_data = fp->private_data;
	p_data->info_size = vma->vm_end - vma->vm_start;
	// check flag set by user space
	if(!(vma->vm_flags  & VM_WRITE))
	{
		printk(KERN_ERR "PROT_WRITE please\n");
		ret = -EINVAL;
		goto __ERR;
	}
	if(!(vma->vm_flags & VM_SHARED))
	{
		printk(KERN_ERR "MAP_SHARED please\n");
		ret = -EINVAL;
		goto __ERR;
	}

	// step 1: allocate mem
	if(!p_data->info_pa)
	{
		struct page *p_page = NULL;
		// allocate memory . maximum is 4MB if used this method
		p_page = alloc_pages(GFP_KERNEL, get_order(p_data->info_size));
		if(!p_page)
			p_data->info_va = NULL;
		else
		{
			p_data->info_va = page_address(p_page); // start virtual address
			p_data->info_pa = page_to_phys(p_page); // start physical address
		}
		if(!p_data->info_va)
		{
			printk(KERN_ERR "couldn't alloc data input memory\n");
			return -ENOMEM;
		}
	}
	else
	{
		// because we used buff cacheable
		printk(KERN_INFO "%s is called before\n",__func__);
		return -ENOMEM;
	}
	// indicate the offset from start hardware address
	vma->vm_pgoff = p_data->info_pa >> PAGE_SHIFT;

	// step 2: remap mem
	if(remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, p_data->info_size, vma->vm_page_prot))
	{
		printk(KERN_ERR "remap_pfn_range failed\n");
		free_pages((unsigned long)p_data->info_va, get_order(p_data->info_size));
		p_data->info_va = NULL;
	}
	info_va_tmp = p_data->info_va;
	// for debug
	printk(KERN_INFO "mmap V 0x%08X P 0x%08X SIZE 0x%08X\n",(unsigned int)p_data->info_va,
			(unsigned int)p_data->info_pa, p_data->info_size); 	
__ERR:
	return ret;
}
static struct file_operations aes_des_fops = {
	.owner 		= 	THIS_MODULE,
	.open 		= 	ae_sw_open,
	.release 	= 	ae_sw_close,
	.read 		= 	ae_sw_read,
	.write 		= 	ae_sw_write,
	.unlocked_ioctl = 	ae_sw_ioctl,
	.mmap 		= 	ae_sw_mmap,
};

static int es_probe(struct platform_device *pdev)
{
	printk(KERN_INFO "entering %s\n",__func__);
	// init semaphore
	sema_init(&sema, 1);
	return 0;
}

static int __devexit es_remove(struct platform_device *pdev)
{
	printk(KERN_INFO "entering %s\n",__func__);
	return 0;
}

static struct platform_driver ae_sw_driver = {
	.driver = {
		.owner 	= 	THIS_MODULE,
		.name 	= 	MODULE_NAME,
	},
	.probe 	= 	es_probe,
	.remove = 	__devexit_p(es_remove),
};

static void ae_device_release(struct device *dev)
{
	printk(KERN_INFO "entering %s\n",__func__);
	// do nothing
}

static struct platform_device ae_sw_device = {
	.name 	= 	MODULE_NAME, 	
	.id 	= 	-1,
	.dev 	= {
		.release 	= 	ae_device_release,
	}
};

static int __init ae_sw_init(void)
{
	printk(KERN_INFO "entering %s\n",__func__);
	int ret = -1;
	ret = platform_device_register(&ae_sw_device);
	if(ret < 0)
	{
		printk(KERN_ERR "register platform device failed %d \n",ret);
		return ret;
	}
	ret = platform_driver_register(&ae_sw_driver);
	if(ret < 0)
	{
		printk(KERN_ERR "register platform driver failed %d\n",ret);
		return ret;
	}
	ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
	if(ret < 0)
	{
		printk(KERN_ERR "failed to alloc_chrdev_region %d\n",ret);
		goto __FAILED_REGISTER_DEVNUM;
	}
	cls = class_create(THIS_MODULE, class_name);
	if(IS_ERR(cls))
	{
		printk(KERN_ERR "failed to create class device\n");
		goto __FAILED_CREATE_CLASS_DEVICE;
	}
	dev = device_create(cls, NULL, dev_num, NULL, "aes_des_d%d",MINOR(dev_num));
	if(IS_ERR(dev))
	{
		printk(KERN_ERR "failed to create device\n");
		goto __FAILED_CREATE_DEVICE;
	}
	my_cdev = cdev_alloc();
	if(IS_ERR(my_cdev))
	{
		printk(KERN_ERR "failed to alloc cdev\n");
		goto __FAILED_CDEV_ALLOC;
	}
	cdev_init(my_cdev, &aes_des_fops);
	ret = cdev_add(my_cdev, dev_num, 1);
	if(ret < 0)
	{
		printk(KERN_ERR "failed to cdev_add\n");
		goto __FAILED_CDEV_ADD;
	}
	return ret;
__FAILED_CDEV_ADD:
	cdev_del(my_cdev);
__FAILED_CDEV_ALLOC:
	device_destroy(cls, dev_num);
__FAILED_CREATE_CLASS_DEVICE:
	class_destroy(cls);
__FAILED_CREATE_DEVICE:
	unregister_chrdev_region(dev_num, 1);
__FAILED_REGISTER_DEVNUM:
	return ret;
}

static void __exit ae_sw_exit(void)
{
	printk(KERN_INFO "entering %s\n",__func__);
	cdev_del(my_cdev);
	device_destroy(cls, dev_num);
	class_destroy(cls);
	unregister_chrdev_region(dev_num, 1);

	platform_driver_unregister(&ae_sw_driver);
	platform_device_unregister(&ae_sw_device);
}

module_init(ae_sw_init);
module_exit(ae_sw_exit);

MODULE_DESCRIPTION("GIANN : security driver");
MODULE_AUTHOR("GIANN : ngocgia73@gmail.com");
MODULE_LICENSE("GPL");

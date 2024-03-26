#include <asm/processor.h>
#include <asm/alternative.h>
#include <linux/interrupt.h>
#include <uapi/asm/kvm_para.h>

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <asm/current.h>
#include <linux/sched.h>

#include <asm/uaccess.h>
#include <linux/ctype.h>
#include <linux/smp.h>

#include <asm/segment.h>
#include <linux/buffer_head.h>
#include <asm/processor.h>
#include <linux/sched.h>
#include <linux/delay.h>

MODULE_LICENSE("GPL");

#define DEV_ID 232
#define DEVNAME "dump_dev" 
extern unsigned long trampoline(unsigned long pi,unsigned long app_baseaddr,unsigned long app_size);
extern void work_map(void);

unsigned long urdtsc(void)
{
    unsigned int lo,hi;

    __asm__ __volatile__
    (
        "rdtsc":"=a"(lo),"=d"(hi)
    );
    return (unsigned long)hi<<32|lo;
}
void clear_ifg(void)
{
	__asm("cli \n"
		:
		:
		:
		);
}
void start_ifg(void)
{
	__asm("sti \n"
		:
		:
		:
		);
}

static void ptid(void *vcpu){
    int cpu_id = get_cpu();
    printk("hello u_cpu:%d\n",cpu_id);
}
//smp_call
void do_smp_call(int u_cpu){
    //cpumask_t cpu_mask;
    int cpu_id = get_cpu();
    printk("attack_cpu:%d\n",cpu_id);
    smp_call_function_single(u_cpu,ptid,NULL,1);
}
// open dev
static int dump_dev_open(struct inode *inode, struct file *filp) 
{   
    return 0; 
} 
// release dev
static int dump_dev_release(struct inode *inode, struct file *filp) 
{ 
    return 0; 
} 
// read dev
static ssize_t dump_dev_read(struct file *filp, char __user *buf, size_t size, loff_t *offset) 
{
    unsigned long pi,*data_page,app_size;
    unsigned long pp[3];
    copy_from_user(pp,buf,size);
    pi=pp[0];
    data_page=pp[1];
    app_size=pp[2];
    clear_ifg();
    trampoline(pi,data_page,app_size);
    work_map();
    start_ifg();
  
    return 0;
} 
// write dev
static ssize_t dump_dev_write(struct file *filp, const char __user *buf, size_t size, loff_t *offset) 
{   
    return size; 
} 

static struct file_operations fops = {
    .owner = THIS_MODULE, 
    .open = dump_dev_open, 
    .release= dump_dev_release, 
    .read = dump_dev_read, 
    .write = dump_dev_write, 
}; 

static int __init dump_dev_init(void) 
{   
    int ret;
    cpumask_t cpu_mask;
    int cpu_id = get_cpu();
    
    ret = register_chrdev(DEV_ID,DEVNAME,&fops);
 
    if (ret < 0) {
        printk(KERN_EMERG DEVNAME "can't register major number.\n");
        return ret;
    }
    return 0;
}

static void __exit dump_dev_exit(void)
{
    unregister_chrdev(DEV_ID,DEVNAME);
}

module_init(dump_dev_init);
module_exit(dump_dev_exit);

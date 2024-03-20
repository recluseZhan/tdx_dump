#define KVM_HYPERCALL   ".byte 0x0f,0x01,0xc1"
#define KVM_HC_VAPIC_POLL_IRQ  2

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

MODULE_LICENSE("GPL");

//extern int calc_md5(char*filename,char*dest)

//static unsigned long data0[4] ={0x0,0x0,0x0,0x0};
//static unsigned long data1 =0x0;
//static unsigned long data2 =0x0;
static int data = 0;
#define DEV_ID 232
#define DEVNAME "dump_dev" 
static unsigned long crc_ssa=0;
static unsigned long crc_anchor=0;
static unsigned long crc_worker=0;
__attribute__((aligned(4096))) uint8_t pp0[4096] = {0x0};
__attribute__((aligned(4096))) uint8_t pp1[4096] = {0x0};
//__attribute__((aligned(4096))) uint8_t pp[4096] = {0x0};
__attribute__((aligned(4096))) uint8_t data_tr[4096] = {0};
__attribute__((aligned(4096))) uint8_t end[1000] = {0};
__attribute__((aligned(4096))) uint8_t test[4096] = {0};

extern unsigned long trampoline(unsigned long pi,unsigned long app_baseaddr,unsigned long app_size);

unsigned long urdtsc(void)
{
    unsigned int lo,hi;

    __asm__ __volatile__
    (
        "rdtsc":"=a"(lo),"=d"(hi)
    );
    return (unsigned long)hi<<32|lo;
}

//vmcall
static inline long kvm_hypercall0(unsigned int nr)
{
	long ret;
	asm volatile(KVM_HYPERCALL
		     : "=a"(ret)
		     : "a"(nr)
		     : "memory");
	return ret;
}

static inline long kvm_hypercall4(unsigned int nr, unsigned long p1,
				  unsigned long p2, unsigned long p3,
				  unsigned long p4)
{
    long ret;
    asm volatile(KVM_HYPERCALL
        : "=a"(ret)
        : "a"(nr), "b"(p1), "c"(p2), "d"(p3), "S"(p4)
        : "memory");
    return ret;
}

//
static int launch_time(void){
    
     return 0;
}
static void ptid(void *vcpu){
	unsigned long t1,t2;
	unsigned long p = 0xa;
	unsigned int cur_cpu = smp_processor_id();
	//kvm_hypercall4(KVM_HC_VAPIC_POLL_IRQ,(unsigned long)p,(unsigned long)pp1,(unsigned long)data_tr,(unsigned long)0xbb);
}
//smp_call
void do_smp_call(void){
    cpumask_t cpu_mask;
    int cpu_id = get_cpu();
    //smp_call_function_single(1,ptid,NULL,1);
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
    trampoline(pi,data_page,app_size);
    return 0;
    //return size; 
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

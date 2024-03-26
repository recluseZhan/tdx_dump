#include<linux/init.h>
#include<linux/module.h>
#include<linux/mm.h>
#include<linux/mm_types.h>
#include<linux/sched.h>
#include<linux/export.h>
#include<linux/init_task.h>
#include<linux/delay.h>

MODULE_LICENSE("GPL");

unsigned long app_baseaddr;
unsigned long app_size;
unsigned long t_pid;
int index;

struct PageInfo{
   unsigned long vir_addr;
   unsigned long phy_addr;
};
__attribute__((aligned(4096))) int random_data_page[1024]={0xaa};

void clear_ifg(void *info)
{
	__asm("cli \n"
		:
		:
		:
		);
     unsigned int cpu;
     cpu = task_cpu(current);
}

void start_ifg(void *info)
{
	__asm("sti \n"
		:
		:
		:
		);
}

void get_appbase(unsigned long t_pid)
{
    struct task_struct *task,*p;
    struct list_head *pos;
    int count=0;

    task=&init_task;
    list_for_each(pos,&task->tasks)
    {
        p=list_entry(pos, struct task_struct, tasks);
        count++;
	if (p->pid == t_pid )
	{
            app_baseaddr = p->mm->mmap_base;
            app_size  = p->mm->task_size;
            break;
	}
    }
    return;
}

void non_v2p(unsigned long vaddr,unsigned long t_pid,struct PageInfo pinfo[],int i){
    
    unsigned long paddr=0;
    unsigned long page_addr=0;
    unsigned long P_OFFSET=0;
    unsigned long *pgd, *pud, *pmd, *pte;
    unsigned long pte_mask;
     
    struct task_struct *task,*p;
    struct list_head *pos;
    int count = 0;
 
    task = &init_task;
    list_for_each(pos,&task->tasks)
    {
        p=list_entry(pos, struct task_struct, tasks);
        count++;
	if (p->pid == t_pid)
	{
            pgd = (unsigned long)p->mm->pgd;
            pgd = pgd + ((vaddr>>39) & 0x1FF);
            break;
	}
    }
    
    pud = (unsigned long *)(((unsigned long)*pgd & PTE_PFN_MASK) + PAGE_OFFSET);
    pud = pud + ((vaddr>>30) & 0x1FF);
    
    pmd = (unsigned long *)(((unsigned long)*pud & PTE_PFN_MASK) + PAGE_OFFSET);
    pmd = pmd + ((vaddr>>21) & 0x1FF);

    pte = (unsigned long *)(((unsigned long)*pmd & PTE_PFN_MASK) + PAGE_OFFSET);
    pte = pte + ((vaddr>>12) & 0x1FF);
    
    pinfo[i].vir_addr = vaddr;
    pinfo[i].phy_addr = *pte;
    *pte = *pte &0xfffffffffffffffe;

    page_addr= (*pte) & PAGE_MASK;
    P_OFFSET=vaddr&~PAGE_MASK;
    paddr=page_addr|P_OFFSET;  
    return;
}

void en_v2p(unsigned long vaddr,unsigned long t_pid,unsigned long phy_addr){
    unsigned long paddr=0;
    unsigned long page_addr=0;
    unsigned long P_OFFSET=0;
    unsigned long *pgd, *pud, *pmd, *pte;
    unsigned long pte_mask;
    
    struct task_struct *task,*p;
    struct list_head *pos;
    int count = 0;
    
    task = &init_task;
    list_for_each(pos,&task->tasks)
    {
        p=list_entry(pos, struct task_struct, tasks);
        count++;
	if (p->pid == t_pid)
	{
            pgd = (unsigned long)p->mm->pgd;
            pgd = pgd + ((vaddr>>39) & 0x1FF);
            break;
	}
    }

    pud = (unsigned long *)(((unsigned long)*pgd & PTE_PFN_MASK) + PAGE_OFFSET);
    pud = pud + ((vaddr>>30) & 0x1FF);
    
    pmd = (unsigned long *)(((unsigned long)*pud & PTE_PFN_MASK) + PAGE_OFFSET);
    pmd = pmd + ((vaddr>>21) & 0x1FF);

    pte = (unsigned long *)(((unsigned long)*pmd & PTE_PFN_MASK) + PAGE_OFFSET);
    pte = pte + ((vaddr>>12) & 0x1FF);

    *pte = phy_addr;
   
    page_addr= (*pte) & PAGE_MASK;
    P_OFFSET=vaddr&~PAGE_MASK;
    paddr=page_addr|P_OFFSET;
    return;
}

struct PageInfo pinfo[1000];
unsigned long laucher_non_v2p(unsigned long app_baseaddr,unsigned long t_pid,unsigned long app_size){
   unsigned long page_size;
   unsigned long current_vaddr;
   int i = 0;
   for(page_size=0; page_size<app_size; page_size= page_size+0x1000)
   {
        __flush_tlb_local();
        __flush_tlb_global();
        current_vaddr = app_baseaddr + page_size;
        if(current_vaddr == &random_data_page){
             index = i;
             break;
        }
        non_v2p(current_vaddr,t_pid,pinfo,i);
        i++;
   }
   index = i;  
   return 0;
}

unsigned long launch_en_v2p(struct PageInfo pinfo[index],unsigned long t_pid){
    int i;
    for(i=0; i<index; i++)
    {
        __flush_tlb_local();
        __flush_tlb_global();
        en_v2p(pinfo[i].vir_addr,t_pid,pinfo[i].phy_addr);
    }
    return 0;
}

unsigned long v2p(unsigned long vaddr,unsigned long t_pid){
    unsigned long paddr=0;
    unsigned long page_addr=0;
    unsigned long P_OFFSET=0;
    unsigned long *pgd, *pud, *pmd, *pte;
    
    struct task_struct *task,*p;
    struct list_head *pos;
    int count = 0;
    
    task = &init_task;
    list_for_each(pos,&task->tasks)
    {
        p=list_entry(pos, struct task_struct, tasks);
        count++;
	if (p->pid == t_pid)
	{
	    pgd = (unsigned long)p->mm->pgd;
	    pgd = pgd + ((vaddr>>39) & 0x1FF);
	    break;
	}
    }
    
    pud = (unsigned long *)(((unsigned long)*pgd & PTE_PFN_MASK) + PAGE_OFFSET);
    pud = pud + ((vaddr>>30) & 0x1FF);
    
    pmd = (unsigned long *)(((unsigned long)*pud & PTE_PFN_MASK) + PAGE_OFFSET);
    pmd = pmd + ((vaddr>>21) & 0x1FF);

    pte = (unsigned long *)(((unsigned long)*pmd & PTE_PFN_MASK) + PAGE_OFFSET);
    pte = pte + ((vaddr>>12) & 0x1FF);
    
    page_addr= (*pte) & PAGE_MASK;
    P_OFFSET=vaddr&~PAGE_MASK;
    paddr=page_addr|P_OFFSET;
    return paddr;
}

unsigned long trampoline(unsigned long pi,unsigned long app_baseaddr,unsigned long app_size){
    asm volatile(
        "mov %%cr3,%%rax\n\t"
        "mov %%rax,%%cr3\n\t"
        :::
    );
    laucher_non_v2p(app_baseaddr,pi,app_size);
    launch_en_v2p(pinfo,pi);
    return 0;
}

static int __init limit_init(void)
{   
    //__flush_tlb_local();
    //__flush_tlb_global();
    //preempt_disable();
    //local_irq_disable();
    //native_write_cr3(__native_read_cr3());
    
    //unsigned long pi = 42490; 
    //unsigned long va = 0x7ffc3958b374;
    //trampoline(pi,va,1);
  
   
  /*
    vaddr1 = &trampoline;
    paddr1 = v2p(vaddr1,(unsigned long)current->pid);
    printk("trampoline_pid=%d",current->pid);
    printk("trampoline_gva=0x%lx",vaddr1);
    printk("trampoline_gpa=0x%lx",paddr1);
    
 */
    printk(KERN_ALERT"handle_limit module is entering..\n");
    return 0;
}

static void __exit limit_exit(void)
{
    printk(KERN_ALERT"handle_limit module is leaving..\n");
}

EXPORT_SYMBOL(trampoline);
EXPORT_SYMBOL(v2p);

module_init(limit_init);
module_exit(limit_exit);

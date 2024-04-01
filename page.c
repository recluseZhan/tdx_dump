#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched/signal.h>
#include <linux/sched.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

__attribute__((aligned(4096))) unsigned long new_pgd[512];
__attribute__((aligned(4096))) unsigned long new_pud[512];
__attribute__((aligned(4096))) unsigned long new_pmd[512];
__attribute__((aligned(4096))) unsigned long new_pte[512];

unsigned long copy_table(unsigned long vaddr,unsigned long t_pid){
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
	    for(int i=0;i<512;i++){
	        new_pgd[i] = *(pgd+i);
	    }
	    pgd = pgd + ((vaddr>>39) & 0x1FF);
	    break;
	}
    }
    
    pud = (unsigned long *)(((unsigned long)*pgd & PTE_PFN_MASK) + PAGE_OFFSET);
    for(int i=0;i<512;i++){
	new_pud[i] = *(pud+i);
    }
    pud = pud + ((vaddr>>30) & 0x1FF);
    
    pmd = (unsigned long *)(((unsigned long)*pud & PTE_PFN_MASK) + PAGE_OFFSET);
    for(int i=0;i<512;i++){
	new_pmd[i] = *(pmd+i);
    }
    pmd = pmd + ((vaddr>>21) & 0x1FF);

    pte = (unsigned long *)(((unsigned long)*pmd & PTE_PFN_MASK) + PAGE_OFFSET);
    for(int i=0;i<512;i++){
	new_pte[i] = *(pte+i);
    }
    //pte = pte + ((vaddr>>12) & 0x1FF);  
    //page_addr= (*pte) & PAGE_MASK;
    //P_OFFSET=vaddr&~PAGE_MASK;
    //paddr=page_addr|P_OFFSET;
    return 0;
}

void change_cr3(unsigned long t_pid) {
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
            p->mm->pgd = (pgd_t *)new_pgd;
            break;
	}
    }
}

static int __init page_init(void)
{
   
    //int pid = 5098; // Example PID
    //unsigned long pa;
    //unsigned long va =0x7ffcb57e2a30;
    //pa = v2p(va,pid);
    // Allocate and initialize new page table
   

    // Map some physical memory to the new page table
    // Example: Map physical address 0x10000 to virtual address 0xFFFF000000000000
    //mapPage(newPageTable, &a, 0x10000);
    //changeProcessPageTable_by_pid(current->pid, newPageTable);
    //printk("va=%lx pa=%lx\n",va,pa);
    // Change page table for process with given PID
    //changeProcessPageTable_by_pid(pid, newPageTable);
    printk(KERN_INFO "Entering page module\n");
    return 0;
}

static void __exit page_exit(void)
{
    printk(KERN_INFO "Exiting page module\n");
}
EXPORT_SYMBOL(copy_table);
EXPORT_SYMBOL(change_cr3);
module_init(page_init);
module_exit(page_exit);


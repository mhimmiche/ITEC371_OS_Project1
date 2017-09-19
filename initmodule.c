/*
 * Author: Mehdi Himmiche
 * Course: ITEC 371 Project 1
 * This program intercepts every open system call
 * and prevents any user from opening the file 
 * /home/student/sensitive. 
 */

/*  Do not remove these includes. You can add to them */
#include <linux/init.h> 
#include <linux/module.h>
#include <linux/version.h>
#include <linux/miscdevice.h>
#include <linux/highmem.h>
#include <asm/unistd.h> 

/* The following typedef's are required to provide more information 
 * about your module. */ 
MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("Mehdi"); // Change to your name. 
MODULE_DESCRIPTION("File Monitor");
MODULE_VERSION("0.1");


/* Variable to store the memory address in the code segment of the original
   open system call */
asmlinkage int (*original_open)(const char* __user, int, int);

/* Variable that you need to initialze with the address of the sys_call_table
 * Note: change the address below (0xffffffff816a0800) to the address 
 * of the syscall table on your CentOS box
 * This address can be found by: grep /boot/System.map`uname-r`
 * You will see two sys_call_table memory addresses. Choose the one for
 * the 64 bit kernel (so ignore the ia32)
 * Note, you should see a symbol R. This means the sys_call_table is 
 * read only. This is important for later. */
unsigned long *sys_call_table = (unsigned long*)0xffffffff816a0800; 

/* Linux 2.6+ kernels have a new security feature: certain pages can
 * be set to read-only or read-write. What is a page?  We will define
 * what a page is when studying memory management. The pages that
 * store system call tables are set to read only. So we must first
 * change that in the kernel. Read this code...there are a few
 * questions you must answer based on this
 */ 
 
/* Structs to let the kernel know this a device */

static const struct file_operations our_fops =\
   {
      .owner = THIS_MODULE,
      .open = &our_open,
	  .write = &our_write,
      .release = &our_release
   };

static struct miscdevice our_device = \
   {
      MISC_DYNAMIC_MINOR,
      "MehdisSuperDuperDeviceThatTotallyDoesntStealData",
      &our_fops
   };

 /* Declaring all global variables we'd be using.
  * This includes a flag to reset, and the array for names of files.
  * The array size has been hard coded to 25 file names because this is a dictatorship and I rule!!
  */
const int ARRAY_SIZE = 25;
int is_set = 0;
char* filenames[ARRAY_SIZE];
int counter = 0;
char* name[20];

static size_t our_write (struct file *file, cont char __user * buffer, size_t length, loff_t* offset) {
	int i;
	if (counter > ARRAY_SIZE-1) 
		return counter;
	counter++;
	for (i=0; i < length && i < BUF_LEN; i++)
		get_user(name[i], buffer+1);
	filenames[counter] = name[i];
	return i;
}

/* This function will be invoked each time a user process attempts
       to open our device. You should keep in mind that the prototype
      of this function may change along different kernel versions. */
static int our_open(struct inode *inode, struct file *file) {
	is_set = 1;
	printk(KERN_INFO "We are in the kernel space\n"); 
    make_rw((unsigned long) sys_call_table);
    original_open = (void*)* (sys_call_table + __NR_open);
    *(sys_call_table + __NR_open) = (unsigned long) custom_open;
    make_ro((unsigned long) sys_call_table);
    return 0;
}

/* This function, in turn, will be called when a process closes our device */
static int our_release(struct inode *inode, struct file *file) {
    is_set = 0;
    make_rw((unsigned long) sys_call_table);
	*(sys_call_table + __NR_open) = (unsigned long) original_open;
	make_ro((unsigned long) sys_call_table);
	printk(KERN_INFO "We are leaving the kernel space\n");
    return 0;
}
 
/* Make a page writeable */
int make_rw (unsigned long address) 
{
  unsigned int level;
  pte_t *pte = lookup_address(address, &level);
  if (pte->pte &~ _PAGE_RW) 
    pte->pte |= _PAGE_RW; 
  return 0;
}

/* Make a page read-only (once we are done with our module, for
   security we must reset the system call table to read only */
int make_ro(unsigned long address) 
{ 
  unsigned int level;
  pte_t *pte = lookup_address(address, &level);
  pte->pte = pte->pte &~ _PAGE_RW;
  return 0;
}

/* Our custom open. Modify this function */
asmlinkage int custom_open(const char* __user file_name, int flags, int mode)
{
	int i, loop_max = counter > ARRAY_SIZE ? ARRAY_SIZE : counter;
	for (i = 0; i < loop_max; i++)
		if (strncmp(file_name, filenames[i]) == 0)
			printk("File opened! Open system call intercepted!"); 
	return original_open(file_name, flags, mode);
}

/* This is the first method that will be called when you load the
   module */
static int __init my_init_module(void) { 
	int retval = misc_register(&our_device);  
	return 0;
}

/* This is the method that is called when you exit a module */
static void __exit my_cleanup_module(void) {
	misc_deregister(&our_device);
	if (is_set == 1) {
		make_rw((unsigned long) sys_call_table);
		*(sys_call_table + __NR_open) = (unsigned long) original_open;
		make_ro((unsigned long) sys_call_table);
		printk(KERN_INFO "We are leaving the kernel space\n");
	}   
	return;
}

/* Here's where we tell Linux which methods to call when loading or
 * removing a module */
module_init(my_init_module);
module_exit(my_cleanup_module);


	


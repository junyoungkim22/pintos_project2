#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);
static bool is_valid_vaddr(const void *va);
void *get_arg(void *esp, int arg_num);

void *get_arg(void *esp, int arg_num)
{
	void *arg_addr = (esp + (8*arg_num));
	return (void*) *((int*)arg_addr);
}

static bool is_valid_vaddr(const void *va)
{
	if(!is_user_vaddr(va))
		return false;
	if(pagedir_get_page(thread_current()->pagedir, va) == NULL)
		return false;
	return true;
	/*
	uint32_t *pt = lookup_page(thread_current()->pagedir , va, false);
	if(pt == NULL)
		return false;
	if(((uint32_t) pt) & PTE_P)
		return true;
	return false;
	*/
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	printf("NUM is %d\n", *((int*)f->esp));
	printf("NUM is %d\n", (int) get_arg(f->esp, 0));
	if(is_valid_vaddr(get_arg(f->esp, 1)))
		printf("valid address\n");
	printf("String to print is %s\n", get_arg(f->esp, 1));
	hex_dump(f->esp, f->esp, 100, true);
  printf ("system call!\n");
  thread_exit ();
}

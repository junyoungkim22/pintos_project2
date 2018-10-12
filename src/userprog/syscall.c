#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/string.h"
#include "devices/shutdown.h"

static void syscall_handler (struct intr_frame *);
static bool is_valid_vaddr(const void *va);
void *get_arg(void *esp, int arg_num);
void sys_exit(int exit_status);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	int syscall_num;
	int fd;
	char *buffer;
	unsigned size;

	syscall_num = (int) get_arg(f->esp, 0);
	switch(syscall_num)
	{
		case SYS_EXIT:
			sys_exit((int) get_arg(f->esp, 1));
			/*
			thread_current()->exit_status = (int) get_arg(f->esp, 1);
			thread_exit();
			*/
			break;
		case SYS_WRITE:
			/*
			if(!is_valid_vaddr(get_arg(f->esp, 2)))
			{
				printf("invalid address\n");
				//do something about invalid address
			}
			*/
			fd = (int) get_arg(f->esp, 1);
			buffer = (char*) get_arg(f->esp, 2);
			size = (unsigned) get_arg(f->esp, 3);
			if(fd == 1)
			{
				putbuf(buffer, size);
			}
			break;
		case SYS_HALT:
			shutdown_power_off();
			break;
	}
	//printf("NUM is %d\n", *((int*)f->esp));
	/*
	printf("NUM is %d\n", (int) get_arg(f->esp, 0));
	if(is_valid_vaddr(get_arg(f->esp, 1)))
	{
		printf("valid address\n");
		printf("String to print is %s\n", get_arg(f->esp, 1));
	}
	hex_dump(f->esp, f->esp, 100, true);
  printf ("system call!\n");
	*/
  //thread_exit ();
}

void sys_exit(int exit_status)
{
	thread_current()->exit_status = exit_status;
	char *save_ptr;
	char *file_name = strtok_r(thread_current()->name, " ", &save_ptr);
	printf("%s: exit(%d)\n", file_name, exit_status);
	thread_exit();
}

void *get_arg(void *esp, int arg_num)
{
	void *arg_addr = (esp + (4*arg_num));
	if(!is_valid_vaddr(arg_addr))
		sys_exit(-1);
	if(!is_valid_vaddr(arg_addr + 3))
		sys_exit(-1);
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


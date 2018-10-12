#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "lib/string.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);
static bool is_valid_vaddr(const void *va);
void *get_arg(void *esp, int arg_num);
void sys_exit(int exit_status);
int allocate_fd(void);
bool fd_compare(struct list_elem *e1, struct list_elem *e2, void *aux);
struct open_file *find_open_file(int fd);

struct 
open_file *find_open_file(int fd)
{
	struct list_elem *e;
	struct list *open_file_list = &thread_current()->open_file_list;
	struct open_file *of;
	for(e = list_begin(open_file_list); e != list_end(open_file_list); e = list_next(e))
	{
		of = list_entry(e, struct open_file, open_file_elem);
		if(of->fd == fd)
			return of;
	}
	return NULL;
}

struct lock filesys_lock;

void
syscall_init (void) 
{
	lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	int syscall_num;
	int fd;
	char *buffer;
	unsigned size;
	bool success;
	char *name;
	struct file *file_addr;
	struct open_file *open_file;

	syscall_num = (int) get_arg(f->esp, 0);
	switch(syscall_num)
	{
		case SYS_EXIT:
			sys_exit((int) get_arg(f->esp, 1));
			break;
		case SYS_CLOSE:
			fd = (int) get_arg(f->esp, 1);
			open_file = find_open_file(fd);
			if(open_file == NULL)
				break;
			list_remove(&open_file->open_file_elem);
			lock_acquire(&filesys_lock);
			file_close(open_file->file);
			lock_release(&filesys_lock);
			free(open_file);
			break;
		case SYS_OPEN:
			name = (char*) get_arg(f->esp, 1);
			if(!is_valid_vaddr(name))
				sys_exit(-1);
			lock_acquire(&filesys_lock);
			file_addr = filesys_open(name);
			lock_release(&filesys_lock);
			if(file_addr == NULL)
			{
				f->eax = -1;
				break;
			}
			fd = allocate_fd();
			open_file = malloc(sizeof(struct open_file));
			open_file->fd = fd;
			open_file->file = file_addr;
			list_insert_ordered(&thread_current()->open_file_list, &open_file->open_file_elem, fd_compare, NULL);
			f->eax = fd;
			break;
		case SYS_WRITE:
			fd = (int) get_arg(f->esp, 1);
			buffer = (char*) get_arg(f->esp, 2);
			size = (unsigned) get_arg(f->esp, 3);
			if(fd == 1)
			{
				putbuf(buffer, size);
			}
			break;
		case SYS_CREATE:
			name = (char*) get_arg(f->esp, 1);
			size = (unsigned) get_arg(f->esp, 2);
			if(!is_valid_vaddr(name))
				sys_exit(-1);
			lock_acquire(&filesys_lock);
			success = filesys_create(name, size);
			lock_release(&filesys_lock);
			f->eax = success;
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
}

int
allocate_fd()
{
	struct list_elem *e;
	struct list *open_file_list = &thread_current()->open_file_list;
	struct open_file *of;
	int allo_fd = 2;
	for(e = list_begin(open_file_list); e != list_end(open_file_list); e = list_next(e))
	{
		of = list_entry(e, struct open_file, open_file_elem);
		if(of->fd == allo_fd)
			allo_fd++;
		else
			break;
	}
	return allo_fd;
}

bool fd_compare(struct list_elem *e1, struct list_elem *e2, void *aux)
{
	(void*) aux;
	struct open_file *of1, *of2;
	of1 = list_entry(e1, struct open_file, open_file_elem);
	of2 = list_entry(e2, struct open_file, open_file_elem);
	return of1->fd < of2->fd;
}

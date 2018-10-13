#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/vaddr.h"
#include "threads/pte.h"
#include "userprog/pagedir.h"

void syscall_init (void);
void sys_exit(int exit_status);

#endif /* userprog/syscall.h */

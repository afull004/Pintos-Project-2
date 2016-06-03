#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"



struct lock fileLock;


static void syscall_handler (struct intr_frame *);
void pushArgs (struct intr_frame *f, int *arg, int n);
void checkValidPtr (const void *vaddr);
void checkValidBuffer (void* buffer, unsigned size);
int userToKernel(const void *vaddr);
int write(int fd, const void *buffer, unsigned size);
int read(int fd, void *buffer, unsigned size);
struct file* getFile (int fd);
struct childProcess* getChildProcess( int pid );
void removeChild (struct childProcess *cp);
int addNewFile(struct file* newFile);
struct childProcess* newChildProcess(int pid);
void exit(int stat);

void syscall_init (void) 
{
  lock_init(&fileLock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


int addNewFile(struct file* newFile){
	struct processFile *newProcessFile = malloc(sizeof(struct processFile));
	newProcessFile->file = newFile;
	newProcessFile->fd = thread_current()->fd;
	thread_current()->fd++;
	list_push_back(&thread_current()->files, &newProcessFile->elem);
	return newProcessFile->fd;
}




static void syscall_handler (struct intr_frame *f UNUSED) {
//	printf ("\n system call!\n");
	//  thread_exit ();

	int arg[3];
	checkValidPtr((const void*)f->esp);

//	printf("%d\n", *(int *) f->esp);

	switch (* (int *) f->esp){
		case SYS_HALT://DONE
		{
			shutdown_power_off(); 
			break;
		}
		case SYS_EXIT://DONE
		{
			pushArgs(f, &arg[0], 1);
			exit(arg[0]);
			break;
		}
		case SYS_EXEC:
		{
			pushArgs(f, &arg[0], 1);
			arg[0] = userToKernel( (const void*) arg[0]);
			pid_t childPID = process_execute( (const char*)arg[0]);
			
			struct childProcess* cProcess = getChildProcess(childPID);
			ASSERT(cProcess);
			

			while(cProcess->load == 0){
				barrier();
			}
			

			if(cProcess->load == 2){
//				printf("ERROR\n");
				f->eax = -1;
			}else{
				f->eax = childPID;
			}	
//			printf("Done\n");
			
			break;
		}
		case SYS_WAIT:
		{
			pushArgs(f, &arg[0], 1);
			f->eax = process_wait(arg[0]);
			break;
		}
		case SYS_CREATE:
		{
			pushArgs(f, &arg[0], 2);
			arg[0] = userToKernel( (const void*) arg[0] );
			
			lock_acquire(&fileLock);
			bool good = filesys_create((const char*)arg[0], (unsigned)arg[1]);
			lock_release(&fileLock);
			f->eax = good;
			break;
		}
		case SYS_REMOVE:
		{

			pushArgs(f, &arg[0], 1);
			arg[0] = userToKernel( (const void*) arg[0] );
			lock_acquire(&fileLock);
			bool good = filesys_remove((const char*) arg[0]);
			lock_release(&fileLock);

			f->eax = good;
			break;
		}
		case SYS_OPEN:
		{
			pushArgs(f, &arg[0], 1);
			arg[0] = userToKernel((const void *) arg[0]);

			lock_acquire(&fileLock);
			struct file *fOpen = filesys_open((const char*) arg[0]);
			if(!fOpen){
				lock_release(&fileLock);
				f->eax = -1;
				break;
			}
			int fd = addNewFile(fOpen);
			lock_release(&fileLock);
			f->eax = fd;



			break; 		
		}
		case SYS_FILESIZE:
		{
			pushArgs(f, &arg[0], 1);
			lock_acquire(&fileLock);
			struct file *file = getFile(arg[0]);
			if(!file){
				lock_release(&fileLock);
				f->eax = -1;
				break;
			}
	
			int sz = file_length(file);
			lock_release(&fileLock);
			

			f->eax = sz;
	
			break;
		}
		case SYS_READ:
		{
			pushArgs(f, &arg[0], 3);
			checkValidBuffer((void *) arg[1], (unsigned)arg[2]);
			arg[1] = userToKernel( (const void*) arg[1] );
			f->eax = read( arg[0], (void *)arg[1], (unsigned)arg[2]);
			break;
		}
		case SYS_WRITE:
		{
			pushArgs(f, &arg[0], 3);
			checkValidBuffer((void *) arg[1], (unsigned) arg[2]);
			arg[1] = userToKernel((const void *) arg[1]);

			f->eax = write(arg[0], (const void *) arg[1],(unsigned) arg[2]);

			break;
		}
		case SYS_SEEK:
		{
			pushArgs(f, &arg[0], 2);
			lock_acquire(&fileLock);
			struct file *file = getFile(arg[0]);
			if(!file){
				lock_release(&fileLock);
				break;
			}
			file_seek(file, (unsigned)arg[1]);
			lock_release(&fileLock);
			break;
		} 
		case SYS_TELL:
		{
			pushArgs(f, &arg[0], 1);
			lock_acquire(&fileLock);
			struct file *file = getFile(arg[0]);
			if(!file){
				lock_release(&fileLock);
				f->eax = -1;
				break;
			}
			off_t off = file_tell(file);
			lock_release(&fileLock);
			f->eax = off;
				

			break;
		}
		case SYS_CLOSE:
		{
			pushArgs(f, &arg[0], 1);
			lock_acquire(&fileLock);
			
			struct thread *cur = thread_current();
			struct list_elem *next;
			struct list_elem *e = list_begin(&cur->files);

			while(e != list_end(&cur->files)){
				next = list_next(e);
				struct processFile *pFile = list_entry(e, struct processFile, elem);
				if(arg[0] == pFile->fd){
					file_close(pFile->file);
					list_remove(&pFile->elem);
					free(pFile);
					break;
				}
				e = next;
			}			


			lock_release(&fileLock); 
			break;
		}
	}

}


void checkValidPtr (const void *vaddr){
	if ((!is_user_vaddr(vaddr) ) || vaddr < ((void *) 0x08048000)){
		exit(-1);
	}
}

void checkValidBuffer (void* buffer, unsigned size)
{
  unsigned i;
  char* local_buffer = (char *) buffer;
  for (i = 0; i < size; i++)
    {
      checkValidPtr((const void*) local_buffer);
      local_buffer++;
    }
}


void pushArgs (struct intr_frame *f, int *arg, int n)
{
  int i;
  int *ptr;
  for (i = 0; i < n; i++){
  	ptr = (int *) f->esp + i + 1;
  	checkValidPtr((const void *) ptr);
  	arg[i] = *ptr;
  }

//  printf("\n\n%s\n\n", userToKernel(arg[0]) );

}


void exit(int stat){
	struct thread *cur = thread_current();
	if(threadExists(cur->parent)){
		cur->cp->status = stat;
	}
	printf("%s: exit(%d)\n", cur->name, stat);
	thread_exit();
}



int userToKernel(const void *vaddr)
{
	checkValidPtr(vaddr);
	void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
	if (!ptr){
		exit(-1);
	}

	return (int) ptr;
}

int read(int fd, void *buffer, unsigned size){

	if(fd == STDIN_FILENO){
		unsigned i;
		uint8_t* buff = (uint8_t*) buffer;
		for(i=0; i<size; i++){
			buff[i] = input_getc();
		}
		return size;
	}
	lock_acquire(&fileLock);
	struct file *f = getFile(fd);
	if(!f){
		lock_release(&fileLock);
		return -1;
	}

	int bytes = file_read(f, buffer, size);
	lock_release(&fileLock);
	return bytes;

}



int write (int fd, const void *buffer, unsigned size){
  if (fd == STDOUT_FILENO){
  	putbuf(buffer, size);
  	return size;
  }

  lock_acquire(&fileLock);
  struct file *f = getFile(fd);
  if (!f){

  	lock_release(&fileLock);
  	return -1;
  }

  int bytes = file_write(f, buffer, size);

  lock_release(&fileLock);
  return bytes;
}


struct file* getFile (int fd)
{


  struct thread *t = thread_current();
  struct list_elem *e;

  for (e = list_begin (&t->files); e != list_end (&t->files);
       e = list_next (e))
        {
          struct processFile *pf = list_entry (e, struct processFile, elem);
          if (fd == pf->fd)
	    {
	      return pf->file;
	    }
        }
  return NULL;
}


struct childProcess* newChildProcess(int pid){
	struct childProcess* cp = malloc(sizeof(struct childProcess));
	cp->pid = pid;
	cp->load = 0;
	cp->wait = false;
	cp->exit = false;
	lock_init(&cp->waitLock);
	list_push_back(&thread_current()->children, &cp->elem);
	return cp;
}


struct childProcess* getChildProcess( int pid ){
	struct thread *cur = thread_current();
	struct list_elem *e;

	for(e = list_begin(&cur->children); e != list_end(&cur->children); e = list_next(e)){
		struct childProcess *cp = list_entry(e, struct childProcess, elem);
		if(pid == cp->pid){
			return cp;

		}
	}
//	printf("RETURNING NULL\n");
	return NULL;
}

void removeChild (struct childProcess *cp){
//	printf("removing cp %s\n\n", thread_current()->name);
	list_remove(&cp->elem);
	free(cp);
}




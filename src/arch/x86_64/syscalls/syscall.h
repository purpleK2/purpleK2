#ifndef SYSCALL_H
#define SYSCALL_H 1

#define SYS_exit  0
#define SYS_open  1
#define SYS_read  2
#define SYS_write 3
#define SYS_close 4
#define SYS_ioctl 5
#define SYS_seek  6
#define SYS_fcntl 7

void sys_exit(int status);
int sys_open(char *path, int mode);
int sys_read(int fd, char *buf, int count);
int sys_write(int fd, const char *buf, int count);
int sys_close(int fd);
int sys_ioctl(int fd, int request, void *arg);
int sys_seek(int fd, int whence, int offset);
int sys_fcntl(int fd, int op, void *arg);

long handle_syscall(long num, long arg1, long arg2, long arg3, long arg4,
                    long arg5, long arg6);

#endif // SYSCALL_H
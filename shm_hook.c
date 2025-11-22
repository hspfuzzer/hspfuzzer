#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
// Remove dependency on systemd
//#include <systemd/sd-daemon.h> 
#include <sys/select.h>
#include <sys/shm.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>  
#include <sys/stat.h>  
#include <sys/time.h>
#include <pthread.h>
#include <ctype.h>
#include<poll.h>
#include <fcntl.h>
#include <dlfcn.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;

#define DEBUG 0  // 0 if not debug mode, 1 if debug mode

// The FDs to communicate with the afl-fuzz
#define FORKSRV_FD 198
#define FORKNET_READ_FD (FORKSRV_FD + 3)
#define FORKNET_WRITE_FD (FORKSRV_FD + 4)

typedef enum protocol_type {
  /* 00 */ PRO_TCP,
  /* 01 */ PRO_UDP
} protocol_type_t;

typedef enum nethook_command {
  /* 01 */ NETHOOK_CMD_SEED_READY = 1,     // Seed is ready
  /* 02 */ NETHOOK_CMD_SEED_READY_NEWCON,  // Seed is ready && need new
                                           // connection
  /* 40 */ NETHOOK_CMD_CONSUMED =
      40,                             // Hook side tells fuzz side data consumed
  /* 41 */ NETHOOK_CMD_TIME_OUT = 41  // Hook side tells fuzz side timeout
} nethook_command_t;

// Settings
int   shm_id;                              // share memory id
u8   *shared_memory;
char *net_ip = "127.0.0.1";
u8    net_protocol = 0;
u32   net_port = 10001;
u32   default_wait_try_num = 10;
int   wait_dummy_conn_second = 0;
int   wait_dummy_conn_millisecond = 500;
int   wait_accept_second = 0;
int   wait_accept_millisecond = 50;
int   wait_recv_second = 0;
int   wait_recv_millisecond = 50;
int   wait_consume_second = 0;
int   wait_consume_millisecond = 50;

// Internal state
pthread_t   thread;
volatile u8 has_start_thread;
volatile u8 has_got_server_fd;
int         server_fd;  // The server listening fd
static int new_server_fd;
volatile u8 has_got_dummy_fd;
int         dummy_fd=-1;  // The dummy client fd
static int new_dummy_fd=-1;
struct sockaddr_in dummy_servaddr;    //the message of dummy_fd

volatile u8
    has_a_connection;  // Is the server under test accepted a connection?
volatile u8 need_a_connection;    // Do we need a connection?
volatile u8 is_data_ready;        // Are the data ready to read?
volatile u8 is_data_consumed;     // Are the data be consumed?
volatile u8 need_break_conn;      // Do we need to break current connection?
volatile u8 has_done_break_conn;  // Do we finish breaking current connection?

volatile u32 cur_seed_length;   // current seed length
volatile u32 orig_seed_length;  // original(last time) seed length

char* msg_buf=NULL;                              //buffer for recvmsg()
struct epoll_event* server_ev;              //ev of server_sock
struct epoll_event* client_ev;              //ev of client_sock

pthread_mutex_t dummy_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  dummy_cond = PTHREAD_COND_INITIALIZER;

pthread_mutex_t accept_wait_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  accept_wait_cond = PTHREAD_COND_INITIALIZER;

pthread_mutex_t accept_done_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  accept_done_cond = PTHREAD_COND_INITIALIZER;

pthread_mutex_t data_ready_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  data_ready_cond = PTHREAD_COND_INITIALIZER;

pthread_mutex_t data_consumed_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  data_consumed_cond = PTHREAD_COND_INITIALIZER;

pthread_mutex_t break_conn_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  break_conn_cond = PTHREAD_COND_INITIALIZER;

// Define macros for accessing environment variables
#define ENV_NETHOOK_PROTOCOL "NETHOOK_PROTOCOL"
#define ENV_NETHOOK_PORT "NETHOOK_PORT"
#define SHM_FUZZ_ENV_VAR "__AFL_SHM_FUZZ_ID"


#if DEBUG
  #define LOG(format, ...)                                          \
    do {                                                            \
      struct timespec ts;                                           \
      clock_gettime(CLOCK_REALTIME, &ts);                           \
      printf("[hook][%ld.%06ld][%d][%d][%s] " format, ts.tv_sec,        \
             ts.tv_nsec / 1000, getpid(), gettid(), __func__, ##__VA_ARGS__); \
    } while (0)
#else
  #define LOG(format, ...)   
#endif  // DEBUG

// bind()
typedef int (*orig_bind_type)(int sockfd, const struct sockaddr *addr,
                              socklen_t addrlen);
orig_bind_type orig_bind;

// listen()
typedef int (*orig_listen_type)(int sockfd, int backlog);
orig_listen_type orig_listen;

// accept()
typedef int (*orig_accept_type)(int, struct sockaddr*, socklen_t*);
orig_accept_type orig_accept;

// read()
typedef ssize_t (*orig_read_func_type)(int sockfd, void *buf, size_t count);
static orig_read_func_type original_read = NULL;

// recv()
typedef ssize_t (*orig_recv_func_type)(int sockfd, void *buf, size_t len,
                                       int flags);
orig_recv_func_type original_recv = NULL;

// recvfrom()
typedef ssize_t (*recvfrom_t)(int sockfd, void *buf, size_t len, int flags,
                              struct sockaddr *src_addr, socklen_t *addrlen);
static recvfrom_t original_recvfrom = NULL;

// recvmsg()
typedef ssize_t (*orig_recvmsg_func_type)(int sockfd, struct msghdr *msg,
                                          int flags);
static orig_recvmsg_func_type original_recvmsg = NULL;

/* FILE READ&WRITE */
typedef char* (*orig_fgets_type)(char*, int, FILE*);
typedef int (*orig_fgetc_type)(FILE*);
typedef int (*orig_fscanf_type)(FILE*, const char*, ...);
typedef size_t(*orig_fread_type)(void* restrict ptr, size_t size, size_t nmemb, FILE* restrict stream);
typedef int (*orig_fprintf_type)(FILE* restrict stream, const char* restrict format, ...);
typedef char* (*orig_fgets_type)(char* restrict s, int n, FILE* restrict stream);
typedef int (*orig_fputs_type)(const char* restrict s, FILE* restrict stream);
typedef int (*orig_fputc_type)(int c, FILE * stream);
typedef size_t(*orig_fwrite_type)(const void* restrict ptr, size_t size, size_t nmemb, FILE * restrict stream);


static orig_fgetc_type orig_fgetc = NULL;
static orig_fscanf_type orig_fscanf = NULL;
static orig_fread_type orig_fread = NULL;
static orig_fprintf_type orig_fprintf= NULL;
static orig_fgets_type orig_fgets = NULL;
static orig_fputs_type orig_fputs = NULL;
static orig_fputc_type orig_fputc = NULL;
static orig_fwrite_type orig_fwrite = NULL;
// close 
typedef int (*orig_close_type)(int);
orig_close_type orig_close;

// write
typedef ssize_t (*orig_write_type)(int fd, const void* buf, size_t count);
orig_write_type orig_write;

// send
typedef ssize_t (*orig_send_type)(int sockfd, const void* buf, size_t len,
                          int flags);
orig_send_type orig_send;

// sendto 
typedef ssize_t(*orig_sendto_type)(int sockfd, const void* buf, size_t len, int flags,
    const struct sockaddr* dest_addr, socklen_t addrlen);
orig_sendto_type orig_sendto;

// dup
typedef int (*orig_dup_type)(int oldfd);

orig_dup_type orig_dup;

//dup2
typedef int (*orig_dup2_type)(int oldfd,int newfd);

orig_dup2_type  orig_dup2;

// fdopen
typedef FILE* (*orig_fdopen_type)(int, const char*);

orig_fdopen_type orig_fdopen;

/* select */
typedef int (*orig_select_type)(int nfds, fd_set *readfds, fd_set *writefds,
                                fd_set *exceptfds, struct timeval *timeout);
orig_select_type orig_select = NULL;

void set_recvfrom_manual_msg(struct sockaddr* src_addr, socklen_t * addrlen);

void set_manual_msg(struct msghdr* msg);

void hex_dump(u8 *buf, int len);

void print_fd_set(fd_set *readfds, int nfds);

void generate_timespec(struct timespec * timeout, int wait_sec, int wait_millsec) {
  struct timeval  now;
  gettimeofday(&now, NULL);
  timeout->tv_sec = now.tv_sec + wait_sec;
  timeout->tv_nsec = now.tv_usec * 1000 + wait_millsec * 1000000;
  // Normalize the timespec
  while (timeout->tv_nsec >= 1000000000) {
    timeout->tv_nsec -= 1000000000;
    timeout->tv_sec++;
  }
}

void try_wait_for_condition(volatile u8 *test_cond_value, pthread_mutex_t *mutex,
                            pthread_cond_t *cond, int wait_sec, int wait_msec,
                            char *op_name, int wait_try_num) {
  struct timespec timeout;
  int             tried_num = 0;
  // 加锁
  pthread_mutex_lock(mutex);
  while (!(*test_cond_value) && tried_num < wait_try_num) {
    // 计算超时时间
    generate_timespec(&timeout, wait_sec, wait_msec);
    // 等待条件满足或超时
    int result = pthread_cond_timedwait(cond, mutex, &timeout);
    tried_num++;

    if (result == ETIMEDOUT) {
      // 超时
      LOG("wait %s timeout, tried_num=%d\n", op_name, tried_num);
      if (*test_cond_value) { break; }
    } else if (result == 0 && *test_cond_value) {
      LOG("wait %s done \n", op_name);
      break;
    } else {
      // 出错
      LOG("wait %s error, "
          "result=%d, *test_cond_value=%hhu******************************************************\n",
          op_name, result, *test_cond_value);
      //perror("wait error");
    }
  }

  // 解锁
  pthread_mutex_unlock(mutex);
}

// Signal the given cond and set the to_set value to 1 if not NULL.
void mutex_signal_set(pthread_mutex_t *mutex, pthread_cond_t *cond,
                      volatile u8 *to_set) {
  pthread_mutex_lock(mutex);
  if (to_set != NULL) { 
      *to_set = 1;
  }
  pthread_cond_signal(cond);
  pthread_mutex_unlock(mutex);
}

// Signal the given cond and if the *if_set is 1 or the if_set pointer is NULL.
void mutex_ifset_signal(pthread_mutex_t *mutex, pthread_cond_t *cond,
                        volatile u8 *if_set) {
  pthread_mutex_lock(mutex);
  if (if_set==NULL || (if_set !=NULL && *if_set !=0)) {
    pthread_cond_signal(cond);
  }
  pthread_mutex_unlock(mutex);
}

// Wait until the checked value is true(1).
void mutex_wait_check(pthread_mutex_t *mutex, pthread_cond_t *cond,
                      volatile u8 *check_value) {
  pthread_mutex_lock(mutex);
  while (!(*check_value)) {
    pthread_cond_wait(cond, mutex);
  }
  pthread_mutex_unlock(mutex);
}

void *thread_function(void *arg) 
{
  // 0. Initialization
  shared_memory = shmat(shm_id, NULL, 0);
  if (shared_memory == (void *)-1) {
    perror("shmat failed");
    exit(-1);
  }

  // 1. Wait for the dummy connection ready.
  struct timespec timeout;
  int             tried_num = 0;
  if (net_protocol == PRO_TCP) 
  {
    try_wait_for_condition(&has_got_dummy_fd, &dummy_mutex, &dummy_cond,
                           wait_dummy_conn_second, wait_dummy_conn_millisecond,
                           "dummy connection", default_wait_try_num);
  }
  LOG("Stage 1 - wait dummy connection done \n");

  while (1) {  // Endless loop
    // 2. Receive command from fuzzer
    u32 command = 0;
    int res = 0;
    if ((res = original_read(FORKNET_READ_FD, &command, 4)) < 0) {
      perror("Don't receive command\n");
    }
    if (res > 0) {
        //we have read the command ,clean the pipe if needed
        int flags = fcntl(FORKNET_READ_FD, F_GETFL, 0);
        fcntl(FORKNET_READ_FD, F_SETFL, flags | O_NONBLOCK);

        char buffer[1024];
        ssize_t bytes_read;

        while (1) {
            bytes_read = original_read(FORKNET_READ_FD, buffer, sizeof(buffer));
            if (bytes_read == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                else {
                    perror("read");
                    break;
                }
            }
            else if (bytes_read == 0) {
                break;
            }
        }
        fcntl(FORKNET_READ_FD, F_SETFL, flags);
    }

    LOG("Stage 2 - Get command type %d\n", command);

    // 3. Make sure the server has one connection accepted
    u8 need_close_prev_conn = 0;
    u8 need_create_a_conn = 0;
    if (command == NETHOOK_CMD_SEED_READY) {
      if (!has_a_connection && net_protocol == PRO_TCP) { need_create_a_conn = 1; }     //udp do not need to care about connection
    } else if (command == NETHOOK_CMD_SEED_READY_NEWCON && net_protocol == PRO_TCP) {
      if (has_a_connection) { need_close_prev_conn = 1; }
      need_create_a_conn = 1;
    }
    LOG("need close=%d, need create=%d\n", need_close_prev_conn,
        need_create_a_conn);
    if (need_close_prev_conn) {
      // Close existing connection
      // need to signal all condition first?

      need_break_conn = 1;
      has_done_break_conn = 0;
      // we can assume the recv() method is waiting, signal it up.
      mutex_signal_set(&data_ready_mutex, &data_ready_cond, &is_data_ready);
      // wait for the breaking connection done
      try_wait_for_condition(&has_done_break_conn, &break_conn_mutex,
                             &break_conn_cond, wait_recv_second,
                             wait_recv_millisecond, "break a connection",
                             1);  // assume recv is blocking so 1 is enough

      //xzw fixed, we should respect current seed though we need to break this con
      //so we just let recv() go and let it return 0 at next time


      need_break_conn = 0;
      has_a_connection = 0;
      is_data_ready = 0;
    }
    if (need_create_a_conn) {
      // Create a new connection
      if (has_a_connection != 0) { perror("wrong has_a_connection status"); }
      // Two cases:
      // 1. only accept() call is used and is waiting;
      // 2. both select() and accept() are used, but the select() may be not
      // waiting (case 2.1, i.e., it also select() on client fds), or is waiting
      // if it only select() on the server listening fd (case 2.2, i.e., using
      // threads to read client fds); In both case 2.1 and 2.2, the accept() is
      // not called yet.

      // signal the waiting accept() for case 1, or the waiting select() for
      // case 2.2
      mutex_signal_set(&accept_wait_mutex, &accept_wait_cond,
                       &need_a_connection);

      // wait to know that a new connection has been created
      try_wait_for_condition(&has_a_connection, &accept_done_mutex,
                             &accept_done_cond, wait_accept_second,
                             wait_accept_millisecond, "accept a connection",
                             default_wait_try_num);
    }
    LOG("Stage 3 - Connection is ready\n");

    // 4. Consume the data
    is_data_consumed = 0;
    orig_seed_length = cur_seed_length = *(u32 *)shared_memory;
    LOG("current seed length:%d\n", orig_seed_length);
    //hex_dump(shared_memory, orig_seed_length + 4);  // orig_seed_length does not include first 4 bytes
    hex_dump(shared_memory, orig_seed_length > 4 ? 8 : orig_seed_length + 4);  // orig_seed_length does not include first 4 bytes
    // now tell recv() that data is ready
    mutex_signal_set(&data_ready_mutex, &data_ready_cond, &is_data_ready);

    // wait until the data are consumed
    try_wait_for_condition(&is_data_consumed, &data_consumed_mutex,
                           &data_consumed_cond, wait_consume_second,
                           wait_consume_millisecond, "consume the data",
                           default_wait_try_num);
    LOG("is data consumed? %u\n", is_data_consumed);
    is_data_ready = 0; // 防止recv中虚假唤醒后读取
    LOG("Stage 4 - Seed data are consumed\n");

    // 5. Send message to fuzzer
    command = is_data_consumed ? NETHOOK_CMD_CONSUMED : NETHOOK_CMD_TIME_OUT;
    if ((res = orig_write(FORKNET_WRITE_FD, &command, 4)) < 0) {
      perror("send command error\n");
    }
    LOG("Stage 5 - Send command %d back to fuzzer\n", command);
  }

  return NULL;
}

void start_thread_if_needed()
{
  if (has_start_thread) { 
      return; 
  }
  if (pthread_create(&thread, NULL, thread_function, NULL) != 0) 
  {
    perror("pthread_create");
  } else 
  {
    has_start_thread = 1;
  }
}

int is_target_server_addr(const struct sockaddr *addr) 
{
  if (addr->sa_family == AF_INET) 
  {
    const struct sockaddr_in *ipv4_addr = (const struct sockaddr_in *)addr;
    if (ntohs(ipv4_addr->sin_port) == net_port) 
    {
      return 1;  // 是 IPv4 地址且端口为 net_port
    }
  }
  return 0;  // 不是 IPv4 地址或端口不为 net_port
}

int create_the_dummy_connection(int sockfd)
{

    int  my_sockfd;
    //char buffer[6] = "hook ";
    my_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (my_sockfd == -1) { perror("Socket creation failed"); }
    dummy_servaddr.sin_family = AF_INET;
    dummy_servaddr.sin_port = htons(net_port);
    dummy_servaddr.sin_addr.s_addr = inet_addr((char*)net_ip);

    // Start connection attempt
    int result = connect(my_sockfd, (struct sockaddr*)&dummy_servaddr, sizeof(dummy_servaddr));
    if (result < 0)
    {
        // Connection attempt failed immediately
        perror("connect failed");
        return -1;
    }

    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);  


    if (!orig_accept) {
        orig_accept = (orig_accept_type)dlsym(RTLD_NEXT, "accept");
    }
    // Start connection attempt
    while (dummy_fd<=0){
     dummy_fd = orig_accept(sockfd, (struct sockaddr*)&server_addr, &addr_len);
    }

  mutex_signal_set(&dummy_mutex, &dummy_cond, &has_got_dummy_fd);

  LOG("get dummy_fd=%d\n", dummy_fd);

  LOG("Dummy connection created well\n");
  return 0;
}

void after_bind_called(int sockfd, const struct sockaddr *addr,
                       socklen_t addrlen) 
{

    int sock_type;
    socklen_t optlen = sizeof(sock_type);

    if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &sock_type, &optlen) == -1) {
        perror("getsockopt");
        exit(EXIT_FAILURE);
    }

    /* TCP SOCK_STREAM  = 1 */
    /* UDP SOCK_DGRAM   = 2 */

  if (is_target_server_addr(addr) && ( (sock_type==PRO_TCP && sock_type == SOCK_STREAM)
 	        || (sock_type==PRO_UDP && sock_type == SOCK_DGRAM) ) ) 
		      // check sock_type in a more portable manner since we later find in uClibc MIPS, SOCK_STREAM is defined as 2
  { 
     
    server_fd = sockfd;
    LOG("Get server_fd:%d\n",sockfd);
    has_got_server_fd = 1;
  }
  start_thread_if_needed();
}

void after_listen_called(int sockfd, int backlog) 
{
  if (has_got_server_fd && server_fd == sockfd && net_protocol==PRO_TCP)
  {
      LOG("Create dummy fd\n");
    create_the_dummy_connection(sockfd); // cannot put in after_bind_called since it is too early
  }
}



u32 read_from_shm(void *buf, u32 len) {

  u32 real_read = 0;     // length that real read

  u32 offset = orig_seed_length - cur_seed_length +
               sizeof(u32);  // 需要加上sizeof(u32)是因为共享内
                             // 存开头表示的是长度，之后才是种子

  if (cur_seed_length <= len) {  // 此时我们需要新的seed

    memcpy(buf, shared_memory + offset, cur_seed_length);
    LOG("read all buf(offset=%d, len=%d)\n", offset, cur_seed_length);
    real_read = cur_seed_length;
    cur_seed_length = 0;

  } else {  // len<seed_length

    memcpy(buf, shared_memory + offset, len);
    LOG("read partial buf(offset=%d, read len=%d)\n", offset,(int) len);
    cur_seed_length -= len;
    real_read = len;
  }

  LOG("remaing length:%u\n", cur_seed_length);

  if (cur_seed_length == 0) { 
      // But cannot signal data consumed here, since the recv() data are 
      // not back to app and consumed yet.
      
    is_data_consumed = 1; 

    LOG("data consumed?  %u\n", is_data_consumed);
  }



  return real_read;
}


__attribute__((constructor)) void hook_start_up() 
{
  // Read the value of NETHOOK_PROTOCOL from the environment variable
  char *protocol_str = getenv(ENV_NETHOOK_PROTOCOL);
  if (protocol_str == NULL) {
    LOG("%s environment variable not set\n", ENV_NETHOOK_PROTOCOL);
  }

  // Convert the string to u8 type
  net_protocol = (uint8_t)atoi(protocol_str);

  // Output the value of NETHOOK_PROTOCOL
  LOG("NETHOOK_PROTOCOL value is: %d\n", net_protocol);

  // Read the value of NETHOOK_PORT from the environment variable
  char *port_str = getenv(ENV_NETHOOK_PORT);
  if (port_str == NULL) {
    LOG("%s environment variable not set\n", ENV_NETHOOK_PORT);
  }

  // Convert the string to a 32-bit int type
  net_port = atoi(port_str);

  // Output the value of NETHOOK_PORT
  LOG("NETHOOK_PORT value is: %d\n", net_port);

    // Read the value of SHM_FUZZ_ENV_VAR from the environment variable
  char *shmid_str = getenv(SHM_FUZZ_ENV_VAR);
  if (shmid_str == NULL) {
    LOG("%s environment variable not set\n", SHM_FUZZ_ENV_VAR);
  }

  // Convert the string to a 32-bit int type
  shm_id = atoi(shmid_str);

  // Output the value of NETHOOK_PORT
  LOG("shm_id value is: %d\n", shm_id);

  if (!original_read) {
    original_read = (orig_read_func_type)dlsym(RTLD_NEXT, "read");
  }

  if (!orig_write) { 
      orig_write = (orig_write_type)dlsym(RTLD_NEXT, "write");
  }

}



int listen(int sockfd, int backlog) {
  LOG("listen called with fd, backlog: %d, %d\n", sockfd, backlog);
  if (!orig_listen) {
    orig_listen = (orig_listen_type)dlsym(RTLD_NEXT, "listen");
  }

  int res =  orig_listen(sockfd, backlog);

  after_listen_called(sockfd, backlog);
  
  return res;
}


int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) 
{
  LOG("bind called with fd, addr, addrlen: %d, %p, %d\n", sockfd, addr,
      addrlen);
  if (!orig_bind) { 
      orig_bind = (orig_bind_type)dlsym(RTLD_NEXT, "bind");
  }

  int res = orig_bind(sockfd, addr, addrlen);

  after_bind_called(sockfd, addr, addrlen);

  return res;
}


int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  if (!orig_accept) {
    orig_accept = (orig_accept_type)dlsym(RTLD_NEXT, "accept");
  }

  //if (!orig_close) { orig_close = (orig_close_type)dlsym(RTLD_NEXT, "close"); }

  LOG("accept called, sockfd = %d\n", sockfd); 

  int con_fd = -1; 
  if (has_got_server_fd && server_fd == sockfd) 
  {
      if (!need_a_connection)//多次对accept的调用是预期的，返回-1并且设置errno=EAGAIN
      {
          errno = EAGAIN;
          return -1;
      }
    mutex_wait_check(&accept_wait_mutex, &accept_wait_cond, &need_a_connection);
    need_a_connection = 0;
    con_fd = dummy_fd;
    //fill the addr if addr is not NULL
    if (addr != NULL) {
        struct sockaddr_in* addr_in = (struct sockaddr_in*)addr;
        addr_in->sin_family = AF_INET;
        addr_in->sin_port = htons(10001);
        inet_pton(AF_INET, "127.0.0.1", &addr_in->sin_addr);
    }
    mutex_signal_set(&accept_done_mutex, &accept_done_cond, &has_a_connection);
  }
  else
  {
    con_fd = orig_accept(sockfd, addr, addrlen);
  }

  LOG("accept will return con_fd = %d\n", con_fd); 

  return con_fd;
}

typedef int (*orig_accept4_type)(int, struct sockaddr*, socklen_t*, int);
orig_accept4_type orig_accept4;

int accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags) {
    if (!orig_accept4) {
        orig_accept4 = (orig_accept4_type)dlsym(RTLD_NEXT, "accept4");
    }

    LOG("accept4 called, sockfd = %d, flags = %d\n", sockfd, flags);

    int con_fd = -1;
    if (has_got_server_fd && server_fd == sockfd)
    {
        if(!need_a_connection)//多次对accept4的调用是预期的，返回-1并且设置errno=EAGAIN
        {
            errno = EAGAIN;
            return -1;
        }

        mutex_wait_check(&accept_wait_mutex, &accept_wait_cond, &need_a_connection);
        need_a_connection = 0;
        con_fd = dummy_fd;

        // fill the addr
        struct sockaddr_in* addr_in = (struct sockaddr_in*)addr;
        addr_in->sin_family = AF_INET;
        addr_in->sin_port = htons(10001);
        inet_pton(AF_INET, "127.0.0.1", &addr_in->sin_addr);

        mutex_signal_set(&accept_done_mutex, &accept_done_cond, &has_a_connection);
    }
    else
    {
        con_fd = orig_accept4(sockfd, addr, addrlen, flags);
    }

    LOG("accept4 will return con_fd = %d\n", con_fd);

    return con_fd;
}

int close(int fd) {
  if (fd == FORKNET_READ_FD ||
      fd == FORKNET_WRITE_FD) {  // do not close our fd for communicate
    return 0;
  }

  if (!orig_close) { orig_close = (orig_close_type)dlsym(RTLD_NEXT, "close"); }
  
  LOG("close called, fd = %d\n", fd); 

  if (has_got_dummy_fd && fd == dummy_fd && net_protocol==PRO_TCP) { 
    // Indicate the connection is abandoned by up app
    has_a_connection = 0;
    // Also singal a data consumed condition since method like recv() will not
    // be called
    mutex_ifset_signal(&data_consumed_mutex, &data_consumed_cond,
                       NULL);
    is_data_consumed = 1;
    LOG("close wake up data consume\n");
    return 0;
  }
  else if(has_got_server_fd && fd == server_fd && net_protocol == PRO_UDP){
      mutex_ifset_signal(&data_consumed_mutex, &data_consumed_cond, NULL);
      is_data_consumed = 1;
      LOG("close wake up data consume\n");

      return orig_close(fd);
  }

  return orig_close(fd);
}

u8 select_only_have_given_fd(fd_set *readfds, int givenfd, int nfds) {
  int fd_count = 0;

  // 遍历所有文件描述符，统计出现的次数
  for (int i = 0; i < nfds; ++i) {
    if (FD_ISSET(i, readfds)) { ++fd_count; }
  }

  // 如果只有一个文件描述符且为给定的fd，则返回1，否则返回0
  if (fd_count == 1 && FD_ISSET(givenfd, readfds)) {
    return 1;
  } else {
    return 0;
  }
}

// Check if the given file descriptor is the only one being polled
u8 poll_only_have_given_fd(struct pollfd* fds, nfds_t nfds, int givenfd) {
    int fd_count = 0;

    // Traverse the array of pollfd structures to count active file descriptors
    for (nfds_t i = 0; i < nfds; ++i) {
        if (fds[i].fd >= 0 && fds[i].events != 0) {
            ++fd_count;  // Count this file descriptor
        }
    }

    // Return 1 if only one file descriptor is present and it matches the givenfd
    if (fd_count == 1) {
        for (nfds_t i = 0; i < nfds; ++i) {
            if (fds[i].fd == givenfd && fds[i].events != 0) { return 1; }
        }
    }

    return 0;
}

int get_i_from_pfds(struct pollfd* fds, nfds_t nfds, int givenfd) {

    for (int i = 0; i < nfds; ++i) {
        LOG("poll_fds[%d]=%d\n", i, fds[i].fd);
        if (fds[i].fd == givenfd) {
            LOG("from pfds return %d\n", i);
            return i;
        }
    }
    LOG("from pfds return -1\n");
    return -1;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
  if (!original_recv) {
    original_recv = (orig_recv_func_type)dlsym(RTLD_NEXT, "recv");
  }

  LOG("recv called, sockfd = %d, len=%zu, flags=%d\n", sockfd, len, flags); 

  // First exclude non-special fd cases
  if (!has_got_dummy_fd || (has_got_dummy_fd && sockfd != dummy_fd)) {
    LOG("will use original recv called, has_got_dummy_fd = %d\n", has_got_dummy_fd); 
    return original_recv(sockfd, buf, len, flags);
  }

   // Check if need to break current connection
  if (need_break_conn) {
    //xzw: It's interesting that we check whether we should break the connection before
    //reading achieves a fact that we can respect the current seed instead of throw it.
      mutex_signal_set(&break_conn_mutex, &break_conn_cond,
          &has_done_break_conn);
      return 0;
  }


   u32 realread = 0;
    do{
    // If data is consumed, signal data_consumed_cond
    mutex_ifset_signal(&data_consumed_mutex, &data_consumed_cond,
        &is_data_consumed);
    // Wait if data is not ready
    mutex_wait_check(&data_ready_mutex, &data_ready_cond, &is_data_ready);

    // Read data to buf.
     realread = read_from_shm(buf, len);
    }while(realread==0);
  

  LOG("recv will return, sockfd = %d, len=%zu, flags=%d, return=%d\n", sockfd,
      len, flags, realread); 

  return realread;
}

/* recvfrom */
ssize_t __attribute__((hot))
recvfrom(int sockfd, void* buf, size_t len, int flags,
    struct sockaddr* src_addr, socklen_t* addrlen) {

    if (!original_recvfrom) { original_recvfrom = dlsym(RTLD_NEXT, "recvfrom"); }

    LOG("recvfrom called, sockfd = %d, len=%zu, flags=%d\n", sockfd, len, flags);

    if (net_protocol == PRO_UDP) {
        if (!has_got_server_fd || (has_got_server_fd && sockfd != server_fd)) {
            LOG("will use original recvfrom , cauze udp not get server_fd or sockfd!=server_fd sockfd:%d\n",
                sockfd);
            return original_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
        }
    }
    else {
        if (!has_got_dummy_fd || (has_got_dummy_fd && sockfd != dummy_fd)) {
            LOG("will use original recvfrom , cauze TCP not get dummy_fd or sockfd!=dummy_fd sockfd = %d\n",
                sockfd);
            return original_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
        }
    }
    // Special fd

      // Check if need to break current connection
    if (need_break_conn && net_protocol == PRO_TCP) {
        mutex_signal_set(&break_conn_mutex, &break_conn_cond,
            &has_done_break_conn);
        return 0;
    }

   u32 realread = 0;
    do{
    // If data is consumed, signal data_consumed_cond
    mutex_ifset_signal(&data_consumed_mutex, &data_consumed_cond,
        &is_data_consumed);
    // Wait if data is not ready
    mutex_wait_check(&data_ready_mutex, &data_ready_cond, &is_data_ready);

    // Read data to buf.
     realread = read_from_shm(buf, len);
    }while(realread==0);
  
    LOG("recvfrom return length=%u\n",realread);

    set_recvfrom_manual_msg(src_addr, addrlen);
    
    return realread;

}

/* read */
ssize_t __attribute__((hot))
read(int fd, void* buf, size_t count) {

    LOG("read called, fd = %d, len=%zu\n", fd, count);

    if (!has_got_dummy_fd || (has_got_dummy_fd && (fd != dummy_fd && fd!=new_dummy_fd))) {
        LOG("will use original read , has_got_dummy_fd = %d\n",
            has_got_dummy_fd);
        return original_read(fd, buf, count);
    }

    // Special fd

        // Check if need to break current connection
    if (need_break_conn) {
        mutex_signal_set(&break_conn_mutex, &break_conn_cond,
            &has_done_break_conn);
        return 0;
    }

    u32 realread = 0;
    do{
    // If data is consumed, signal data_consumed_cond
    mutex_ifset_signal(&data_consumed_mutex, &data_consumed_cond,
        &is_data_consumed);
    // Wait if data is not ready
    mutex_wait_check(&data_ready_mutex, &data_ready_cond, &is_data_ready);

    // Read data to buf.
     realread = read_from_shm(buf, count);
    }while(realread==0);
  
    LOG("read return length=%llu\n",realread);
  
    return realread;
}

/* recvmsg */

ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags) {

    if (!original_recvmsg) {
        original_recvmsg = (orig_recvmsg_func_type)dlsym(RTLD_NEXT, "recvmsg");
    }


    LOG("recvmsg called, fd = %d, flags=%d\n", sockfd, flags);

    if (net_protocol == PRO_UDP) {
        if (!has_got_server_fd || (has_got_server_fd && sockfd != server_fd)) {
            LOG("will use original recvmsg , cauze udp not get server_fd or sockfd!=server_fd sockfd:%d\n",
                sockfd);
            return original_recvmsg(sockfd, msg, flags);
        }
    }
    else {
        if (!has_got_dummy_fd || (has_got_dummy_fd && sockfd != dummy_fd)) {
            LOG("will use original recvmsg , cauze TCP not get dummy_fd or sockfd!=dummy_fd sockfd = %d\n",
                sockfd);
            return original_recvmsg(sockfd, msg, flags);
        }
    }
    // Special fd

    // Check if need to break current connection
    if (need_break_conn) {
        mutex_signal_set(&break_conn_mutex, &break_conn_cond,
            &has_done_break_conn);
        return 0;
    }


    set_manual_msg(msg);  // 填充控制消息

    u32 len = 0;

    for (int i = 0; i < msg->msg_iovlen; i++) {
        len += msg->msg_iov[i].iov_len;
    }

    msg_buf = (char*)realloc(msg_buf, len);
    
      u32 realread = 0;
    do{
    // If data is consumed, signal data_consumed_cond
    mutex_ifset_signal(&data_consumed_mutex, &data_consumed_cond,
        &is_data_consumed);
    // Wait if data is not ready
    mutex_wait_check(&data_ready_mutex, &data_ready_cond, &is_data_ready);

    // Read data to buf.
     realread = read_from_shm(msg_buf, len);
    }while(realread==0);
  
    LOG("recvmsg return length=%u\n",realread);

    memcpy(msg->msg_iov->iov_base, msg_buf, realread);
    //msg->msg_iov->iov_base = msg_buf;
    msg->msg_iov->iov_len = realread;

    return realread;
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
           struct timeval *timeout) {
  if (!orig_select) {
    orig_select = (orig_select_type)dlsym(RTLD_NEXT, "select");
  }

  LOG("select called, nfds = %d\n", nfds); 
  print_fd_set(readfds, nfds);
  print_fd_set(writefds, nfds);
  print_fd_set(exceptfds, nfds);

  if (net_protocol == PRO_TCP) {
      /* assume the connection had been built */
      if (has_got_dummy_fd && has_a_connection) {
          int check_fd = 0;
          if (new_dummy_fd>0) {
              check_fd = new_dummy_fd;
          }
          else {
              check_fd = dummy_fd;
          }

          LOG("dummy_fd=%d\n", check_fd);
          /* Only have dummy_fd? */
          if (select_only_have_given_fd(readfds, check_fd, nfds)) {
              // Tested and find it is even a bit slower if we specially handle the
              // dummy_fd+server_fd case
              FD_SET(check_fd, readfds);
              LOG("select return dummy_fd only\n");
              return  1;
          }
          int num = orig_select(nfds, readfds, writefds, exceptfds, 0);
          LOG("orig_select called ,num=%d\n", num);
          print_fd_set(readfds, nfds);
          print_fd_set(writefds, nfds);
          print_fd_set(exceptfds, nfds);

          if (!FD_ISSET(check_fd, readfds)) {
              FD_SET(check_fd, readfds);
              ++num;
          }
          /* Do not return accept */
          if (FD_ISSET(server_fd, readfds)) {
              FD_CLR(server_fd, readfds);
              --num;
          }
          LOG("return dummy_fd is set,num=%d\n", num);
          return num;

      }

      if (has_got_server_fd && select_only_have_given_fd(readfds, server_fd, nfds) && !has_a_connection ) {
          mutex_wait_check(&accept_wait_mutex, &accept_wait_cond, &need_a_connection);
          FD_SET(server_fd, readfds);
          LOG("select return server_fd only\n");
          return 1;
      }
      else if (has_got_server_fd && FD_ISSET(server_fd, readfds)) {      // may have other fds in the set, and need a new connection
          int num = orig_select(nfds, readfds, writefds, exceptfds, 0);
          if (need_a_connection)
          {
              if (!FD_ISSET(server_fd, readfds)) {
                  FD_SET(server_fd, readfds);
                  ++num;
                  LOG("select will manually add server_fd\n");
              }
          }
          return num;
      }
      LOG("select will call orig_select and return\n");
      return orig_select(nfds, readfds, writefds, exceptfds, timeout);
  }
  else {    //UDP
      if (has_got_server_fd && select_only_have_given_fd(readfds, server_fd, nfds)) {
          FD_SET(server_fd, readfds);
          LOG("select return server_fd only (UDP)\n");
          return 1;
      }
      else if (has_got_server_fd) {    //handle other fds
          int num = orig_select(nfds, readfds, writefds, exceptfds, 0);
          {
              if (!FD_ISSET(server_fd, readfds)) {
                  FD_SET(server_fd, readfds);
                  ++num;
              }
          }
          return num;
      }

      return orig_select(nfds, readfds, writefds, exceptfds, timeout);

  }
}

typedef int (*orig_poll_type)(struct pollfd fds[], nfds_t nfds, int timeout);

orig_poll_type orig_poll = NULL;

int poll(struct pollfd* fds, nfds_t nfds, int timeout) {
    if (!orig_poll) { orig_poll = (orig_poll_type)dlsym(RTLD_NEXT, "poll"); }

    LOG("poll called, nfds = %zu\n", nfds);

    if (nfds == 1) {
        if (fds[0].fd != server_fd && fds[0].fd != dummy_fd) {
            LOG("poll fd = %d\n", fds[0].fd);
            return orig_poll(fds, nfds, timeout);
        }
    }


    int server_i=get_i_from_pfds(fds, nfds, server_fd);

    if (!has_a_connection) {
        if (server_i < 0) {
            LOG("error in poll, mistake in finding server_fd\n");
            LOG("return original poll\n");
            return orig_poll(fds, nfds, timeout);
        }
    }


        if (net_protocol == PRO_TCP) {
        /* assume the connection had been built */
        if (has_got_dummy_fd && has_a_connection) {

            int dummy_i = get_i_from_pfds(fds, nfds, dummy_fd);

            if (dummy_i < 0) { LOG("error in poll, mistake in finding dummy_fd dummy_fd:%d\n",dummy_fd); }

            /* Poll will not only have dummy_fd */

            int num = orig_poll(fds, nfds, 0);

            /* dummy_fd */
            if (!(fds[dummy_i].revents == POLLIN)) {
                fds[dummy_i].revents = POLLIN;
                ++num;
            }
            /* Do not return accept */
            if (fds[server_i].revents == POLLIN) {
                fds[server_i].revents = 0;
                num--;
            }

            LOG("return dummy_fd is set,num=%d\n", num);
            return num;

        }

        if (has_got_server_fd && poll_only_have_given_fd(fds, nfds, server_fd)) {
            mutex_wait_check(&accept_wait_mutex, &accept_wait_cond, &need_a_connection);
            fds[server_i].revents =
                POLLIN;  // Tell SUT to accept the connection
            return 1;
        }
        else if (has_got_server_fd && fds[server_i].revents == POLLIN) {
            int num = orig_poll(fds, nfds, 0);
            if (need_a_connection) {

                if (fds[server_i].revents != POLLIN) {
                    fds[server_i].revents = POLLIN;
                    ++num;
                }

            }

            return num;
        }

        return orig_poll(fds, nfds, timeout);
    }
    else {      //UDP
            for (int i = 0; i < nfds; i++) {
                LOG("poll fds[%d]:%d", i, fds[i].fd);
                if (fds[i].revents == POLLIN) LOG("POLLIN\n");else LOG("\n");
            }
        if (has_got_server_fd && poll_only_have_given_fd(fds, nfds, server_fd)) {
            fds[server_i].revents = POLLIN; 
            return 1;
        }
        else if (has_got_server_fd ) {
            int num = orig_poll(fds, nfds, 0);

                if (fds[server_i].revents != POLLIN) {
                    fds[server_i].revents = POLLIN;
                    ++num;
                }        

            return num;
        }

        return orig_poll(fds, nfds, timeout);


    }
}

typedef int (*orig_epoll_ctl_type)(int, int, int, struct epoll_event*);

orig_epoll_ctl_type orig_epoll_ctl = NULL;

int epoll_ctl(int epfd, int op, int fd, struct epoll_event* event) {
    if (!orig_epoll_ctl) {
        orig_epoll_ctl = (orig_epoll_ctl_type)dlsym(RTLD_NEXT, "epoll_ctl");
    }

    if ( fd==server_fd && op == EPOLL_CTL_ADD) {
        if (server_ev != NULL) {
            LOG("already has server_ev\n");
            return 0;
        }
        LOG("save server_epoll event\n");
        server_ev = event;

    }
    else if (fd == dummy_fd && op == EPOLL_CTL_ADD) {
        if (client_ev != NULL) {
            LOG("already has client_ev\n");
            return 0;
        }
        LOG("save client_epoll event\n");
        client_ev = event;

    }

    int ret=orig_epoll_ctl(epfd, op, fd, event);
    LOG("epoll_ctl return %d\n", ret);

    return ret;

}

typedef int (*original_epoll_wait_type)(int epfd, struct epoll_event* events, int maxevents, int timeout);
original_epoll_wait_type original_epoll_wait = NULL;
int epoll_wait(int epfd, struct epoll_event* events, int maxevents,
    int timeout) {
    if (!original_epoll_wait) {
        original_epoll_wait = (original_epoll_wait_type)dlsym(RTLD_NEXT, "epoll_wait");
    }
    LOG("has_a_connection?=%d has_got_dummy_fd?=%d has_got_server_fd?=%d\n", has_a_connection, has_got_dummy_fd, has_got_server_fd);


    int nfds = original_epoll_wait(epfd, events, maxevents, 0);
    if (nfds == -1) {
        perror("epoll_wait");
        return -1;
    }
    LOG("nfds=%d\n", nfds);
    int flag = 0;
    // 检查是否有事件发生
    //有我们期望的事件
    for (int i = 0; i < nfds; i++) {
        if ((events + i) == client_ev && has_a_connection && has_got_dummy_fd) {
            (events + i)->events |= EPOLLIN;
            (events + i)->data.fd = dummy_fd;
            flag = 1;
        
        }
        else if ((events + i) == server_ev && has_got_server_fd && !has_a_connection) {
            mutex_wait_check(&accept_wait_mutex, &accept_wait_cond, &need_a_connection);
            (events + i)->events |= EPOLLIN;
            (events + i)->data.fd = server_fd;
            flag = 1;
        }
    }
    LOG("add our logic\n");
    //没有我们期望的事件
    if (!flag) {
        if (has_a_connection && has_got_dummy_fd) {
            client_ev->events |= EPOLLIN;
            client_ev->data.fd = dummy_fd;
            *(events+nfds) = *client_ev;
            LOG("epoll_wait return client_ev for read\n");
            return nfds+1;
        }
        if (has_got_server_fd && !has_a_connection) {
            mutex_wait_check(&accept_wait_mutex, &accept_wait_cond, &need_a_connection);
            server_ev->events |= EPOLLIN;
            server_ev->data.fd = server_fd;
            *(events + nfds) = *server_ev;  // Tell SUT to accept the connection
            LOG("epoll_wait return client_ev for accept\n");
            LOG("data (union contents):\n");
            LOG("  fd: %d\n", events->data.fd);
            LOG("  u32: %u\n", events->data.u32);
            LOG("  u64: %llu\n", (unsigned long long) events->data.u64);
            LOG("  ptr: %p\n", events->data.ptr);
            return nfds+1;
        }
    }


    return original_epoll_wait(epfd, events, maxevents, timeout);
}


ssize_t write(int fd, const void* buf, size_t count)
{
    // Dummy fd should not write
  if (has_got_dummy_fd && fd == dummy_fd) {
    LOG("call write with dummy_fd\n");
    return count;
  }

  return orig_write(fd, buf, count);
}

ssize_t send(int sockfd, const void * buf, size_t len, int flags)
{
  if (!orig_send) {
    orig_send = (orig_send_type)dlsym(RTLD_NEXT, "send");
  }

  LOG("send called sockfd=%d, len=%zu, flags=%d, buf:\n", sockfd, len, flags);
  hex_dump((u8*)buf, len);

  // Dummy fd should not write
  if (has_got_dummy_fd && sockfd == dummy_fd) {
    LOG("call send with dummy_fd\n");
    return len;
  }

  return orig_send(sockfd, buf, len, flags);
}

ssize_t sendto(int sockfd, const void* buf, size_t len, int flags,
    const struct sockaddr* dest_addr, socklen_t addrlen) {
    if (!orig_sendto) {
        orig_sendto = (orig_sendto_type)dlsym(RTLD_NEXT, "sendto");
    }

    LOG("sendto called sockfd=%d, len=%zu, flags=%d, dest_addr=%s\n",
        sockfd, len, flags, inet_ntoa(((struct sockaddr_in*)dest_addr)->sin_addr));
    hex_dump((u8*)buf, len);

    // Dummy fd should not write
    if (has_got_dummy_fd && sockfd == dummy_fd) {
        LOG("call sendto with dummy_fd\n");
        return len;
    }

    return orig_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

int dup(int oldfd) {
    if (!orig_dup) {
        orig_dup = (orig_dup_type)dlsym(RTLD_NEXT, "dup");
    }

    int new_fd = orig_dup(oldfd);

    if (has_got_server_fd && server_fd == oldfd) {
        server_fd = new_fd;
        LOG("dup  server_fd %d->%d\n", oldfd, new_fd);
    }
    else if (has_got_dummy_fd && dummy_fd == oldfd) {
        new_dummy_fd = new_fd;
        LOG("dup  dummy_fd %d->%d\n", oldfd, new_fd);
    }

   

    return new_fd;

}

int dup2(int oldfd,int newfd) {
    if (!orig_dup2) {
        orig_dup2 = (orig_dup2_type)dlsym(RTLD_NEXT, "dup2");
    }

    int ret = orig_dup(oldfd);

    if (has_got_server_fd && server_fd == oldfd) {
        new_server_fd = newfd;
        LOG("dup2 server_fd %d->%d", oldfd, newfd);
    }
    else if (has_got_dummy_fd && dummy_fd == oldfd) {
        new_dummy_fd = newfd;
        LOG("dup  dummy_fd %d->%d", oldfd, newfd);
    }

    return ret;

}

FILE* mark_fp = NULL;

FILE* fdopen(int fd, const char* mode) {
    if(orig_fdopen==NULL)
    orig_fdopen = (orig_fdopen_type)dlsym(RTLD_NEXT, "fdopen");

    FILE* fp = orig_fdopen(fd, mode);

    LOG("fdopen fd:%d --> filefd:%d\n", fd, fp);

    if ((fd == new_dummy_fd ) && fp != NULL ) {
        mark_fp = fp;    
        LOG("get mark_fp:%d\n", mark_fp);
    }

    return fp;
}

int is_marked(FILE* fp) {
    return (fp == mark_fp && mark_fp!=NULL);
}

char* fgets(char* s, int size, FILE* stream) {
    if (!orig_fgets) {
        orig_fgets = (orig_fgets_type)dlsym(RTLD_NEXT, "fgets");
    }

    LOG("fgets stream=%d mark_fp=%d", stream, mark_fp);
    if (!is_marked(stream)) {
        LOG("is_marked?:%d\n", is_marked(stream));
        return orig_fgets(s, size, stream);
    }

    // Special fd

    // If data is consumed, signal data_consumed_cond
    mutex_ifset_signal(&data_consumed_mutex, &data_consumed_cond,
        &is_data_consumed);
    // Wait if data is not ready
    mutex_wait_check(&data_ready_mutex, &data_ready_cond, &is_data_ready);

    // Check if need to break current connection
    if (need_break_conn) {
        mutex_signal_set(&break_conn_mutex, &break_conn_cond,
            &has_done_break_conn);
        return NULL;
    }

    u32 realread=0;

    do{
        // If data is consumed, signal data_consumed_cond
        mutex_ifset_signal(&data_consumed_mutex, &data_consumed_cond,
            &is_data_consumed);
        // Wait if data is not ready
        mutex_wait_check(&data_ready_mutex, &data_ready_cond, &is_data_ready);
    
        // Read data to buf.
         realread = read_from_shm(s, size);
        }while(realread==0);

    return s;

}

// Hook fgetc 函数
int fgetc(FILE* stream) {

    if (!orig_fgetc) {
        orig_fgetc = (orig_fgetc_type)dlsym(RTLD_NEXT, "fgetc");
    }

    LOG("fgtec %d\n", is_marked(stream));
    if (!is_marked(stream)) {
        return orig_fgetc(stream);
    }


    // Check if need to break current connection
    if (need_break_conn) {
        mutex_signal_set(&break_conn_mutex, &break_conn_cond,
            &has_done_break_conn);
        return 0;
    }

    u32 realread=0;
    char buffer[1];
    do{
        // If data is consumed, signal data_consumed_cond
        mutex_ifset_signal(&data_consumed_mutex, &data_consumed_cond,
            &is_data_consumed);
        // Wait if data is not ready
        mutex_wait_check(&data_ready_mutex, &data_ready_cond, &is_data_ready);
    
        // Read data to buf.
         realread =  read_from_shm(buffer, sizeof(buffer));
        }while(realread==0);

    return buffer[0];

}

size_t fread(void* restrict ptr, size_t size, size_t nmemb, FILE* restrict stream) {

    if (!orig_fread) {
        orig_fread = (orig_fread_type)dlsym(RTLD_NEXT, "fread");
    }

    LOG("fgets stream=%d mark_fp=%d", stream, mark_fp);
    if (!is_marked(stream)) {
        LOG("is_marked?:%d\n", is_marked(stream));
        return orig_fread(ptr, size,nmemb, stream);
    }


    // Check if need to break current connection
    if (need_break_conn) {
        mutex_signal_set(&break_conn_mutex, &break_conn_cond,
            &has_done_break_conn);
        return 0;
    }

    u32 realread=0;

    do{
        // If data is consumed, signal data_consumed_cond
        mutex_ifset_signal(&data_consumed_mutex, &data_consumed_cond,
            &is_data_consumed);
        // Wait if data is not ready
        mutex_wait_check(&data_ready_mutex, &data_ready_cond, &is_data_ready);
    
        // Read data to buf.
         realread = read_from_shm(ptr, size*nmemb);
        }while(realread==0);


    return realread/nmemb ;
}

int count_format_specifiers(const char* format) {
    int count = 0;
    const char* ptr = format;
    while (*ptr) {
        if (*ptr == '%') {
            ptr++;
            while (*ptr && strchr("+-0 #", *ptr)) ptr++;
            while (*ptr && isdigit(*ptr)) ptr++;
            if (*ptr == '.') {
                ptr++;
                while (*ptr && isdigit(*ptr)) ptr++;
            }
            if (*ptr && strchr("hlL", *ptr)) ptr++;
            if (*ptr && strchr("diouxXeEfFgGaAcsCSpnm%", *ptr)) {
                count++;
            }
        }
        ptr++;
    }
    return count;
}

int read_and_match_from_shared_memory(const char* format, va_list args) {
    char buffer[1024];
    char temp[1024];
    int total_read = 0;
    int ret;

    buffer[0] = '\0';  

    do {
        read_from_shm(temp, sizeof(temp));
        strncat(buffer, temp, sizeof(buffer) - strlen(buffer) - 1);
        total_read += strlen(temp);

        va_list args_copy;
        va_copy(args_copy, args);
        ret = vsscanf(buffer, format, args_copy);
        va_end(args_copy);
    } while (ret != count_format_specifiers(format) && total_read < 1024);

    return ret;
}



int fscanf(FILE* stream, const char* format, ...) {

    if (!orig_fscanf) {
        orig_fscanf = (orig_fscanf_type)dlsym(RTLD_NEXT, "fscanf");
    }

    if (is_marked(stream)) {

        // If data is consumed, signal data_consumed_cond
        mutex_ifset_signal(&data_consumed_mutex, &data_consumed_cond,
            &is_data_consumed);
        // Wait if data is not ready
        mutex_wait_check(&data_ready_mutex, &data_ready_cond, &is_data_ready);

        // Check if need to break current connection
        if (need_break_conn) {
            mutex_signal_set(&break_conn_mutex, &break_conn_cond,
                &has_done_break_conn);
            return 0;
        }

        va_list args;
        va_start(args, format);
        int ret = read_and_match_from_shared_memory(format, args);
        va_end(args);
        return ret;
    }
    else {
        va_list args;
        va_start(args, format);
        int ret = orig_fscanf(stream, format, args);
        va_end(args);
        return ret;
    }
}


int fputs(const char* restrict s, FILE* restrict stream) {


    if (!orig_fputs)
        orig_fputs = dlsym(RTLD_NEXT, "fputs");

    int sockfd = fileno(stream);


    // Dummy fd should not write
    if (has_got_dummy_fd && (sockfd == new_dummy_fd || sockfd == dummy_fd)) {
        LOG("call fputs with dummy_fd\n");
        return 0;
    }

    return orig_fputs(s,stream);
}

int fputc(int c, FILE* stream) {


    if (!orig_fputc)
        orig_fputc = dlsym(RTLD_NEXT, "fputc");

    int sockfd = fileno(stream);


    // Dummy fd should not write
    if (has_got_dummy_fd && (sockfd == new_dummy_fd || sockfd == dummy_fd)) {
        LOG("call fputc with dummy_fd\n");
        return c;
    }

    return orig_fputc(c, stream);

}

size_t fwrite(const void* restrict ptr, size_t size, size_t nmemb, FILE* restrict stream) {
   
    if (!orig_fwrite)
        orig_fwrite = dlsym(RTLD_NEXT, "fwrite");

    int sockfd = fileno(stream);


    // Dummy fd should not write
    if (has_got_dummy_fd && (sockfd == new_dummy_fd || sockfd == dummy_fd)) {
        LOG("call fwrite with dummy_fd\n");
        return size* nmemb;
    }

    return orig_fwrite(ptr,size,nmemb,stream);
}


void set_recvfrom_manual_msg( struct sockaddr* src_addr, socklen_t* addrlen) {

    if (src_addr != NULL && addrlen != NULL) {
        if (*addrlen >= sizeof(struct sockaddr_in)) {
            struct sockaddr_in* src_in = (struct sockaddr_in*)src_addr;
            src_in->sin_family = AF_INET;
            src_in->sin_port = htons(net_port);
            inet_pton(AF_INET, net_ip, &(src_in->sin_addr));
            *addrlen = sizeof(struct sockaddr_in);
        }
    }

}


void set_manual_msg(struct msghdr* msg) {
    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(10000);
    inet_pton(AF_INET, "127.0.0.1", &(target_addr.sin_addr));

    memcpy(msg->msg_name, &target_addr, sizeof(struct sockaddr_in));

    struct in_pktinfo ip_pktinfo_value;
    ip_pktinfo_value.ipi_spec_dst.s_addr = inet_addr("127.0.0.1");

    ip_pktinfo_value.ipi_ifindex = 1;

    char            control_buffer[CMSG_SPACE(sizeof(struct in_pktinfo))];
    struct cmsghdr* cmptr = (struct cmsghdr*)control_buffer;

    cmptr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
    cmptr->cmsg_level = IPPROTO_IP;
    cmptr->cmsg_type = IP_PKTINFO;

    memcpy(CMSG_DATA(cmptr), &ip_pktinfo_value, sizeof(struct in_pktinfo));

    memcpy(msg->msg_control, control_buffer, sizeof(control_buffer));
}

void hex_dump(u8* buf, int len) {

 #if DEBUG
  int i, j;

  // 每行显示16个字节
  for (i = 0; i < len; i += 16) {
    printf("%08x: ", i);  // 打印行地址

    // 打印十六进制值
    for (j = 0; j < 16; j++) {
        if (i + j < len) {
            printf("%02x ", buf[i + j]);
        } else {
            printf("   ");  // 不足16字节的部分补空格
        }
    }

    printf("  ");

    // 打印ASCII字符
    for (j = 0; j < 16; j++) {
        if (i + j < len) {
            if (buf[i + j] >= 32 && buf[i + j] <= 126) {
              printf("%c", buf[i + j]);  // 可打印字符
            } else {
              printf(".");  // 不可打印字符显示为点号
            }
        }
    }

    printf("\n");
  }
  #endif
}

// 打印传入的fd_set中的所有fd的集合，用"[]"括起来
void print_fd_set(fd_set *readfds, int nfds) {
#if DEBUG
  if (readfds == NULL) {
    printf("NULL\n");
    return;
  }

  printf("[");
  int printed = 0;
  for (int fd = 0; fd < nfds; ++fd) {
    if (FD_ISSET(fd, readfds)) {
        if (printed > 0) { printf(", "); }
        printf("%d", fd);
        printed++;
    }
  }
  printf("]\n");
#endif
}

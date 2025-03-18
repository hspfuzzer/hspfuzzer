/*
   american fuzzy lop++ - forkserver code
   --------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com> and
                        Dominik Maier <mail@dmnk.co>


   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2023 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Shared code that implements a forkserver. This is used by the fuzzer
   as well the other components like afl-tmin.

 */

#include "config.h"
#include "types.h"
#include "debug.h"
#include "common.h"
#include "list.h"
#include "forkserver.h"
#include "hash.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/stat.h>

#define DEBUG 0
#if DEBUG
  #define LOG(format, ...)                                                    \
    do {                                                                      \
      struct timespec ts;                                                     \
      clock_gettime(CLOCK_REALTIME, &ts);                                     \
      printf("[fuzz][%ld.%06ld][%d][%d][%s] " format, ts.tv_sec,              \
             ts.tv_nsec / 1000, getpid(), gettid(), __func__, ##__VA_ARGS__); \
    } while (0)
#else
  #define LOG(format, ...)
#endif  // DEBUG

#ifdef __linux__
  #include <dlfcn.h>

/* function to load nyx_helper function from libnyx.so */

nyx_plugin_handler_t *afl_load_libnyx_plugin(u8 *libnyx_binary) {

  void                 *handle;
  nyx_plugin_handler_t *plugin = calloc(1, sizeof(nyx_plugin_handler_t));

  ACTF("Trying to load libnyx.so plugin...");
  handle = dlopen((char *)libnyx_binary, RTLD_NOW);
  if (!handle) { goto fail; }

  plugin->nyx_config_load = dlsym(handle, "nyx_config_load");
  if (plugin->nyx_config_load == NULL) { goto fail; }

  plugin->nyx_config_set_workdir_path =
      dlsym(handle, "nyx_config_set_workdir_path");
  if (plugin->nyx_config_set_workdir_path == NULL) { goto fail; }

  plugin->nyx_config_set_input_buffer_size =
      dlsym(handle, "nyx_config_set_input_buffer_size");
  if (plugin->nyx_config_set_input_buffer_size == NULL) { goto fail; }

  plugin->nyx_config_set_input_buffer_write_protection =
      dlsym(handle, "nyx_config_set_input_buffer_write_protection");
  if (plugin->nyx_config_set_input_buffer_write_protection == NULL) {

    goto fail;

  }

  plugin->nyx_config_set_hprintf_fd =
      dlsym(handle, "nyx_config_set_hprintf_fd");
  if (plugin->nyx_config_set_hprintf_fd == NULL) { goto fail; }

  plugin->nyx_config_set_process_role =
      dlsym(handle, "nyx_config_set_process_role");
  if (plugin->nyx_config_set_process_role == NULL) { goto fail; }

  plugin->nyx_config_set_reuse_snapshot_path =
      dlsym(handle, "nyx_config_set_reuse_snapshot_path");
  if (plugin->nyx_config_set_reuse_snapshot_path == NULL) { goto fail; }

  plugin->nyx_new = dlsym(handle, "nyx_new");
  if (plugin->nyx_new == NULL) { goto fail; }

  plugin->nyx_shutdown = dlsym(handle, "nyx_shutdown");
  if (plugin->nyx_shutdown == NULL) { goto fail; }

  plugin->nyx_option_set_reload_mode =
      dlsym(handle, "nyx_option_set_reload_mode");
  if (plugin->nyx_option_set_reload_mode == NULL) { goto fail; }

  plugin->nyx_option_set_timeout = dlsym(handle, "nyx_option_set_timeout");
  if (plugin->nyx_option_set_timeout == NULL) { goto fail; }

  plugin->nyx_option_apply = dlsym(handle, "nyx_option_apply");
  if (plugin->nyx_option_apply == NULL) { goto fail; }

  plugin->nyx_set_afl_input = dlsym(handle, "nyx_set_afl_input");
  if (plugin->nyx_set_afl_input == NULL) { goto fail; }

  plugin->nyx_exec = dlsym(handle, "nyx_exec");
  if (plugin->nyx_exec == NULL) { goto fail; }

  plugin->nyx_get_bitmap_buffer = dlsym(handle, "nyx_get_bitmap_buffer");
  if (plugin->nyx_get_bitmap_buffer == NULL) { goto fail; }

  plugin->nyx_get_bitmap_buffer_size =
      dlsym(handle, "nyx_get_bitmap_buffer_size");
  if (plugin->nyx_get_bitmap_buffer_size == NULL) { goto fail; }

  plugin->nyx_get_aux_string = dlsym(handle, "nyx_get_aux_string");
  if (plugin->nyx_get_aux_string == NULL) { goto fail; }

  plugin->nyx_remove_work_dir = dlsym(handle, "nyx_remove_work_dir");
  if (plugin->nyx_remove_work_dir == NULL) { goto fail; }

  plugin->nyx_config_set_aux_buffer_size =
      dlsym(handle, "nyx_config_set_aux_buffer_size");
  if (plugin->nyx_config_set_aux_buffer_size == NULL) { goto fail; }

  OKF("libnyx plugin is ready!");
  return plugin;

fail:

  FATAL("failed to load libnyx: %s\n", dlerror());
  ck_free(plugin);
  return NULL;

}

void afl_nyx_runner_kill(afl_forkserver_t *fsrv) {

  if (fsrv->nyx_mode) {

    if (fsrv->nyx_aux_string) { ck_free(fsrv->nyx_aux_string); }

    /* check if we actually got a valid nyx runner */
    if (fsrv->nyx_runner) {

      fsrv->nyx_handlers->nyx_shutdown(fsrv->nyx_runner);

    }

    /* if we have use a tmp work dir we need to remove it */
    if (fsrv->nyx_use_tmp_workdir && fsrv->nyx_tmp_workdir_path) {

      remove_nyx_tmp_workdir(fsrv, fsrv->nyx_tmp_workdir_path);

    }

    if (fsrv->nyx_log_fd >= 0) { close(fsrv->nyx_log_fd); }

  }

}

  /* Wrapper for FATAL() that kills the nyx runner (and removes all created tmp
   * files) before exiting. Used before "afl_fsrv_killall()" is registered as
   * an atexit() handler. */
  #define NYX_PRE_FATAL(fsrv, x...) \
    do {                            \
                                    \
      afl_nyx_runner_kill(fsrv);    \
      FATAL(x);                     \
                                    \
    } while (0)

#endif

/**
 * The correct fds for reading and writing pipes
 */

/* Describe integer as memory size. */

static list_t fsrv_list = {.element_prealloc_count = 0};

static void fsrv_exec_child(afl_forkserver_t *fsrv, char **argv) {

  if (fsrv->qemu_mode || fsrv->cs_mode) {

    setenv("AFL_DISABLE_LLVM_INSTRUMENTATION", "1", 0);

  }

  execv(fsrv->target_path, argv);

  WARNF("Execv failed in forkserver.");

}

/* Initializes the struct */

void afl_fsrv_init(afl_forkserver_t *fsrv) {

#ifdef __linux__
  fsrv->nyx_handlers = NULL;
  fsrv->out_dir_path = NULL;
  fsrv->nyx_mode = 0;
  fsrv->nyx_parent = false;
  fsrv->nyx_standalone = false;
  fsrv->nyx_runner = NULL;
  fsrv->nyx_id = 0xFFFFFFFF;
  fsrv->nyx_bind_cpu_id = 0xFFFFFFFF;
  fsrv->nyx_use_tmp_workdir = false;
  fsrv->nyx_tmp_workdir_path = NULL;
  fsrv->nyx_log_fd = -1;
#endif

  // this structure needs default so we initialize it if this was not done
  // already
  fsrv->out_fd = -1;
  fsrv->out_dir_fd = -1;
  fsrv->dev_null_fd = -1;
  fsrv->dev_urandom_fd = -1;

  /* Settings */
  fsrv->use_stdin = true;
  fsrv->no_unlink = false;
  fsrv->exec_tmout = EXEC_TIMEOUT;
  fsrv->init_tmout = EXEC_TIMEOUT * FORK_WAIT_MULT;
  fsrv->mem_limit = MEM_LIMIT;
  fsrv->out_file = NULL;
  fsrv->child_kill_signal = SIGKILL;

  /* Nethook*/
  fsrv->new_start_tmout = 5000;
  fsrv->new_conn_tmout = 10;
  fsrv->timeout_times_threh = 5;
  fsrv->badconn_times_threh = 6;

  /* exec related stuff */
  fsrv->child_pid = -1;
  fsrv->map_size = get_map_size();
  fsrv->real_map_size = fsrv->map_size;
  fsrv->use_fauxsrv = false;
  fsrv->last_run_timed_out = false;
  fsrv->debug = false;
  fsrv->uses_crash_exitcode = false;
  fsrv->uses_asan = false;

  fsrv->init_child_func = fsrv_exec_child;

  //fsrv->need_new_conn = 1; /* xzw : At first need new conn */

  list_append(&fsrv_list, fsrv);

}

/* Initialize a new forkserver instance, duplicating "global" settings */
void afl_fsrv_init_dup(afl_forkserver_t *fsrv_to, afl_forkserver_t *from) {

  fsrv_to->use_stdin = from->use_stdin;
  fsrv_to->dev_null_fd = from->dev_null_fd;
  fsrv_to->exec_tmout = from->exec_tmout;
  fsrv_to->init_tmout = from->init_tmout;
  fsrv_to->mem_limit = from->mem_limit;
  fsrv_to->map_size = from->map_size;
  fsrv_to->real_map_size = from->real_map_size;
  fsrv_to->support_shmem_fuzz = from->support_shmem_fuzz;
  fsrv_to->out_file = from->out_file;
  fsrv_to->dev_urandom_fd = from->dev_urandom_fd;
  fsrv_to->out_fd = from->out_fd;  // not sure this is a good idea
  fsrv_to->no_unlink = from->no_unlink;
  fsrv_to->uses_crash_exitcode = from->uses_crash_exitcode;
  fsrv_to->crash_exitcode = from->crash_exitcode;
  fsrv_to->child_kill_signal = from->child_kill_signal;
  fsrv_to->fsrv_kill_signal = from->fsrv_kill_signal;
  fsrv_to->debug = from->debug;

  // These are forkserver specific.
  fsrv_to->out_dir_fd = -1;
  fsrv_to->child_pid = -1;
  fsrv_to->use_fauxsrv = 0;
  fsrv_to->last_run_timed_out = 0;

  fsrv_to->init_child_func = from->init_child_func;
  // Note: do not copy ->add_extra_func or ->persistent_record*

  fsrv_to->need_new_conn = from->need_new_conn; /* xzw:not sure this is a good idea */
  fsrv_to->forced_kill = from->forced_kill;
  fsrv_to->no_connection_reuse = from->no_connection_reuse;
  fsrv_to->no_multi_connection = from->no_multi_connection;
  fsrv_to->ewma_enabled = from->ewma_enabled;
  list_append(&fsrv_list, fsrv_to);

}

/* Wrapper for select() and read(), reading a 32 bit var.
  Returns the time passed to read.
  If the wait times out, returns timeout_ms + 1;
  Returns 0 if an error occurred (fd closed, signal, ...); */
static u32 __attribute__((hot))
read_s32_timed(s32 fd, s32 *buf, u32 timeout_ms, volatile u8 *stop_soon_p) {

  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(fd, &readfds);
  struct timeval timeout;
  int            sret;
  ssize_t        len_read;

  timeout.tv_sec = (timeout_ms / 1000);
  timeout.tv_usec = (timeout_ms % 1000) * 1000;
#if !defined(__linux__)
  u32 read_start = get_cur_time_us();
#endif

  /* set exceptfds as well to return when a child exited/closed the pipe. */
restart_select:
  sret = select(fd + 1, &readfds, NULL, NULL, &timeout);

  if (likely(sret > 0)) {

  restart_read:
    if (*stop_soon_p) {

      // Early return - the user wants to quit.
      return 0;

    }

    len_read = read(fd, (u8 *)buf, 4);

    if (likely(len_read == 4)) {  // for speed we put this first

#if defined(__linux__)
      u32 exec_ms = MIN(
          timeout_ms,
          ((u64)timeout_ms - (timeout.tv_sec * 1000 + timeout.tv_usec / 1000)));
#else
      u32 exec_ms = MIN(timeout_ms, (get_cur_time_us() - read_start) / 1000);
#endif

      // ensure to report 1 ms has passed (0 is an error)
      return exec_ms > 0 ? exec_ms : 1;

    } else if (unlikely(len_read == -1 && errno == EINTR)) {

      goto restart_read;

    } else if (unlikely(len_read < 4)) {

      return 0;

    }

  } else if (unlikely(!sret)) {

    *buf = -1;
    return timeout_ms + 1;

  } else if (unlikely(sret < 0)) {

    if (likely(errno == EINTR)) goto restart_select;

    *buf = -1;
    return 0;

  }

  return 0;  // not reached

}

/* Internal forkserver for non_instrumented_mode=1 and non-forkserver mode runs.
  It execvs for each fork, forwarding exit codes and child pids to afl. */

static void afl_fauxsrv_execv(afl_forkserver_t *fsrv, char **argv) {

  unsigned char tmp[4] = {0, 0, 0, 0};
  pid_t         child_pid;

  if (!be_quiet) { ACTF("Using Fauxserver:"); }

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) {

    abort();  // TODO: Abort?

  }

  void (*old_sigchld_handler)(int) = signal(SIGCHLD, SIG_DFL);

  while (1) {

    uint32_t was_killed;
    int      status;

    /* Wait for parent by reading from the pipe. Exit if read fails. */

    if (read(FORKSRV_FD, &was_killed, 4) != 4) { exit(0); }

    /* Create a clone of our process. */

    child_pid = fork();

    if (child_pid < 0) { PFATAL("Fork failed"); }

    /* In child process: close fds, resume execution. */

    if (!child_pid) {  // New child

      close(fsrv->out_dir_fd);
      close(fsrv->dev_null_fd);
      close(fsrv->dev_urandom_fd);

      if (fsrv->plot_file != NULL) {

        fclose(fsrv->plot_file);
        fsrv->plot_file = NULL;

      }

      // enable terminating on sigpipe in the childs
      struct sigaction sa;
      memset((char *)&sa, 0, sizeof(sa));
      sa.sa_handler = SIG_DFL;
      sigaction(SIGPIPE, &sa, NULL);

      signal(SIGCHLD, old_sigchld_handler);

      // FORKSRV_FD is for communication with AFL, we don't need it in the
      // child
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);

      // finally: exec...
      execv(fsrv->target_path, argv);

      /* Use a distinctive bitmap signature to tell the parent about execv()
        falling through. */

      *(u32 *)fsrv->trace_bits = EXEC_FAIL_SIG;

      WARNF("Execv failed in fauxserver.");
      break;

    }

    /* In parent process: write PID to AFL. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) { exit(0); }

    /* after child exited, get and relay exit status to parent through waitpid.
     */

    if (waitpid(child_pid, &status, 0) < 0) {

      // Zombie Child could not be collected. Scary!
      WARNF("Fauxserver could not determine child's exit code. ");

    }

    /* Relay wait status to AFL pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) { exit(1); }

  }

}

/* Report on the error received via the forkserver controller and exit */
static void report_error_and_exit(int error) {

  switch (error) {

    case FS_ERROR_MAP_SIZE:
      FATAL(
          "AFL_MAP_SIZE is not set and fuzzing target reports that the "
          "required size is very large. Solution: Run the fuzzing target "
          "stand-alone with the environment variable AFL_DEBUG=1 set and set "
          "the value for __afl_final_loc in the AFL_MAP_SIZE environment "
          "variable for afl-fuzz.");
      break;
    case FS_ERROR_MAP_ADDR:
      FATAL(
          "the fuzzing target reports that hardcoded map address might be the "
          "reason the mmap of the shared memory failed. Solution: recompile "
          "the target with either afl-clang-lto and do not set "
          "AFL_LLVM_MAP_ADDR or recompile with afl-clang-fast.");
      break;
    case FS_ERROR_SHM_OPEN:
      FATAL("the fuzzing target reports that the shm_open() call failed.");
      break;
    case FS_ERROR_SHMAT:
      FATAL("the fuzzing target reports that the shmat() call failed.");
      break;
    case FS_ERROR_MMAP:
      FATAL(
          "the fuzzing target reports that the mmap() call to the shared "
          "memory failed.");
      break;
    case FS_ERROR_OLD_CMPLOG:
      FATAL(
          "the -c cmplog target was instrumented with an too old AFL++ "
          "version, you need to recompile it.");
      break;
    case FS_ERROR_OLD_CMPLOG_QEMU:
      FATAL(
          "The AFL++ QEMU/FRIDA loaders are from an older version, for -c you "
          "need to recompile it.\n");
      break;
    default:
      FATAL("unknown error code %d from fuzzing target!", error);

  }

}

/* Spins up fork server. The idea is explained here:

   https://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html

   In essence, the instrumentation allows us to skip execve(), and just keep
   cloning a stopped child. So, we just execute once, and then send commands
   through a pipe. The other part of this logic is in afl-as.h / llvm_mode */

void afl_fsrv_start(afl_forkserver_t *fsrv, char **argv,
                    volatile u8 *stop_soon_p, u8 debug_child_output) {

  int   st_pipe[2], ctl_pipe[2];
  int   send_pipe[2], recv_pipe[2];
  s32   status;
  s32   rlen;
  char *ignore_autodict = getenv("AFL_NO_AUTODICT");

#ifdef __linux__
  if (unlikely(fsrv->nyx_mode)) {

    if (fsrv->nyx_runner != NULL) { return; }

    if (!be_quiet) { ACTF("Spinning up the NYX backend..."); }

    if (fsrv->nyx_use_tmp_workdir) {

      fsrv->nyx_tmp_workdir_path = create_nyx_tmp_workdir();
      fsrv->out_dir_path = fsrv->nyx_tmp_workdir_path;

    } else {

      if (fsrv->out_dir_path == NULL) {

        NYX_PRE_FATAL(fsrv, "Nyx workdir path not found...");

      }

    }

    /* libnyx expects an absolute path */
    char *outdir_path_absolute = realpath(fsrv->out_dir_path, NULL);
    if (outdir_path_absolute == NULL) {

      NYX_PRE_FATAL(fsrv, "Nyx workdir path cannot be resolved ...");

    }

    char *workdir_path = alloc_printf("%s/workdir", outdir_path_absolute);

    if (fsrv->nyx_id == 0xFFFFFFFF) {

      NYX_PRE_FATAL(fsrv, "Nyx ID is not set...");

    }

    if (fsrv->nyx_bind_cpu_id == 0xFFFFFFFF) {

      NYX_PRE_FATAL(fsrv, "Nyx CPU ID is not set...");

    }

    void *nyx_config = fsrv->nyx_handlers->nyx_config_load(fsrv->target_path);

    fsrv->nyx_handlers->nyx_config_set_workdir_path(nyx_config, workdir_path);
    fsrv->nyx_handlers->nyx_config_set_input_buffer_size(nyx_config, MAX_FILE);
    fsrv->nyx_handlers->nyx_config_set_input_buffer_write_protection(nyx_config,
                                                                     true);

    char *nyx_log_path = getenv("AFL_NYX_LOG");
    if (nyx_log_path) {

      fsrv->nyx_log_fd =
          open(nyx_log_path, O_CREAT | O_TRUNC | O_WRONLY, DEFAULT_PERMISSION);
      if (fsrv->nyx_log_fd < 0) {

        NYX_PRE_FATAL(fsrv, "AFL_NYX_LOG path could not be written");

      }

      fsrv->nyx_handlers->nyx_config_set_hprintf_fd(nyx_config,
                                                    fsrv->nyx_log_fd);

    }

    if (fsrv->nyx_standalone) {

      fsrv->nyx_handlers->nyx_config_set_process_role(nyx_config, StandAlone);

    } else {

      if (fsrv->nyx_parent) {

        fsrv->nyx_handlers->nyx_config_set_process_role(nyx_config, Parent);

      } else {

        fsrv->nyx_handlers->nyx_config_set_process_role(nyx_config, Child);

      }

    }

    if (getenv("AFL_NYX_AUX_SIZE") != NULL) {

      fsrv->nyx_aux_string_len = atoi(getenv("AFL_NYX_AUX_SIZE"));

      if (fsrv->nyx_handlers->nyx_config_set_aux_buffer_size(
              nyx_config, fsrv->nyx_aux_string_len) != 1) {

        NYX_PRE_FATAL(fsrv,
                      "Invalid AFL_NYX_AUX_SIZE value set (must be a multiple "
                      "of 4096) ...");

      }

    } else {

      fsrv->nyx_aux_string_len = 0x1000;

    }

    if (getenv("AFL_NYX_REUSE_SNAPSHOT") != NULL) {

      if (access(getenv("AFL_NYX_REUSE_SNAPSHOT"), F_OK) == -1) {

        NYX_PRE_FATAL(fsrv, "AFL_NYX_REUSE_SNAPSHOT path does not exist");

      }

      /* stupid sanity check to avoid passing an empty or invalid snapshot
       * directory */
      char *snapshot_file_path =
          alloc_printf("%s/global.state", getenv("AFL_NYX_REUSE_SNAPSHOT"));
      if (access(snapshot_file_path, R_OK) == -1) {

        NYX_PRE_FATAL(fsrv,
                      "AFL_NYX_REUSE_SNAPSHOT path does not contain a valid "
                      "Nyx snapshot");

      }

      ck_free(snapshot_file_path);

      /* another sanity check to avoid passing a snapshot directory that is
       * located in the current workdir (the workdir will be wiped by libnyx on
       * startup) */
      char *workdir_snapshot_path =
          alloc_printf("%s/workdir/snapshot", outdir_path_absolute);
      char *reuse_snapshot_path_real =
          realpath(getenv("AFL_NYX_REUSE_SNAPSHOT"), NULL);

      if (strcmp(workdir_snapshot_path, reuse_snapshot_path_real) == 0) {

        NYX_PRE_FATAL(
            fsrv,
            "AFL_NYX_REUSE_SNAPSHOT path is located in current workdir "
            "(use another output directory)");

      }

      ck_free(reuse_snapshot_path_real);
      ck_free(workdir_snapshot_path);

      fsrv->nyx_handlers->nyx_config_set_reuse_snapshot_path(
          nyx_config, getenv("AFL_NYX_REUSE_SNAPSHOT"));

    }

    fsrv->nyx_runner = fsrv->nyx_handlers->nyx_new(nyx_config, fsrv->nyx_id);

    ck_free(workdir_path);
    ck_free(outdir_path_absolute);

    if (fsrv->nyx_runner == NULL) { FATAL("Something went wrong ..."); }

    u32 tmp_map_size =
        fsrv->nyx_handlers->nyx_get_bitmap_buffer_size(fsrv->nyx_runner);
    fsrv->real_map_size = tmp_map_size;
    fsrv->map_size = (((tmp_map_size + 63) >> 6) << 6);
    if (!be_quiet) { ACTF("Target map size: %u", fsrv->real_map_size); }

    fsrv->trace_bits =
        fsrv->nyx_handlers->nyx_get_bitmap_buffer(fsrv->nyx_runner);

    fsrv->nyx_handlers->nyx_option_set_reload_mode(
        fsrv->nyx_runner, getenv("AFL_NYX_DISABLE_SNAPSHOT_MODE") == NULL);
    fsrv->nyx_handlers->nyx_option_apply(fsrv->nyx_runner);

    fsrv->nyx_handlers->nyx_option_set_timeout(fsrv->nyx_runner, 2, 0);
    fsrv->nyx_handlers->nyx_option_apply(fsrv->nyx_runner);

    fsrv->nyx_aux_string = malloc(fsrv->nyx_aux_string_len);
    memset(fsrv->nyx_aux_string, 0, fsrv->nyx_aux_string_len);

    /* dry run */
    fsrv->nyx_handlers->nyx_set_afl_input(fsrv->nyx_runner, "INIT", 4);
    switch (fsrv->nyx_handlers->nyx_exec(fsrv->nyx_runner)) {

      case Abort:
        NYX_PRE_FATAL(fsrv, "Error: Nyx abort occurred...");
        break;
      case IoError:
        NYX_PRE_FATAL(fsrv, "Error: QEMU-Nyx has died...");
        break;
      case Error:
        NYX_PRE_FATAL(fsrv, "Error: Nyx runtime error has occurred...");
        break;
      default:
        break;

    }

    /* autodict in Nyx mode */
    if (!ignore_autodict) {

      char *x =
          alloc_printf("%s/workdir/dump/afl_autodict.txt", fsrv->out_dir_path);
      int nyx_autodict_fd = open(x, O_RDONLY);
      ck_free(x);

      if (nyx_autodict_fd >= 0) {

        struct stat st;
        if (fstat(nyx_autodict_fd, &st) >= 0) {

          u32 f_len = st.st_size;
          u8 *dict = ck_alloc(f_len);
          if (dict == NULL) {

            NYX_PRE_FATAL(
                fsrv, "Could not allocate %u bytes of autodictionary memory",
                f_len);

          }

          u32 offset = 0, count = 0;
          u32 len = f_len;

          while (len != 0) {

            rlen = read(nyx_autodict_fd, dict + offset, len);
            if (rlen > 0) {

              len -= rlen;
              offset += rlen;

            } else {

              NYX_PRE_FATAL(
                  fsrv,
                  "Reading autodictionary fail at position %u with %u bytes "
                  "left.",
                  offset, len);

            }

          }

          offset = 0;
          while (offset < (u32)f_len &&
                 (u8)dict[offset] + offset < (u32)f_len) {

            fsrv->add_extra_func(fsrv->afl_ptr, dict + offset + 1,
                                 (u8)dict[offset]);
            offset += (1 + dict[offset]);
            count++;

          }

          if (!be_quiet) { ACTF("Loaded %u autodictionary entries", count); }
          ck_free(dict);

        }

        close(nyx_autodict_fd);

      }

    }

    return;

  }

#endif

  if (!be_quiet) { ACTF("Spinning up the fork server..."); }

#ifdef AFL_PERSISTENT_RECORD
  if (unlikely(fsrv->persistent_record)) {

    fsrv->persistent_record_data =
        (u8 **)ck_alloc(fsrv->persistent_record * sizeof(u8 *));
    fsrv->persistent_record_len =
        (u32 *)ck_alloc(fsrv->persistent_record * sizeof(u32));

    if (!fsrv->persistent_record_data || !fsrv->persistent_record_len) {

      FATAL("Unable to allocate memory for persistent replay.");

    }

  }

#endif

  if (fsrv->use_fauxsrv) {

    /* TODO: Come up with some nice way to initialize this all */

    if (fsrv->init_child_func != fsrv_exec_child) {

      FATAL("Different forkserver not compatible with fauxserver");

    }

    if (!be_quiet) { ACTF("Using AFL++ faux forkserver..."); }
    fsrv->init_child_func = afl_fauxsrv_execv;

  }

  if (pipe(st_pipe) || pipe(ctl_pipe)) { PFATAL("pipe() failed"); }
  if (pipe(recv_pipe) || pipe(send_pipe)) { PFATAL("pipe() failed"); } //nethook add

  fsrv->last_run_timed_out = 0;
  fsrv->fsrv_pid = fork();

  if (fsrv->fsrv_pid < 0) { PFATAL("fork() failed"); }

  if (!fsrv->fsrv_pid) {

    /* CHILD PROCESS */

    // enable terminating on sigpipe in the childs
    struct sigaction sa;
    memset((char *)&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigaction(SIGPIPE, &sa, NULL);

    struct rlimit r;

    if (!fsrv->cmplog_binary) {

      unsetenv(CMPLOG_SHM_ENV_VAR);  // we do not want that in non-cmplog fsrv

    }

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... */
    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {

      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r);                        /* Ignore errors */

    }

    if (fsrv->mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)fsrv->mem_limit) << 20;

#ifdef RLIMIT_AS
      setrlimit(RLIMIT_AS, &r);                            /* Ignore errors */
#else
      /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. */

      setrlimit(RLIMIT_DATA, &r);                          /* Ignore errors */
#endif                                                        /* ^RLIMIT_AS */

    }

    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. */

    if (!fsrv->debug) {

      r.rlim_max = r.rlim_cur = 0;
      setrlimit(RLIMIT_CORE, &r);                          /* Ignore errors */

    }

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

    setsid();

    if (!(debug_child_output)) {

      dup2(fsrv->dev_null_fd, 1);
      dup2(fsrv->dev_null_fd, 2);

    }

    if (!fsrv->use_stdin) {

      dup2(fsrv->dev_null_fd, 0);

    } else {

      dup2(fsrv->out_fd, 0);
      close(fsrv->out_fd);

    }

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) { PFATAL("dup2() failed"); }
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) { PFATAL("dup2() failed"); }

    // nethook add
    if (dup2(send_pipe[0], FORKSRV_FD + 3) < 0) { PFATAL("dup2() failed"); }
    if (dup2(recv_pipe[1], FORKSRV_FD + 4) < 0) { PFATAL("dup2() failed"); }

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    // nethook add
    close(send_pipe[0]);
    close(send_pipe[1]);
    close(recv_pipe[0]);
    close(recv_pipe[1]);

    close(fsrv->out_dir_fd);
    close(fsrv->dev_null_fd);
    close(fsrv->dev_urandom_fd);

    if (fsrv->plot_file != NULL) {

      fclose(fsrv->plot_file);
      fsrv->plot_file = NULL;

    }

    /* This should improve performance a bit, since it stops the linker from
       doing extra work post-fork(). */

    if (!getenv("LD_BIND_LAZY")) { setenv("LD_BIND_NOW", "1", 1); }

    /* Set sane defaults for sanitizers */
    set_sanitizer_defaults();

    fsrv->init_child_func(fsrv, argv);

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */

    *(u32 *)fsrv->trace_bits = EXEC_FAIL_SIG;
    FATAL("Error: execv to target failed\n");

  }

  /* PARENT PROCESS */

  char pid_buf[16];
  sprintf(pid_buf, "%d", fsrv->fsrv_pid);
  if (fsrv->cmplog_binary)
    setenv("__AFL_TARGET_PID2", pid_buf, 1);
  else
    setenv("__AFL_TARGET_PID1", pid_buf, 1);

  /* Close the unneeded endpoints. */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  // nethook
  close(send_pipe[0]);
  close(recv_pipe[1]);

  fsrv->fsrv_ctl_fd = ctl_pipe[1];
  fsrv->fsrv_st_fd = st_pipe[0];

  // nethook
  fsrv->hook_ctl_fd = send_pipe[1];
  fsrv->hook_st_fd = recv_pipe[0];

  /* Wait for the fork server to come up, but don't wait too long. */

  rlen = 0;
  if (fsrv->init_tmout) {

    u32 time_ms = read_s32_timed(fsrv->fsrv_st_fd, &status, fsrv->init_tmout,
                                 stop_soon_p);

    if (!time_ms) {

      s32 tmp_pid = fsrv->fsrv_pid;
      if (tmp_pid > 0) {

        kill(tmp_pid, fsrv->child_kill_signal);
        fsrv->fsrv_pid = -1;

      }

    } else if (time_ms > fsrv->init_tmout) {

      fsrv->last_run_timed_out = 1;
      s32 tmp_pid = fsrv->fsrv_pid;
      if (tmp_pid > 0) {

        kill(tmp_pid, fsrv->child_kill_signal);
        fsrv->fsrv_pid = -1;

      }

    } else {

      rlen = 4;

    }

  } else {

    rlen = read(fsrv->fsrv_st_fd, &status, 4);

  }

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4) {

    if (!be_quiet) { OKF("All right - fork server is up."); }

     // xzw destructive enable
    fsrv->use_shmem_fuzz = 1;
    ACTF("Using SHARED MEMORY FUZZING feature(forced).");

    if (getenv("AFL_DEBUG")) {

      ACTF("Extended forkserver functions received (%08x).", status);

    }

    if ((status & FS_OPT_ERROR) == FS_OPT_ERROR)
      report_error_and_exit(FS_OPT_GET_ERROR(status));

    if ((status & FS_OPT_ENABLED) == FS_OPT_ENABLED) {

      // workaround for recent AFL++ versions
      if ((status & FS_OPT_OLD_AFLPP_WORKAROUND) == FS_OPT_OLD_AFLPP_WORKAROUND)
        status = (status & 0xf0ffffff);

      if ((status & FS_OPT_NEWCMPLOG) == 0 && fsrv->cmplog_binary) {

        if (fsrv->qemu_mode || fsrv->frida_mode) {

          report_error_and_exit(FS_ERROR_OLD_CMPLOG_QEMU);

        } else {

          report_error_and_exit(FS_ERROR_OLD_CMPLOG);

        }

      }

      if ((status & FS_OPT_SNAPSHOT) == FS_OPT_SNAPSHOT) {

        fsrv->snapshot = 1;
        if (!be_quiet) { ACTF("Using SNAPSHOT feature."); }

      }

     

       //xzw add support to shm
      if (fsrv->use_net || (status & FS_OPT_SHDMEM_FUZZ) == FS_OPT_SHDMEM_FUZZ) {

        if (fsrv->support_shmem_fuzz || fsrv->use_net ) {

          fsrv->use_shmem_fuzz = 1;
          if (!be_quiet) { ACTF("Using SHARED MEMORY FUZZING feature(normal)."); }

          // Since nethook is force to use shared memory to fuzz, so do not go into the if. zyp
          if (!fsrv->use_net && ((status & FS_OPT_AUTODICT) == 0 || ignore_autodict)) {

            u32 send_status = (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ);
            if (write(fsrv->fsrv_ctl_fd, &send_status, 4) != 4) {

              FATAL("Writing to forkserver failed.");

            }

          }

        } else {

          FATAL(
              "Target requested sharedmem fuzzing, but we failed to enable "
              "it.");

        }
        ACTF("fsrv->use_shmem_fuzz:%d\n", fsrv->use_shmem_fuzz);
        ACTF("fsrv->support_shmem_fuzz:%d\n", fsrv->support_shmem_fuzz);
      }

      if ((status & FS_OPT_MAPSIZE) == FS_OPT_MAPSIZE) {

        u32 tmp_map_size = FS_OPT_GET_MAPSIZE(status);

        if (!fsrv->map_size) { fsrv->map_size = MAP_SIZE; }

        fsrv->real_map_size = tmp_map_size;

        if (tmp_map_size % 64) {

          tmp_map_size = (((tmp_map_size + 63) >> 6) << 6);

        }

        if (!be_quiet) { ACTF("Target map size: %u", fsrv->real_map_size); }
        if (tmp_map_size > fsrv->map_size) {

          FATAL(
              "Target's coverage map size of %u is larger than the one this "
              "AFL++ is set with (%u). Either set AFL_MAP_SIZE=%u and restart "
              " afl-fuzz, or change MAP_SIZE_POW2 in config.h and recompile "
              "afl-fuzz",
              tmp_map_size, fsrv->map_size, tmp_map_size);

        }

        fsrv->map_size = tmp_map_size;

      }

      if ((status & FS_OPT_AUTODICT) == FS_OPT_AUTODICT) {

        if (!ignore_autodict) {

          if (fsrv->add_extra_func == NULL || fsrv->afl_ptr == NULL) {

            // this is not afl-fuzz - or it is cmplog - we deny and return
            if (fsrv->use_shmem_fuzz) {

              status = (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ);

            } else {

              status = (FS_OPT_ENABLED);

            }

            if (write(fsrv->fsrv_ctl_fd, &status, 4) != 4) {

              FATAL("Writing to forkserver failed.");

            }

            return;

          }

          if (!be_quiet) { ACTF("Using AUTODICT feature."); }

          if (fsrv->use_shmem_fuzz) {

            status = (FS_OPT_ENABLED | FS_OPT_AUTODICT | FS_OPT_SHDMEM_FUZZ);

          } else {

            status = (FS_OPT_ENABLED | FS_OPT_AUTODICT);

          }

          if (write(fsrv->fsrv_ctl_fd, &status, 4) != 4) {

            FATAL("Writing to forkserver failed.");

          }

          if (read(fsrv->fsrv_st_fd, &status, 4) != 4) {

            FATAL("Reading from forkserver failed.");

          }

          if (status < 2 || (u32)status > 0xffffff) {

            FATAL("Dictionary has an illegal size: %d", status);

          }

          u32 offset = 0, count = 0;
          u32 len = status;
          u8 *dict = ck_alloc(len);
          if (dict == NULL) {

            FATAL("Could not allocate %u bytes of autodictionary memory", len);

          }

          while (len != 0) {

            rlen = read(fsrv->fsrv_st_fd, dict + offset, len);
            if (rlen > 0) {

              len -= rlen;
              offset += rlen;

            } else {

              FATAL(
                  "Reading autodictionary fail at position %u with %u bytes "
                  "left.",
                  offset, len);

            }

          }

          offset = 0;
          while (offset < (u32)status &&
                 (u8)dict[offset] + offset < (u32)status) {

            fsrv->add_extra_func(fsrv->afl_ptr, dict + offset + 1,
                                 (u8)dict[offset]);
            offset += (1 + dict[offset]);
            count++;

          }

          if (!be_quiet) { ACTF("Loaded %u autodictionary entries", count); }
          ck_free(dict);

        }

      }

    }

    return;

  }

  if (fsrv->last_run_timed_out) {

    FATAL(
        "Timeout while initializing fork server (setting "
        "AFL_FORKSRV_INIT_TMOUT may help)");

  }

  if (waitpid(fsrv->fsrv_pid, &status, 0) <= 0) { PFATAL("waitpid() failed"); }

  if (WIFSIGNALED(status)) {

    if (fsrv->mem_limit && fsrv->mem_limit < 500 && fsrv->uses_asan) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, "
           "before receiving any input\n"
           "    from the fuzzer! Since it seems to be built with ASAN and you "
           "have a\n"
           "    restrictive memory limit configured, this is expected; please "
           "run with '-m 0'.\n");

    } else if (!fsrv->mem_limit) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, "
           "before receiving any input\n"
           "    from the fuzzer! You can try the following:\n\n"

           "    - The target binary crashes because necessary runtime "
           "conditions it needs\n"
           "      are not met. Try to:\n"
           "      1. Run again with AFL_DEBUG=1 set and check the output of "
           "the target\n"
           "         binary for clues.\n"
           "      2. Run again with AFL_DEBUG=1 and 'ulimit -c unlimited' and "
           "analyze the\n"
           "         generated core dump.\n\n"

           "    - Possibly the target requires a huge coverage map and has "
           "CTORS.\n"
           "      Retry with setting AFL_MAP_SIZE=10000000.\n\n"

           MSG_FORK_ON_APPLE

           "    - Less likely, there is a horrible bug in the fuzzer. If other "
           "options\n"
           "      fail, poke the Awesome Fuzzing Discord for troubleshooting "
           "tips.\n");

    } else {

      u8 val_buf[STRINGIFY_VAL_SIZE_MAX];

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, "
           "before receiving any input\n"
           "    from the fuzzer! You can try the following:\n\n"

           "    - The target binary crashes because necessary runtime "
           "conditions it needs\n"
           "      are not met. Try to:\n"
           "      1. Run again with AFL_DEBUG=1 set and check the output of "
           "the target\n"
           "         binary for clues.\n"
           "      2. Run again with AFL_DEBUG=1 and 'ulimit -c unlimited' and "
           "analyze the\n"
           "         generated core dump.\n\n"

           "    - The current memory limit (%s) is too restrictive, causing "
           "the\n"
           "      target to hit an OOM condition in the dynamic linker. Try "
           "bumping up\n"
           "      the limit with the -m setting in the command line. A simple "
           "way confirm\n"
           "      this diagnosis would be:\n\n"

           MSG_ULIMIT_USAGE
           " /path/to/fuzzed_app )\n\n"

           "      Tip: you can use https://jwilk.net/software/recidivm to\n"
           "      estimate the required amount of virtual memory for the "
           "binary.\n\n"

           MSG_FORK_ON_APPLE

           "    - Possibly the target requires a huge coverage map and has "
           "CTORS.\n"
           "      Retry with setting AFL_MAP_SIZE=10000000.\n\n"

           "    - Less likely, there is a horrible bug in the fuzzer. If other "
           "options\n"
           "      fail, poke the Awesome Fuzzing Discord for troubleshooting "
           "tips.\n",
           stringify_mem_size(val_buf, sizeof(val_buf), fsrv->mem_limit << 20),
           fsrv->mem_limit - 1);

    }

    FATAL("Fork server crashed with signal %d", WTERMSIG(status));

  }

  if (*(u32 *)fsrv->trace_bits == EXEC_FAIL_SIG) {

    FATAL("Unable to execute target application ('%s')", argv[0]);

  }

  if (fsrv->mem_limit && fsrv->mem_limit < 500 && fsrv->uses_asan) {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated "
         "before we could complete a\n"
         "    handshake with the injected code. Since it seems to be built "
         "with ASAN and\n"
         "    you have a restrictive memory limit configured, this is "
         "expected; please\n"
         "    run with '-m 0'.\n");

  } else if (!fsrv->mem_limit) {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete"
         " a\n"
         "handshake with the injected code. You can try the following:\n\n"

         "    - The target binary crashes because necessary runtime conditions "
         "it needs\n"
         "      are not met. Try to:\n"
         "      1. Run again with AFL_DEBUG=1 set and check the output of the "
         "target\n"
         "         binary for clues.\n"
         "      2. Run again with AFL_DEBUG=1 and 'ulimit -c unlimited' and "
         "analyze the\n"
         "         generated core dump.\n\n"

         "    - Possibly the target requires a huge coverage map and has "
         "CTORS.\n"
         "      Retry with setting AFL_MAP_SIZE=10000000.\n\n"

         "Otherwise there is a horrible bug in the fuzzer.\n"
         "Poke the Awesome Fuzzing Discord for troubleshooting tips.\n");

  } else {

    u8 val_buf[STRINGIFY_VAL_SIZE_MAX];

    SAYF(
        "\n" cLRD "[-] " cRST
        "Hmm, looks like the target binary terminated "
        "before we could complete a\n"
        "    handshake with the injected code. You can try the following:\n\n"

        "%s"

        "    - The target binary crashes because necessary runtime conditions "
        "it needs\n"
        "      are not met. Try to:\n"
        "      1. Run again with AFL_DEBUG=1 set and check the output of the "
        "target\n"
        "         binary for clues.\n"
        "      2. Run again with AFL_DEBUG=1 and 'ulimit -c unlimited' and "
        "analyze the\n"
        "         generated core dump.\n\n"

        "    - Possibly the target requires a huge coverage map and has "
        "CTORS.\n"
        "      Retry with setting AFL_MAP_SIZE=10000000.\n\n"

        "    - The current memory limit (%s) is too restrictive, causing an "
        "OOM\n"
        "      fault in the dynamic linker. This can be fixed with the -m "
        "option. A\n"
        "      simple way to confirm the diagnosis may be:\n\n"

        MSG_ULIMIT_USAGE
        " /path/to/fuzzed_app )\n\n"

        "      Tip: you can use https://jwilk.net/software/recidivm to\n"
        "      estimate the required amount of virtual memory for the "
        "binary.\n\n"

        "    - The target was compiled with afl-clang-lto and a constructor "
        "was\n"
        "      instrumented, recompiling without AFL_LLVM_MAP_ADDR might solve "
        "your \n"
        "      problem\n\n"

        "    - Less likely, there is a horrible bug in the fuzzer. If other "
        "options\n"
        "      fail, poke the Awesome Fuzzing Discord for troubleshooting "
        "tips.\n",
        getenv(DEFER_ENV_VAR)
            ? "    - You are using deferred forkserver, but __AFL_INIT() is "
              "never\n"
              "      reached before the program terminates.\n\n"
            : "",
        stringify_int(val_buf, sizeof(val_buf), fsrv->mem_limit << 20),
        fsrv->mem_limit - 1);

  }

  FATAL("Fork server handshake failed");

}

/* Stop the forkserver and child */

void afl_fsrv_kill(afl_forkserver_t *fsrv) {

  if (fsrv->child_pid > 0) { kill(fsrv->child_pid, fsrv->child_kill_signal); }
  if (fsrv->fsrv_pid > 0) {

    kill(fsrv->fsrv_pid, fsrv->fsrv_kill_signal);
    waitpid(fsrv->fsrv_pid, NULL, 0);

  }

  close(fsrv->fsrv_ctl_fd);
  close(fsrv->fsrv_st_fd);
  fsrv->fsrv_pid = -1;
  fsrv->child_pid = -1;

#ifdef __linux__
  afl_nyx_runner_kill(fsrv);
#endif

}

/* Get the map size from the target forkserver */

u32 afl_fsrv_get_mapsize(afl_forkserver_t *fsrv, char **argv,
                         volatile u8 *stop_soon_p, u8 debug_child_output) {

  afl_fsrv_start(fsrv, argv, stop_soon_p, debug_child_output);
  return fsrv->map_size;

}

/* Delete the current testcase and write the buf to the testcase file */

void __attribute__((hot))
afl_fsrv_write_to_testcase(afl_forkserver_t *fsrv, u8 *buf, size_t len) {

#ifdef __linux__
  if (unlikely(fsrv->nyx_mode)) {

    fsrv->nyx_handlers->nyx_set_afl_input(fsrv->nyx_runner, buf, len);
    return;

  }

#endif

#ifdef AFL_PERSISTENT_RECORD
  if (unlikely(fsrv->persistent_record)) {

    fsrv->persistent_record_len[fsrv->persistent_record_idx] = len;
    fsrv->persistent_record_data[fsrv->persistent_record_idx] = afl_realloc(
        (void **)&fsrv->persistent_record_data[fsrv->persistent_record_idx],
        len);

    if (unlikely(!fsrv->persistent_record_data[fsrv->persistent_record_idx])) {

      FATAL("allocating replay memory failed.");

    }

    memcpy(fsrv->persistent_record_data[fsrv->persistent_record_idx], buf, len);

    if (unlikely(++fsrv->persistent_record_idx >= fsrv->persistent_record)) {

      fsrv->persistent_record_idx = 0;

    }

  }

#endif

  if (likely(fsrv->use_shmem_fuzz)) {

    if (unlikely(len > MAX_FILE)) len = MAX_FILE;


    *fsrv->shmem_fuzz_len = len;
    memcpy(fsrv->shmem_fuzz, buf, len);
#ifdef _DEBUG
    if (getenv("AFL_DEBUG")) {

      fprintf(stderr, "FS crc: %016llx len: %u\n",
              hash64(fsrv->shmem_fuzz, *fsrv->shmem_fuzz_len, HASH_CONST),
              *fsrv->shmem_fuzz_len);
      fprintf(stderr, "SHM :");
      for (u32 i = 0; i < *fsrv->shmem_fuzz_len; i++)
        fprintf(stderr, "%02x", fsrv->shmem_fuzz[i]);
      fprintf(stderr, "\nORIG:");
      for (u32 i = 0; i < *fsrv->shmem_fuzz_len; i++)
        fprintf(stderr, "%02x", buf[i]);
      fprintf(stderr, "\n");

    }

#endif

  } else {

    s32 fd = fsrv->out_fd;

    if (!fsrv->use_stdin && fsrv->out_file) {

      if (unlikely(fsrv->no_unlink)) {

        fd = open(fsrv->out_file, O_WRONLY | O_CREAT | O_TRUNC,
                  DEFAULT_PERMISSION);

      } else {

        unlink(fsrv->out_file);                           /* Ignore errors. */
        fd = open(fsrv->out_file, O_WRONLY | O_CREAT | O_EXCL,
                  DEFAULT_PERMISSION);

      }

      if (fd < 0) { PFATAL("Unable to create '%s'", fsrv->out_file); }

    } else if (unlikely(fd <= 0)) {

      // We should have a (non-stdin) fd at this point, else we got a problem.
      FATAL(
          "Nowhere to write output to (neither out_fd nor out_file set (fd is "
          "%d))",
          fd);

    } else {

      lseek(fd, 0, SEEK_SET);

    }

    // fprintf(stderr, "WRITE %d %u\n", fd, len);
    ck_write(fd, buf, len, fsrv->out_file);

    if (fsrv->use_stdin) {

      if (ftruncate(fd, len)) { PFATAL("ftruncate() failed"); }
      lseek(fd, 0, SEEK_SET);

    } else {

      close(fd);

    }

  }

}

// 0 not existing, 1 existing
u8 exist_pid(int pid) {
  if (pid == -1 || pid == 0) { return 0; }
  int killres = kill(pid, 0);
  int errnon = errno;
  if (killres == 0) {
    return 1;  // the process is existing and is child
  } else if (killres == -1) {
    if (errnon == ESRCH) {
      return 0;  // the process is not existing
    } else if (errnon == EPERM) {
      return 0;  // the process is existing but is not child
    } else {
      return 0;  // should not happen
    }
  }
  return 0;
}

// xzw add for ewma
double ewma(double prev_avg, double value, double alpha) {
  return alpha * value + (1 - alpha) * prev_avg;
}

u32 count_connections(afl_forkserver_t *fsrv, int protocol) {
  char  path[256];
  FILE *fp;
  u32   count = 0;
  char  buffer[1024];

  // 根据协议类型选择正确的文件路径
  if (protocol == 1) {
    snprintf(path, sizeof(path), "/proc/%d/net/udp", fsrv->child_pid);
  } else if (protocol == 0) {
    snprintf(path, sizeof(path), "/proc/%d/net/tcp", fsrv->child_pid);
  } else {
    fprintf(stderr, "Invalid protocol type. Use 1 for UDP, 0 for TCP.\n");
    return 0;
  }
  // 尝试打开文件
  fp = fopen(path, "r");
  if (fp == NULL) {
    // perror("Unable to open file");
    return 0;
  }

  if (fgets(buffer, sizeof(buffer), fp) == NULL) {
    fclose(fp);
    return -1;
  }

  while (fgets(buffer, sizeof(buffer), fp) != NULL) {
    if (strlen(buffer) > 0) { count++; }
  }

  fclose(fp);

  return count;  // 返回计数，不减1因为跳过了第一行标题
}

/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update afl->fsrv->trace_bits. */

u64 last_time = 0;
u8 *previous_trace_bits=NULL;
u32 ewma_avg = 0;

fsrv_run_result_t __attribute__((hot))
afl_fsrv_run_target(afl_forkserver_t *fsrv, u32 timeout,
                    volatile u8 *stop_soon_p) {

  s32 res;
  u32 exec_ms;
  u32 write_value = fsrv->last_run_timed_out;

  if (!last_time) { last_time = get_cur_time(); }

#ifdef __linux__
  if (fsrv->nyx_mode) {

    static uint32_t last_timeout_value = 0;

    if (last_timeout_value != timeout) {

      fsrv->nyx_handlers->nyx_option_set_timeout(
          fsrv->nyx_runner, timeout / 1000, (timeout % 1000) * 1000);
      fsrv->nyx_handlers->nyx_option_apply(fsrv->nyx_runner);
      last_timeout_value = timeout;

    }

    enum NyxReturnValue ret_val =
        fsrv->nyx_handlers->nyx_exec(fsrv->nyx_runner);

    fsrv->total_execs++;

    switch (ret_val) {

      case Normal:
        return FSRV_RUN_OK;
      case Crash:
      case Asan:
        return FSRV_RUN_CRASH;
      case Timeout:
        return FSRV_RUN_TMOUT;
      case InvalidWriteToPayload:
        /* ??? */
        FATAL("FixMe: Nyx InvalidWriteToPayload handler is missing");
        break;
      case Abort:
        FATAL("Error: Nyx abort occurred...");
      case IoError:
        if (*stop_soon_p) {

          return 0;

        } else {

          FATAL("Error: QEMU-Nyx has died...");

        }

        break;
      case Error:
        FATAL("Error: Nyx runtime error has occurred...");
        break;

    }

    return FSRV_RUN_OK;

  }

#endif
  /* After this memset, fsrv->trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

#ifdef __linux__
  if (!fsrv->nyx_mode) {

    memset(fsrv->trace_bits, 0, fsrv->map_size);
    MEM_BARRIER();

  }

#else
  memset(fsrv->trace_bits, 0, fsrv->map_size);
  MEM_BARRIER();
#endif


  u8 need_new_prog = 0;
  u8 is_new_start = 0;
  u8 exp_send = 0;

  

    if (fsrv->exp_signal) {
    u64 cur_time = get_cur_time();

    if (cur_time - last_time >= fsrv->exp_t_interval) {
      last_time = cur_time;
      exp_send = 1;
    }

       if (exp_send) {
      LOG("exp send signal\n");
      int sig=0;

      if (fsrv->exp_signal == 1) {
        sig = SIGUSR1;
      } else if (fsrv->exp_signal == 2) {
        sig = SIGRTMIN;
      } else {
        RPFATAL(fsrv->exp_signal,"Wrong set environment variable?");
      }
      s32 tmp_pid1 = fsrv->child_pid;
      if (tmp_pid1 > 0) { kill(tmp_pid1, sig); }

      exp_send = 0;
    }
  }

  // First check whether we need to fork new child process
  if (fsrv->use_net) {  
    if (!exist_pid(fsrv->child_pid)) { 
        need_new_prog = 1; 
    }
  }

  if (!fsrv->use_net || (fsrv->use_net && need_new_prog)) 
  {  // In nethook, we only need to fork server sometimes 

    /* we have the fork server (or faux server) up and running
    First, tell it if the previous run timed out. */

    if ((res = write(fsrv->fsrv_ctl_fd, &write_value, 4)) != 4) {
      if (*stop_soon_p) { return 0; }
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");
    }

    fsrv->last_run_timed_out = 0;

    if ((res = read(fsrv->fsrv_st_fd, &fsrv->child_pid, 4)) != 4) {
      if (*stop_soon_p) { return 0; }
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");
    }

    is_new_start = 1;
    fsrv->keep_timeout_times = 0;
    fsrv->keep_badconn_times = 0;
  }

#ifdef AFL_PERSISTENT_RECORD
  // end of persistent loop?
  if (unlikely(fsrv->persistent_record &&
               fsrv->persistent_record_pid != fsrv->child_pid)) {

    fsrv->persistent_record_pid = fsrv->child_pid;
    u32 idx, val;
    if (unlikely(!fsrv->persistent_record_idx))
      idx = fsrv->persistent_record - 1;
    else
      idx = fsrv->persistent_record_idx - 1;
    val = fsrv->persistent_record_len[idx];
    memset((void *)fsrv->persistent_record_len, 0,
           fsrv->persistent_record * sizeof(u32));
    fsrv->persistent_record_len[idx] = val;

  }

#endif

  if (fsrv->child_pid <= 0) {

    if (*stop_soon_p) { return 0; }

    if ((fsrv->child_pid & FS_OPT_ERROR) &&
        FS_OPT_GET_ERROR(fsrv->child_pid) == FS_ERROR_SHM_OPEN)
      FATAL(
          "Target reported shared memory access failed (perhaps increase "
          "shared memory available).");

    FATAL("Fork server is misbehaving (OOM?)");

  }

  if (!fsrv->use_net) 
  {
    exec_ms = read_s32_timed(fsrv->fsrv_st_fd, &fsrv->child_status, timeout,
                             stop_soon_p);

    if (exec_ms > timeout) {
      /* If there was no response from forkserver after timeout seconds,
      we kill the child. The forkserver should inform us afterwards */

      s32 tmp_pid = fsrv->child_pid;
      if (tmp_pid > 0) {
        kill(tmp_pid, fsrv->child_kill_signal);
        fsrv->child_pid = -1;
      }

      fsrv->last_run_timed_out = 1;
      if (read(fsrv->fsrv_st_fd, &fsrv->child_status, 4) < 4) { exec_ms = 0; }
    }

    if (!exec_ms) {
      if (*stop_soon_p) { return 0; }
      SAYF("\n" cLRD "[-] " cRST
           "Unable to communicate with fork server. Some possible reasons:\n\n"
           "    - You've run out of memory. Use -m to increase the the memory "
           "limit\n"
           "      to something higher than %llu.\n"
           "    - The binary or one of the libraries it uses manages to "
           "create\n"
           "      threads before the forkserver initializes.\n"
           "    - The binary, at least in some circumstances, exits in a way "
           "that\n"
           "      also kills the parent process - raise() could be the "
           "culprit.\n"
           "    - If using persistent mode with QEMU, "
           "AFL_QEMU_PERSISTENT_ADDR "
           "is\n"
           "      probably not valid (hint: add the base address in case of "
           "PIE)"
           "\n\n"
           "If all else fails you can disable the fork server via "
           "AFL_NO_FORKSRV=1.\n",
           fsrv->mem_limit);
      RPFATAL(res, "Unable to communicate with fork server");
    }

    if (!WIFSTOPPED(fsrv->child_status)) { fsrv->child_pid = -1; }

    fsrv->total_execs++;

    /* Any subsequent operations on fsrv->trace_bits must not be moved by the
       compiler below this point. Past this location, fsrv->trace_bits[]
       behave very normally and do not have to be treated as volatile. */

    MEM_BARRIER();

    /* Report outcome to caller. */

    /* Was the run unsuccessful? */
    if (unlikely(*(u32 *)fsrv->trace_bits == EXEC_FAIL_SIG)) {
      return FSRV_RUN_ERROR;
    }

    /* Did we timeout? */
    if (unlikely(fsrv->last_run_timed_out)) {
      fsrv->last_kill_signal = fsrv->child_kill_signal;
      return FSRV_RUN_TMOUT;
    }

    /* Did we crash?
    In a normal case, (abort) WIFSIGNALED(child_status) will be set.
    MSAN in uses_asan mode uses a special exit code as it doesn't support
    abort_on_error. On top, a user may specify a custom AFL_CRASH_EXITCODE.
    Handle all three cases here. */

    if (unlikely(
            /* A normal crash/abort */
            (WIFSIGNALED(fsrv->child_status)) ||
            /* special handling for msan and lsan */
            (fsrv->uses_asan &&
             (WEXITSTATUS(fsrv->child_status) == MSAN_ERROR ||
              WEXITSTATUS(fsrv->child_status) == LSAN_ERROR)) ||
            /* the custom crash_exitcode was returned by the target */
            (fsrv->uses_crash_exitcode &&
             WEXITSTATUS(fsrv->child_status) == fsrv->crash_exitcode))) {
#ifdef AFL_PERSISTENT_RECORD
      if (unlikely(fsrv->persistent_record)) {
        char fn[PATH_MAX];
        u32  i, writecnt = 0;
        for (i = 0; i < fsrv->persistent_record; ++i) {
          u32 entry =
              (i + fsrv->persistent_record_idx) % fsrv->persistent_record;
          u8 *data = fsrv->persistent_record_data[entry];
          u32 len = fsrv->persistent_record_len[entry];
          if (likely(len && data)) {
            snprintf(fn, sizeof(fn), "%s/RECORD:%06u,cnt:%06u",
                     fsrv->persistent_record_dir, fsrv->persistent_record_cnt,
                     writecnt++);
            int fd = open(fn, O_CREAT | O_TRUNC | O_WRONLY, 0644);
            if (fd >= 0) {
              ck_write(fd, data, len, fn);
              close(fd);
            }
          }
        }

        ++fsrv->persistent_record_cnt;
      }

#endif

      /* For a proper crash, set last_kill_signal to WTERMSIG, else set it to 0
       */
      fsrv->last_kill_signal =
          WIFSIGNALED(fsrv->child_status) ? WTERMSIG(fsrv->child_status) : 0;
      return FSRV_RUN_CRASH;
    }
  } 
  else  // nethook logic
  {
    fsrv_run_result_t finalres = FSRV_RUN_OK;

    u32 command = NETHOOK_CMD_SEED_READY;
    u8  is_new_conn = 0;
    if (fsrv->need_new_conn || fsrv->no_connection_reuse)
    { 
      command = NETHOOK_CMD_SEED_READY_NEWCON;
      is_new_conn = 1;
      fsrv->need_new_conn = 0;
      fsrv->keep_timeout_times = 0;
      //printf("send newcon command once\n");
    }

    //ACTF("Fuzz write len: %u\n\n", *(unsigned int*)fsrv->shmem_fuzz_len);

    if ((res = write(fsrv->hook_ctl_fd, &command, 4)) != 4) {
      if (*stop_soon_p) { return 0; }
      RPFATAL(res, "Unable to tell server seed ready");
    }

    // LOG("Send command %d\n", command);

    u32 result = 0;
    u32 used_timeout =
        timeout + (is_new_start ? fsrv->new_start_tmout : 0) +
        (is_new_conn ? fsrv->new_conn_tmout : 0) +
        fsrv->new_conn_tmout;  // 增加一次fsrv->new_conn_tmout因为可能hook端发现close会自动重连

    exec_ms =
        read_s32_timed(fsrv->hook_st_fd, &result, used_timeout, stop_soon_p);

    u8 need_kill = 0;

    /* xzw add no conn reuse means kill the PUT after every exec */
    if (fsrv->forced_kill) {
        need_kill = 1;
        fsrv->total_execs++;
        return finalres ;
    }

    if (fsrv->no_connection_reuse) { 
        fsrv->need_new_conn = 1; 
        fsrv->total_execs++;
        return finalres;
    }

    u8 is_simple_timeout = (result == NETHOOK_CMD_TIME_OUT);

    if (exec_ms > timeout && !need_kill) 
    {
      // 如果超时，有几种可能，如子进程已经退出，或者处理此次种子确实太慢

      if (!exist_pid(fsrv->child_pid)) 
      {     // 如果是因为子进程退出，则需要把fsrv_st_fd上的返回值读走

        if (read(fsrv->fsrv_st_fd, &fsrv->child_status, 4) < 4) { exec_ms = 0; }
        fsrv->child_pid = -1;
        finalres = FSRV_RUN_CRASH;
      } 
      else  // 如果子进程还在、只是超时，则进行一些记录
      {  
         is_simple_timeout = 1;
      }
    }

    if (is_simple_timeout && !need_kill) {
      fsrv->keep_timeout_times++;
      LOG("fsrv->keep_timeout_times=%d, fsrv->keep_badconn_times=%d\n",
          fsrv->keep_timeout_times, fsrv->keep_badconn_times);
      if (fsrv->keep_timeout_times > fsrv->timeout_times_threh) {
        // 本连接处理input超时过多，则需要重连
         if (fsrv->no_multi_connection) {
             need_kill=1;
         } else {
             fsrv->need_new_conn = 1;
             fsrv->keep_badconn_times++;
             if (fsrv->keep_badconn_times >
                 fsrv->badconn_times_threh) {  // 持续每个连接都超时，则需要重新启动子进程
            need_kill = 1;
             }
         }
        }
       
    finalres = FSRV_RUN_TMOUT;
    }


    // emwa logic
    if (fsrv->ewma_enabled) {
    if (!previous_trace_bits) {
         previous_trace_bits = (u8 *)ck_alloc(fsrv->map_size);

         ewma_avg = count_diff_bits(fsrv, previous_trace_bits);

         memcpy(previous_trace_bits, fsrv->trace_bits, fsrv->map_size);

    } else {
         u32 diff_bits_count = count_diff_bits(fsrv, previous_trace_bits);

         memcpy(previous_trace_bits, fsrv->trace_bits, fsrv->map_size);

         ewma_avg = ewma(ewma_avg, diff_bits_count, 0.1);

         if (fsrv->debug) printf("ewma_avg=%u\n", ewma_avg);

         if (fsrv->need_new_conn || need_kill) {
             // 如果上层已经处理给ewma奖励
             ewma_avg = 5;
         } else if (ewma_avg == 0) {
             // 先尝试断开连接
             if (!fsrv->need_new_conn && !fsrv->no_multi_connection) {
            fsrv->need_new_conn = 1;
            ewma_avg = 5;
             } else {  // 杀进程
            need_kill = 1;
            ewma_avg = 5;
             }
         }
    }
    }
    if (*stop_soon_p) { return 0;  }

    if (!exec_ms &&!is_simple_timeout &&!need_kill ) {
      RPFATAL(res, "Unable to communicate with fork server (nethook)");
    }

    if (exec_ms <= timeout || need_kill) 
    {  // 正常情况
      fsrv->keep_timeout_times = 0;
      fsrv->keep_badconn_times = 0;
    }

    fsrv->total_execs++;

    MEM_BARRIER();


    /* Was the run unsuccessful? */
    if (unlikely(*(u32 *)fsrv->trace_bits == EXEC_FAIL_SIG)) {
        finalres = FSRV_RUN_ERROR;
    }


    // 如果需要kill，执行
    if (need_kill) 
    {

        LOG("kill once\n");
        fsrv->need_new_conn = 1;
        s32 tmp_pid = fsrv->child_pid;
        if (tmp_pid > 0) {
         
        kill(tmp_pid, fsrv->child_kill_signal);
        fsrv->child_pid = -1;

        }

        fsrv->last_run_timed_out = 1;
        if (read(fsrv->fsrv_st_fd, &fsrv->child_status, 4) < 4) { exec_ms = 0; }
    }

    return finalres;

  }

  /* success :) */
  return FSRV_RUN_OK;

}

void afl_fsrv_killall() {

  LIST_FOREACH(&fsrv_list, afl_forkserver_t, {

    afl_fsrv_kill(el);

  });

}

void afl_fsrv_deinit(afl_forkserver_t *fsrv) {

  afl_fsrv_kill(fsrv);
  list_remove(&fsrv_list, fsrv);

}

/*xzw add for emwa, We use the XOR result of current trace and previous trace
as the input value of EWMA to determine the status of the server ,if the XOR
results keeps low the status of the server is abnormal
*/

/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast. ftom afl-fuzz-bitmap.c */
const u8 simplify_lookup1[256] = {

    [0] = 1, [1 ... 255] = 128

};

u32 my_count_non_255_bytes(afl_forkserver_t *fsrv) {
  u32 *ptr = (u64 *)fsrv->trace_bits;
  u32  i = ((fsrv->real_map_size + 3) >> 2);
  u32  ret = 0;

  while (i--) {
    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (likely(v == 0xffffffffU)) { continue; }
    if ((v & 0x000000ffU) != 0x000000ffU) { ++ret; }
    if ((v & 0x0000ff00U) != 0x0000ff00U) { ++ret; }
    if ((v & 0x00ff0000U) != 0x00ff0000U) { ++ret; }
    if ((v & 0xff000000U) != 0xff000000U) { ++ret; }
  }

  return ret;
}

inline u32 count_diff_bits(afl_forkserver_t *fsrv, u8 *previous_map) {
#ifdef WORD_SIZE_64

  u64 *current = (u64 *)fsrv->trace_bits;
  u64 *previous = (u64 *)previous_map;

  u32 i = ((fsrv->real_map_size + 7) >> 3);  // map_size / 8 for 64-bit

#else

  u32 *current = (u32 *)fsrv->trace_bits;
  u32 *previous = (u32 *)previous_map;

  u32 i = ((fsrv->real_map_size + 3) >> 2);  // map_size / 4 for 32-bit

#endif /* ^WORD_SIZE_64 */

  u32 different_bits_count = 0;

   while (i--) {
    u64 cur_word = *(current++);
    u64 prev_word = *(previous++);

    // Process each byte within the word and compare after simplification
    for (u32 j = 0; j < sizeof(u64); j++) {
        u8 cur_byte = (cur_word >> (j * 8)) & 0xFF;
        u8 prev_byte = (prev_word >> (j * 8)) & 0xFF;

        u8 simplified_current = simplify_lookup1[cur_byte];
        u8 simplified_previous = simplify_lookup1[prev_byte];

        u8 xor_result = simplified_current ^ simplified_previous;

        // if there is a difference
        if (xor_result) { different_bits_count++; }
    }
  }

  return different_bits_count;
}

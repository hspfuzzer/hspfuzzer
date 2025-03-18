# HSPFuzzer

HSPFuzzer(High-Speed network Protocol Fuzzer) implements high-speed network protocol fuzzing by **connection resue** , achieving a 1062x speed increase compared to [aflnet](https://github.com/aflnet/aflnet)

HSPFuzzer is developed based on [AFLplusplus](https://github.com/AFLplusplus/AFLplusplus) version [v4.09c](https://github.com/AFLplusplus/AFLplusplus/tree/v4.09c)

## BUILD

#### Building and installing HSPFuzzer

llvm is needed for  AFLplusplus

```bash
git clone https://github.com/hspfuzzer/hspfuzzer.git
cd hspfuzzer
make clean all
```

Compile the hook part of HSPFuzzer, `libpthread` is needed.

```bash
clang -shared -fPIC shm_hook.c -o shm_hook.so -ldl -lpthread -g
```

After that you have `afl-fuzz` and `shm_hook.so` in your current directory

HSPFuzzer uses `afl-clang-fast/afl-clang-fast++` for instrumentation, so use 

```bash
CC=/path/to/afl-clang-fast CXX=/path/to/afl-clang-fast++
```

when compiling fuzz target (`afl-clang/afl-gcc` will also work, but performs much worse)

## USAGE

the use of HSPFuzzer is similar to [desock(preeny)](https://github.com/zardus/preeny)

```bash
-H <protocol>:<port>
```

**protocol**: Indicates the protocol type:

`0` for **TCP**

`1` for **UDP**

**port**: Specifies the port number.

#### Environment variables

HSPFuzzer adapts connection multiplexing to maximize the fuzzing speed, but you can also choose to disable/enable certain features.

`AFL_EWMA_ENABLED=1 (default 0)`This will enable EWMA mode, which may improve fuzz performance on some programs.

`AFL_FORCED_KILL=1 (default 0) ` This will cause HSPFuzzer to kill the program after each fuzz, just like aflnet does.

`AFL_NO_CONNECTION_REUSE=1 (default 0) ` This will prevent HSPFuzzer from reusing connections.

`AFL_NO_MULTI_CONN=1 (default 0) ` This will cause HSPFuzzer to not try to reconnect when a connection error occurs (HSPFuzzer allows connection errors and attempts to reconnect) but instead kill the program directly.

#### Start fuzz:

```bash
AFL_PRELOAD=/path/to/shm_hook.so ./afl-fuzz -H <protocol>:<port>\
-i seeds_dir -o output_dir -- /path/to/tested/program [...program's cmdline...]
```

## DEBUG

If you have problems with HSPFuzzer,we recommend  start the fuzzer with `AFL_DEBUG=1`, set `DEBUG_MODE=1` and recompile [shm_hook.c](https://github.com/hspfuzzer/hspfuzzer/blob/main/shm_hook.c#L39), which will print the output of the fuzzer and the program under test, or try `old_shom_hook.c` which is considered a more compatible version.

You can submit an issue if you encounter any problems and we will do our best to help you :)


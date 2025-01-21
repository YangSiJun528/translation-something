이 자료는 [CMCDragonkai](https://github.com/CMCDragonkai)아 [gist에 작성한 문서](https://gist.github.com/CMCDragonkai/10ab53654b2aa6ce55c11cfc5b2432a4)을 한국어로 번역한 문서입니다.

claude 3.5 sonnet을 사용하여 변역하였습니다.

---

# Linux 실행 파일의 메모리 레이아웃 이해하기

메모리를 다루기 위해 필요한 도구들:

* `hexdump`
* `objdump`
* `readelf`
* `xxd`
* `gcore`
* `strace`
* `diff`
* `cat`

> 번역자 추가 설명
> * [`hexdump`](https://man7.org/linux/man-pages/man1/hexdump.1.html): 파일이나 표준 입력을 16진수(헥사) 형식으로 덤프 출력하는 도구입니다. 바이너리 파일의 내용을 확인하거나 디버깅할 때 유용합니다.
> * [`objdump`](https://man7.org/linux/man-pages/man1/objdump.1.html): 오브젝트 파일의 세부 정보를 출력하는 도구로, 실행 파일, 라이브러리, 또는 디버그 정보를 확인할 수 있습니다. 섹션, 기계어 코드, 디스어셈블 등을 확인할 때 사용됩니다.
> * [`readelf`](https://man7.org/linux/man-pages/man1/readelf.1.html): ELF(Executable and Linkable Format) 파일의 정보를 출력하는 도구입니다. 헤더, 심볼 테이블, 섹션 정보 등 ELF 형식의 세부 정보를 분석할 수 있습니다.
> * [`xxd`](https://linux.die.net/man/1/xxd): 파일의 내용을 헥사 및 ASCII 형식으로 변환하거나 반대로 헥사 형식의 내용을 바이너리로 변환하는 도구입니다. 주로 데이터 변환과 분석에 사용됩니다.
> * [`gcore`](https://man7.org/linux/man-pages/man1/gcore.1.html): 실행 중인 프로세스의 메모리 상태를 코어 덤프 파일로 저장하는 도구입니다. 디버깅이나 오류 분석을 위해 사용됩니다.
> * [`strace`](https://man7.org/linux/man-pages/man1/strace.1.html): 실행 중인 프로세스가 호출하는 시스템 호출(syscall)과 해당 호출의 결과를 추적하는 디버깅 도구입니다. 프로세스와 커널 간의 상호작용을 분석할 때 유용합니다.
> * [`diff`](https://man7.org/linux/man-pages/man1/diff.1.html): 두 파일의 차이점을 비교하고 이를 라인 단위로 출력하는 도구입니다. 소스 코드 변경점 비교 등에 자주 사용됩니다.
> * [`cat`](https://man7.org/linux/man-pages/man1/cat.1.html): 파일의 내용을 출력하거나, 여러 파일을 하나로 연결하여 출력하는 간단하고 강력한 도구입니다.

우리는 다음 링크들의 내용을 살펴볼 것입니다: https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/ 와 http://duartes.org/gustavo/blog/post/anatomy-of-a-program-in-memory/

실제로 여러 C 메모리 할당자들이 있습니다. 
그리고 각각의 메모리 할당자들은 메모리를 다른 방식으로 배치합니다. 현재 glibc의 메모리 할당자는 `ptmalloc2`입니다. 이는 dlmalloc에서 분기되었습니다. 분기 후 스레딩 지원이 추가되었고, 2006년에 릴리스되었습니다. glibc에 통합된 후에는 glibc의 malloc 소스 코드에 직접적인 코드 변경이 이루어졌습니다. 따라서 glibc의 malloc에는 원래의 `ptmalloc2`와는 다른 많은 변화가 있습니다.

glibc의 malloc은 내부적으로 OS로부터 메모리를 획득하기 위해 `brk` 또는 `mmap` 시스템 콜을 호출합니다. `brk` 시스템 콜은 일반적으로 힙의 크기를 늘리는 데 사용되며, `mmap`은 공유 라이브러리를 로드하고, 스레드를 위한 새로운 영역을 생성하는 등 여러 용도로 사용됩니다. 실제로 요청된 메모리의 크기가 `MMAP_THRESHOLD`보다 큰 경우 `brk` 대신 `mmap`을 사용합니다. `strace`를 사용하여 어떤 호출이 이루어지는지 확인할 수 있습니다.

예전 `dlmalloc`을 사용할 때는 2개의 스레드가 동시에 malloc을 호출하면 하나의 스레드만 임계 영역에 들어갈 수 있었고, 메모리 청크의 freelist 데이터 구조가 모든 가용 스레드 간에 공유되었습니다. 따라서 메모리 할당은 전역 잠금 작업이었습니다.

하지만 ptmalloc2에서는 2개의 스레드가 동시에 malloc을 호출하면, 각 스레드가 별도의 힙과 자체 freelist 청크 데이터 구조를 유지하기 때문에 메모리가 즉시 할당됩니다.

각 스레드에 대해 별도의 힙과 freelist를 유지하는 이러한 행위를 "per-thread arena"라고 합니다.

지난 세션에서는 프로그램의 메모리 레이아웃이 일반적으로 다음과 같다는 것을 확인했습니다:

```
User Stack
    |
    v
Memory Mapped Region for Shared Libraries or Anything Else
    ^
    |
Heap
Uninitialised Data (.bss)
Initialised Data (.data)
Program Text (.text)
0
```

이해를 돕기 위해, 메모리를 조사하는 대부분의 도구들은 낮은 주소를 상단에 두고 높은 주소를 하단에 둡니다.

따라서 다음과 같이 생각하는 것이 더 쉽습니다:

```
0
Program Text (.text)
Initialised Data (.data)
Uninitialised Data (.bss)
Heap
    |
    v
Memory Mapped Region for Shared Libraries or Anything Else
    ^
    |
User Stack
```

문제는 우리가 정확히 무슨 일이 일어나는지 제대로 파악하지 못했다는 것입니다. 그리고 위의 다이어그램은 완전히 이해하기에는 너무 단순합니다.

C 프로그램을 몇 개 작성하고 그들의 메모리 구조를 조사해봅시다.

> 직접적인 컴파일이나 어셈블리는 실제로 실행 파일을 생성하지 않습니다. 그것은 링커가 수행하는데, 링커는 컴파일/어셈블리로 생성된 다양한 오브젝트 코드 파일들을 가져와서, 그들이 포함하고 있는 모든 이름을 해결하고 최종 실행 바이너리를 생성합니다.
> http://stackoverflow.com/a/845365/582917

다음은 우리의 첫 번째 프로그램입니다 (`gcc -pthread memory_layout.c -o memory_layout`로 컴파일):

```c
#include <stdio.h> // standard io
#include <stdlib.h> // C standard library
#include <pthread.h> // threading
#include <unistd.h> // unix standard library
#include <sys/types.h> // system types for linux

// getchar basically is like "read"
// it prompts the user for input
// in this case, the input is thrown away
// which makes similar to a "pause" continuation primitive 
// but a pause that is resolved through user input, which we promptly throw away!
void * thread_func (void * arg) {

    printf("Before malloc in thread 1\n");
    getchar();
    char * addr = (char *) malloc(1000);
    printf("After malloc and before free in thread 1\n");
    getchar();
    free(addr);
    printf("After free in thread 1\n");
    getchar();

}

int main () {

    char * addr;
    printf("Welcome to per thread arena example::%d\n", getpid());
    printf("Before malloc in the main thread\n");
    getchar();
    addr = (char *) malloc(1000);
    printf("After malloc and before free in main thread\n");
    getchar();
    free(addr);
    printf("After free in main thread\n");
    getchar();

    // pointer to the thread 1
    pthread_t thread_1;
    // pthread_* functions return 0 upon succeeding, and other numbers upon failing
    int pthread_status;

    pthread_status = pthread_create(&thread_1, NULL, thread_func, NULL);
    
    if (pthread_status != 0) {
        printf("Thread creation error\n");
        return -1;
    }

    // returned status code from thread_1
    void * thread_1_status;

    pthread_status = pthread_join(thread_1, &thread_1_status);
    
    if (pthread_status != 0) {
        printf("Thread join error\n");
        return -1;
    }

    return 0;

}
```



위의 `getchar` 사용은 기본적으로 계산을 일시 중지하고 사용자 입력을 기다리기 위한 것입니다. 이는 메모리 레이아웃을 검사할 때 프로그램을 단계별로 실행할 수 있게 해줍니다.

`pthread`의 사용은 POSIX 스레드를 생성하기 위한 것으로, 이는 Linux OS에서 스케줄링되는 실제 커널 스레드입니다. 흥미로운 점은 스레드 사용이 프로세스 메모리 레이아웃이 여러 스레드에 대해 어떻게 활용되는지 검사하는 데 유용하다는 것입니다. 각 스레드는 자체 힙과 스택이 필요하다는 것이 밝혀졌습니다.

`pthread` 함수들은 성공 시 0 기반의 상태 코드를 반환하기 때문에 다소 특이합니다. 이는 `pthread` 작업의 성공을 나타내며, 이는 기본 운영 체제에서 부작용을 수반합니다.

위에서 볼 수 있듯이, 참조 오류 패턴이 많이 사용되고 있습니다. 즉, 여러 값을 반환하는 대신(튜플을 통해), 우리는 참조 컨테이너를 사용하여 추가 메타데이터나 단순히 데이터 자체를 저장합니다.

이제 프로그램을 실행할 수 있습니다 `./memory_layout` (`Ctrl + Z`를 사용하여 프로그램을 일시 중단해보세요):

```
$ ./memory_layout
Welcome to per thread arena example::1255
Before malloc in the main thread
```

이 시점에서 프로그램이 일시 중지되었으므로, `/proc/1255/maps`를 살펴봄으로써 메모리 내용을 검사할 수 있습니다. 이는 커널이 제공하는 가상 파일로, 프로그램의 정확한 메모리 레이아웃을 보여줍니다. 실제로 각 메모리 섹션을 요약하므로, 특정 바이트 주소를 볼 수 있는 기능 없이도 메모리가 어떻게 배치되어 있는지 이해하는 데 유용합니다.

```
$ cat /proc/1255/maps # you can also use `watch -d cat /proc/1255/maps` to get updates
00400000-00401000 r-xp 00000000 fc:00 1457150                            /home/vagrant/c_tests/memory_layout
00600000-00601000 r--p 00000000 fc:00 1457150                            /home/vagrant/c_tests/memory_layout
00601000-00602000 rw-p 00001000 fc:00 1457150                            /home/vagrant/c_tests/memory_layout
7f849c31b000-7f849c4d6000 r-xp 00000000 fc:00 1579071                    /lib/x86_64-linux-gnu/libc-2.19.so
7f849c4d6000-7f849c6d6000 ---p 001bb000 fc:00 1579071                    /lib/x86_64-linux-gnu/libc-2.19.so
7f849c6d6000-7f849c6da000 r--p 001bb000 fc:00 1579071                    /lib/x86_64-linux-gnu/libc-2.19.so
7f849c6da000-7f849c6dc000 rw-p 001bf000 fc:00 1579071                    /lib/x86_64-linux-gnu/libc-2.19.so
7f849c6dc000-7f849c6e1000 rw-p 00000000 00:00 0
7f849c6e1000-7f849c6fa000 r-xp 00000000 fc:00 1579084                    /lib/x86_64-linux-gnu/libpthread-2.19.so
7f849c6fa000-7f849c8f9000 ---p 00019000 fc:00 1579084                    /lib/x86_64-linux-gnu/libpthread-2.19.so
7f849c8f9000-7f849c8fa000 r--p 00018000 fc:00 1579084                    /lib/x86_64-linux-gnu/libpthread-2.19.so
7f849c8fa000-7f849c8fb000 rw-p 00019000 fc:00 1579084                    /lib/x86_64-linux-gnu/libpthread-2.19.so
7f849c8fb000-7f849c8ff000 rw-p 00000000 00:00 0
7f849c8ff000-7f849c922000 r-xp 00000000 fc:00 1579072                    /lib/x86_64-linux-gnu/ld-2.19.so
7f849cb10000-7f849cb13000 rw-p 00000000 00:00 0
7f849cb1d000-7f849cb21000 rw-p 00000000 00:00 0
7f849cb21000-7f849cb22000 r--p 00022000 fc:00 1579072                    /lib/x86_64-linux-gnu/ld-2.19.so
7f849cb22000-7f849cb23000 rw-p 00023000 fc:00 1579072                    /lib/x86_64-linux-gnu/ld-2.19.so
7f849cb23000-7f849cb24000 rw-p 00000000 00:00 0
7fffb5d61000-7fffb5d82000 rw-p 00000000 00:00 0                          [stack]
7fffb5dfe000-7fffb5e00000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```



/proc/$PID/maps의 각 행은 프로세스의 주소 공간에서 연속된 가상 메모리 영역을 설명합니다. 각 행은 다음과 같은 필드를 가집니다:

* address - 해당 영역의 프로세스 주소 공간에서의 시작 및 끝 주소
* perms - 페이지에 어떻게 접근할 수 있는지를 설명하는 `rwxp` 또는 `rwxs`이며, 여기서 `s`는 private 또는 shared 페이지를 의미합니다. 프로세스가 허용되지 않은 메모리에 접근하려고 하면 segmentation fault가 발생합니다.
* offset - 해당 영역이 `mmap`을 사용하여 파일에서 매핑된 경우, 매핑이 시작되는 파일에서의 오프셋입니다
* dev - 해당 영역이 파일에서 매핑된 경우, 파일이 위치한 16진수로 표현된 주 장치 번호와 부 장치 번호입니다. 주 번호는 장치 드라이버를 가리키고, 부 번호는 장치 드라이버에 의해 해석되거나, 장치 드라이버의 특정 장치를 나타냅니다(예: 여러 개의 플로피 드라이브)
* inode - 해당 영역이 파일에서 매핑된 경우, 파일 번호입니다
* pathname - 해당 영역이 파일에서 매핑된 경우, 파일의 이름입니다. [heap], [stack], [vdso]와 같은 특별한 이름을 가진 영역이 있습니다. [vdso]는 virtual dynamic shared object의 약자로, 커널 모드로 전환하기 위해 시스템 콜에서 사용됩니다

일부 영역은 pathname 필드에 파일 경로나 특별한 이름이 없습니다. 이러한 영역들은 익명 영역입니다. 익명 영역은 mmap에 의해 생성되지만 어떤 파일에도 연결되어 있지 않으며, 공유 메모리, 힙에 없는 버퍼 등 여러 가지 용도로 사용되고, pthread 라이브러리는 새로운 스레드의 스택으로 익명 매핑된 영역을 사용합니다.

연속된 가상 메모리가 반드시 연속된 물리적 메모리를 의미하지는 않습니다. 이를 위해서는 가상 메모리 시스템이 없는 OS를 사용해야 합니다. 하지만 연속된 가상 메모리가 연속된 물리적 메모리와 같을 가능성이 높으며, 적어도 포인터를 추적할 필요는 없습니다. 하드웨어 수준에서도 가상 메모리에서 물리적 메모리로의 변환을 위한 특별한 장치가 있습니다. 그래서 여전히 매우 빠릅니다.

여기서 `bc` 도구를 사용하는 것이 매우 중요한데, 16진수와 10진수 간의 변환이 자주 필요하기 때문입니다. 다음과 같이 사용할 수 있습니다: `bc <<< 'obase=10; ibase=16; 4010000 - 4000000'`, 이는 본질적으로 16진수를 사용하여 `4010000 - 4000000` 뺄셈을 수행한 다음 그 결과를 10진수로 변환합니다.



주 부 번호에 대해 부가적인 설명을 하자면, `ls -l /dev | grep 252` 또는 `lsblk | grep 252`를 사용하여 `major:minor` 번호에 해당하는 장치를 찾아볼 수 있습니다. 여기서 `0d252 ~ 0xfc`입니다.

Linux 장치 드라이버의 모든 주 부 번호 할당은 다음에서 확인할 수 있습니다: http://www.lanana.org/docs/device-list/devices-2.6+.txt

이는 또한 240 - 254 사이가 로컬/실험적 사용을 위한 것임을 보여줍니다. 또한 232 - 239는 할당되지 않았으며, 255는 예약되어 있습니다. 우리는 해당 장치가 device mapper 장치라는 것을 확인할 수 있습니다. 따라서 로컬/실험적 사용을 위해 예약된 범위를 사용하고 있습니다. 주 부 번호는 255까지만 가능한데, 이는 단일 바이트에서 가능한 가장 큰 10진수이기 때문입니다. 단일 바이트는 `0b11111111` 또는 `0xFF`입니다. 단일 16진수 숫자는 니블입니다. 2개의 16진수 숫자가 바이트입니다.

가장 먼저 주목할 점은 메모리 주소가 낮은 것에서 높은 것으로 시작하지만, 이 프로그램을 실행할 때마다 많은 영역의 주소가 다르다는 것입니다. 이는 일부 영역의 경우 주소가 정적으로 할당되지 않는다는 것을 의미합니다. 이는 실제로 보안 기능 때문인데, 특정 영역의 주소 공간을 무작위화함으로써 공격자가 관심 있는 특정 메모리 조각을 획득하기 어렵게 만듭니다. 하지만 프로그램을 로드하는 방법을 알 수 있도록 고정되어야 하는 영역도 있습니다. 우리는 프로그램 데이터와 실행 가능한 메모리가 `vsyscall`과 함께 항상 고정되어 있는 것을 볼 수 있습니다. "PIE"(position independent executable)라고 하는 것을 만들어 프로그램 데이터와 실행 가능한 메모리도 무작위화하는 것이 실제로 가능하지만, 이는 기본적으로 활성화되어 있지 않으며, 또한 프로그램이 정적으로 컴파일되는 것을 방지하여 반드시 링크되어야 합니다 (https://sourceware.org/ml/binutils/2012-02/msg00249.html). 또한 "PIE" 실행 파일은 일부 성능 문제를 발생시킵니다(32비트와 64비트 컴퓨터에서 서로 다른 종류의 문제). 일부 영역의 주소 무작위화는 "PIC"(position independent code)라고 하며, Linux에서 꽤 오랫동안 기본적으로 활성화되어 있었습니다. 자세한 정보는 다음을 참조하세요: http://blog.fpmurphy.com/2008/06/position-independent-executables.html 및 http://eli.thegreenplace.net/2011/08/25/load-time-relocation-of-shared-libraries



위의 프로그램을 `gcc -fPIE -pie ./hello.c -o hello`를 사용하여 컴파일하면 "PIE" 실행 파일이 생성됩니다. nixpkgs에서는 64비트 바이너리에 대해 "PIE"를 기본으로 컴파일하는 것에 대한 논의가 있지만, 심각한 성능 문제로 인해 32비트 바이너리는 unPIEd 상태로 유지됩니다. 참조: https://github.com/NixOS/nixpkgs/issues/7220

그런데 `/proc/$PID/maps`를 검사하고 정확한 사람이 읽을 수 있는 바이트 크기를 제공하는 도구가 있다면 좋지 않을까요?

이제 각 영역에 대해 자세히 살펴보겠습니다. 아직 `malloc`이 발생하지 않아 `[heap]` 영역이 없는 프로그램 시작 시점임을 기억하세요.

```
     0 - 400000 - 4194304 B - 4096 KiB ~ 4 MiB - NOT ALLOCATED
400000 - 401000 - 4096 B    - 4 KiB
600000 - 601000 - 4096 B    - 4 KiB
601000 - 602000 - 4096 B    - 4 KiB
```

이것이 우리의 초기 메모리 범위입니다. `0` 주소에서 시작하여 `40 00 00` 주소에 도달하는 추가 구성 요소를 추가했습니다. 주소는 왼쪽을 포함하고 오른쪽을 제외하는 것으로 보입니다. 하지만 주소가 0에서 시작한다는 것을 기억하세요. 따라서 `bc <<< 'obase=10;ibase=16 400000 - 0'`를 사용하여 1을 더하거나 빼지 않고도 해당 범위의 실제 바이트 수를 얻을 수 있습니다. 이 경우 할당되지 않은 첫 번째 영역은 대략 4 MiB입니다. 할당되지 않았다고 할 때, `/proc/$PID/maps`에 표시되지 않는다는 의미입니다. 이는 두 가지 중 하나를 의미할 수 있습니다. 파일이 할당된 모든 메모리를 보여주지 않거나, 그러한 메모리를 보여줄 가치가 없다고 판단하거나, 아니면 그곳에 실제로 할당된 메모리가 없다는 것입니다.



우리는 `0`와 `400000` 사이에 실제로 메모리가 있는지 확인할 수 있습니다. 정수를 포인터로 캐스팅하여 메모리 주소 어딘가를 가리키는 포인터를 생성하고 역참조를 시도하면 됩니다. 다음과 같이 할 수 있습니다:

```c
#include <stdio.h>

int main () {

    // 0x0 is hex literal that defaults to signed integer
    // here we are casting it to a void pointer
    // and then assigning it to a value declared to be a void pointer
    // this is the correct way to create an arbitrary pointer in C
    void * addr = (void *) 0x0;

    // in order to print out what exists at that pointer, we must dereference the pointer
    // but C doesn't know how to handle a value of void type
    // which means, we recast the void pointer to a char pointer
    // a char is some arbitrary byte, so hopefully it's a printable ASCII value
    // actually, we don't need to hope, because we have made printf specifically print the hex representation of the char, therefore it does not need to be a printable ascii value
    printf("0x%x\n", ((char *) addr)[0]); // prints 0x0
    printf("0x%x\n", ((char *) addr)[1]); // prints 0x1
    printf("0x%x\n", ((char *) addr)[2]); // prints 0x2

}
```

위의 코드를 실행하면 간단한 `segmentation fault`가 발생합니다. 이는 `/proc/$PID/maps`가 진실을 말하고 있다는 것을 증명합니다. `0-400000` 사이에는 실제로 아무것도 없습니다.

질문은 이 약 4 MiB의 간격이 왜 존재하는지입니다. 왜 0부터 메모리 할당을 시작하지 않을까요? 이는 malloc과 링커 구현자들의 임의적인 선택이었습니다. 그들은 단순히 64비트 ELF 실행 파일의 진입점이 `0x400000`이어야 하고, 32비트 ELF 실행 파일의 진입점은 `0x08048000`이어야 한다고 결정했습니다. 흥미로운 점은 위치 독립적 실행 파일(PIE)을 생성하면 대신 시작 주소가 `0x0`으로 바뀐다는 것입니다.

다음을 참조하세요:

* http://stackoverflow.com/questions/7187981/whats-the-memory-before-0x08048000-used-for-in-32-bit-machine
* http://stackoverflow.com/questions/12488010/why-the-entry-point-address-in-my-executable-is-0x8048330-0x330-being-offset-of
* http://stackoverflow.com/questions/14314021/why-linux-gnu-linker-chose-address-0x400000



> 진입점 주소는 실행 파일을 생성할 때 링크 편집기가 설정합니다. 로더는 제어를 진입점 주소로 전송하기 전에 ELF 헤더에 지정된 주소에 프로그램 파일을 매핑합니다.

> 로드 주소는 임의적이지만 x86에서는 SYSV와 함께 표준화되었습니다. 모든 아키텍처마다 다릅니다. 위와 아래에 무엇이 오는지도 임의적이며, 종종 링크된 라이브러리와 mmap() 영역이 차지합니다.

이것이 의미하는 바는 프로그램 실행 파일이 어떤 작업을 시작하기 전에 메모리에 로드된다는 것입니다. 실행 파일의 진입점은 `readelf`로 확인할 수 있습니다. 하지만 여기서 또 다른 질문이 생깁니다. 왜 `readelf`가 제공하는 진입점이 `0x400000`이 아닐까요? 그것은 `0x400000`과 진입점 사이의 위치가 EHDR과 PHDR, 즉 ELF 헤더와 프로그램 헤더에 사용되는 것으로 간주되기 때문입니다. 이에 대해서는 나중에 자세히 살펴보겠습니다.

```
$ readelf --file-header ./memory_layout | grep 'Entry point address'
  Entry point address:               0x400720
```

다음으로 우리가 볼 것은:

```
400000 - 401000 - 4096 B    - 4 KiB
600000 - 601000 - 4096 B    - 4 KiB
601000 - 602000 - 4096 B    - 4 KiB
```

보시다시피, 우리는 각각 4 KiB인 3개의 메모리 섹션이 있으며, 모두 `/home/vagrant/c_tests/memory_layout`에서 할당되었습니다.

이 섹션들은 무엇일까요?

첫 번째 세그먼트: "텍스트 세그먼트".

두 번째 세그먼트: "데이터 세그먼트".

세 번째 세그먼트: "BSS 세그먼트".

텍스트 세그먼트는 프로세스의 바이너리 이미지를 저장합니다. 데이터 세그먼트는 프로그래머가 초기화한 정적 변수를 저장합니다(예: `static char * foo = "bar";`). BSS 세그먼트는 0으로 채워지는 초기화되지 않은 정적 변수를 저장합니다(예: `static char * username;`).



우리의 프로그램은 현재 매우 단순해서 각각이 4 KiB에 완벽하게 들어맞는 것처럼 보입니다. 어떻게 이렇게 완벽할 수 있을까요!?

실제로 Linux OS와 다른 많은 OS들에서는 기본적으로 페이지 크기가 4 KiB로 설정되어 있습니다. 이는 메모리에서 주소 지정이 가능한 최소 세그먼트가 4 KiB라는 의미입니다. 참조: https://en.wikipedia.org/wiki/Page_%28computer_memory%29

> 페이지, 메모리 페이지, 또는 가상 페이지는 페이지 테이블의 단일 항목으로 설명되는 고정 길이의 연속된 가상 메모리 블록입니다. 이는 가상 메모리 운영 체제에서 메모리 관리를 위한 가장 작은 단위입니다.

`getconf PAGESIZE`를 실행하면 4096바이트를 보여줍니다.

따라서 이는 각 세그먼트가 아마도 `4096` 바이트보다 훨씬 작지만, 4096 바이트로 패딩된다는 것을 의미합니다.

이전에 보여드린 것처럼, 임의의 포인터를 만들고 해당 바이트에 저장된 값을 출력하는 것이 가능합니다. 이제 우리는 위에 표시된 세그먼트에 대해 이를 수행할 수 있습니다.

하지만 잠깐, 우리는 더 잘할 수 있습니다. 개별 바이트를 해킹하는 대신, 이 데이터가 실제로 구조체로 구성되어 있다는 것을 인식할 수 있습니다.

어떤 종류의 구조체일까요? `readelf` 소스 코드를 살펴보면 관련 구조체를 찾을 수 있습니다. 이러한 구조체는 표준 C 라이브러리의 일부가 아닌 것 같으므로, 이를 작동시키기 위해 뭔가를 포함시킬 수는 없습니다. 하지만 코드가 단순하므로 복사하여 붙여넣기만 하면 됩니다. 참조: http://rpm5.org/docs/api/readelf_8h-source.html



다음을 확인해보세요:

```c
// compile with gcc -std=c99 -o elfheaders ./elfheaders.c
#include <stdio.h>
#include <stdint.h>

// from: http://rpm5.org/docs/api/readelf_8h-source.html
// here we're only concerned about 64 bit executables, the 32 bit executables have different sized headers

typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint64_t Elf64_Xword;
typedef uint32_t Elf64_Word;
typedef uint16_t Elf64_Half;
typedef uint8_t  Elf64_Char;

#define EI_NIDENT 16

// this struct is exactly 64 bytes
// this means it goes from 0x400000 - 0x400040
typedef struct {
    Elf64_Char  e_ident[EI_NIDENT]; // 16 B
    Elf64_Half  e_type;             // 2 B
    Elf64_Half  e_machine;          // 2 B
    Elf64_Word  e_version;          // 4 B
    Elf64_Addr  e_entry;            // 8 B
    Elf64_Off   e_phoff;            // 8 B
    Elf64_Off   e_shoff;            // 8 B
    Elf64_Word  e_flags;            // 4 B
    Elf64_Half  e_ehsize;           // 2 B
    Elf64_Half  e_phentsize;        // 2 B
    Elf64_Half  e_phnum;            // 2 B
    Elf64_Half  e_shentsize;        // 2 B
    Elf64_Half  e_shnum;            // 2 B
    Elf64_Half  e_shstrndx;         // 2 B
} Elf64_Ehdr;

// this struct is exactly 56 bytes
// this means it goes from 0x400040 - 0x400078
typedef struct {
     Elf64_Word  p_type;   // 4 B
     Elf64_Word  p_flags;  // 4 B
     Elf64_Off   p_offset; // 8 B
     Elf64_Addr  p_vaddr;  // 8 B
     Elf64_Addr  p_paddr;  // 8 B
     Elf64_Xword p_filesz; // 8 B
     Elf64_Xword p_memsz;  // 8 B
     Elf64_Xword p_align;  // 8 B
} Elf64_Phdr;

int main(int argc, char *argv[]){

    // from examination of objdump and /proc/ID/maps, we can see that this is the first thing loaded into memory
    // earliest in the virtual memory address space, for a 64 bit ELF executable
    // %lx is required for 64 bit hex, while %x is just for 32 bit hex

    Elf64_Ehdr * ehdr_addr = (Elf64_Ehdr *) 0x400000;

    printf("Magic:                      0x");
    for (unsigned int i = 0; i < EI_NIDENT; ++i) {
        printf("%x", ehdr_addr->e_ident[i]);
    }
    printf("\n");
    printf("Type:                       0x%x\n", ehdr_addr->e_type);
    printf("Machine:                    0x%x\n", ehdr_addr->e_machine);
    printf("Version:                    0x%x\n", ehdr_addr->e_version);
    printf("Entry:                      %p\n", (void *) ehdr_addr->e_entry);
    printf("Phdr Offset:                0x%lx\n", ehdr_addr->e_phoff); 
    printf("Section Offset:             0x%lx\n", ehdr_addr->e_shoff);
    printf("Flags:                      0x%x\n", ehdr_addr->e_flags);
    printf("ELF Header Size:            0x%x\n", ehdr_addr->e_ehsize);
    printf("Phdr Header Size:           0x%x\n", ehdr_addr->e_phentsize);
    printf("Phdr Entry Count:           0x%x\n", ehdr_addr->e_phnum);
    printf("Section Header Size:        0x%x\n", ehdr_addr->e_shentsize);
    printf("Section Header Count:       0x%x\n", ehdr_addr->e_shnum);
    printf("Section Header Table Index: 0x%x\n", ehdr_addr->e_shstrndx);

    Elf64_Phdr * phdr_addr = (Elf64_Phdr *) 0x400040;

    printf("Type:                     %u\n", phdr_addr->p_type); // 6 - PT_PHDR - segment type
    printf("Flags:                    %u\n", phdr_addr->p_flags); // 5 - PF_R + PF_X - r-x permissions equal to chmod binary 101
    printf("Offset:                   0x%lx\n", phdr_addr->p_offset); // 0x40 - byte offset from the beginning of the file at which the first segment is located
    printf("Program Virtual Address:  %p\n", (void *) phdr_addr->p_vaddr); // 0x400040 - virtual address at which the first segment is located in memory  
    printf("Program Physical Address: %p\n", (void *) phdr_addr->p_paddr); // 0x400040 - physical address at which the first segment is located in memory (irrelevant on Linux)
    printf("Loaded file size:         0x%lx\n", phdr_addr->p_filesz); // 504 - bytes loaded from the file for the PHDR
    printf("Loaded mem size:          0x%lx\n", phdr_addr->p_memsz); // 504 - bytes loaded into memory for the PHDR
    printf("Alignment:                %lu\n", phdr_addr->p_align); // 8 - alignment using modular arithmetic (mod p_vaddr palign)  === (mod p_offset p_align)
    
    return 0;

}
```

위의 코드를 실행하면 다음과 같은 결과가 나옵니다:

```
$ ./elfheaders
Magic:                      0x7f454c46211000000000
Type:                       0x2
Machine:                    0x3e
Version:                    0x1
Entry:                      0x400490
Phdr Offset:                0x40
Section Offset:             0x1178
Flags:                      0x0
ELF Header Size:            0x40
Phdr Header Size:           0x38
Phdr Entry Count:           0x9
Section Header Size:        0x40
Section Header Count:       0x1e
Section Header Table Index: 0x1b
Type:                     6
Flags:                    5
Offset:                   0x40
Program Virtual Address:  0x400040
Program Physical Address: 0x400040
Loaded file size:         0x1f8
Loaded mem size:          0x1f8
Alignment:                8
```



위의 출력을 다음과 비교해보세요:

```
$ readelf --file-header ./elfheaders
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x400490
  Start of program headers:          64 (bytes into file)
  Start of section headers:          4472 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         9
  Size of section headers:           64 (bytes)
  Number of section headers:         30
  Section header string table index: 27
```

우리는 기본적으로 우리만의 작은 `readelf` 프로그램을 작성했습니다.

따라서 `0x400000 - 0x401000`의 시작 부분에 실제로 무엇이 있는지 이해하기 시작하고 있습니다. OS가 이 프로그램을 어떻게 사용해야 하는지 알려주는 ELF 실행 파일 헤더와 기타 흥미로운 메타데이터가 모두 있습니다. 구체적으로 이는 프로그램의 실제 진입점(`./elfheader`의 경우: `0x400490`, `./memory_layout`의 경우: `0x400720`)과 메모리의 실제 시작점인 `0x400000` 사이에 위치한 것에 관한 것입니다. 연구할 프로그램 헤더가 더 있지만, 지금은 이 정도면 충분합니다. 참조: http://www.ouah.org/RevEng/x430.htm 



하지만 OS는 이 데이터를 어디서 가져올까요? 메모리에 넣기 전에 이 데이터를 획득해야 합니다. 실제로 답은 매우 간단합니다. 바로 파일 자체입니다.

`hexdump`를 사용하여 바이너리의 실제 내용을 보고, 나중에는 `objdump`를 사용하여 이를 어셈블리로 디스어셈블하여 기계 코드의 의미를 파악해보겠습니다.

시작 메모리 주소가 파일의 시작 주소와 같을 리가 없습니다. 따라서 `0x400000` 대신 파일은 대부분 `0x0`에서 시작할 것입니다.

```
$ hexdump -C -s 0x0 ./memory_layout # the -s option is just for offset, it's actually redundant here, but will be useful later
00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
00000010  02 00 3e 00 01 00 00 00  20 07 40 00 00 00 00 00  |..>..... .@.....|
00000020  40 00 00 00 00 00 00 00  a8 11 00 00 00 00 00 00  |@...............|
00000030  00 00 00 00 40 00 38 00  09 00 40 00 1e 00 1b 00  |....@.8...@.....|
00000040  06 00 00 00 05 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
00000050  40 00 40 00 00 00 00 00  40 00 40 00 00 00 00 00  |@.@.....@.@.....|
00000060  f8 01 00 00 00 00 00 00  f8 01 00 00 00 00 00 00  |................|
00000070  08 00 00 00 00 00 00 00  03 00 00 00 04 00 00 00  |................|
00000080  38 02 00 00 00 00 00 00  38 02 40 00 00 00 00 00  |8.......8.@.....|
00000090  38 02 40 00 00 00 00 00  1c 00 00 00 00 00 00 00  |8.@.............|
000000a0  1c 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00  |................|
000000b0  01 00 00 00 05 00 00 00  00 00 00 00 00 00 00 00  |................|
000000c0  00 00 40 00 00 00 00 00  00 00 40 00 00 00 00 00  |..@.......@.....|
000000d0  34 0c 00 00 00 00 00 00  34 0c 00 00 00 00 00 00  |4.......4.......|
000000e0  00 00 20 00 00 00 00 00  01 00 00 00 06 00 00 00  |.. .............|
000000f0  00 0e 00 00 00 00 00 00  00 0e 60 00 00 00 00 00  |..........`.....|
00000100  00 0e 60 00 00 00 00 00  78 02 00 00 00 00 00 00  |..`.....x.......|
00000110  80 02 00 00 00 00 00 00  00 00 20 00 00 00 00 00  |.......... .....|
00000120  02 00 00 00 06 00 00 00  18 0e 00 00 00 00 00 00  |................|
00000130  18 0e 60 00 00 00 00 00  18 0e 60 00 00 00 00 00  |..`.......`.....|
00000140  e0 01 00 00 00 00 00 00  e0 01 00 00 00 00 00 00  |................|
00000150  08 00 00 00 00 00 00 00  04 00 00 00 04 00 00 00  |................|
00000160  54 02 00 00 00 00 00 00  54 02 40 00 00 00 00 00  |T.......T.@.....|
00000170  54 02 40 00 00 00 00 00  44 00 00 00 00 00 00 00  |T.@.....D.......|
00000180  44 00 00 00 00 00 00 00  04 00 00 00 00 00 00 00  |D...............|
00000190  50 e5 74 64 04 00 00 00  e0 0a 00 00 00 00 00 00  |P.td............|
000001a0  e0 0a 40 00 00 00 00 00  e0 0a 40 00 00 00 00 00  |..@.......@.....|
000001b0  3c 00 00 00 00 00 00 00  3c 00 00 00 00 00 00 00  |<.......<.......|
000001c0  04 00 00 00 00 00 00 00  51 e5 74 64 06 00 00 00  |........Q.td....|
000001d0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
...
```



긴 텍스트이므로 `less`로 파이프하는 것이 좋습니다. `*`는 "위 줄과 동일"을 의미한다는 점에 유의하세요.

우선 처음 16바이트를 확인해보세요: `7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00`.

이것이 `readelf`가 보여주는 매직 바이트와 동일하다는 점에 주목하세요:

```
$ readelf -h ./memory_layout | grep Magic
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
```

따라서 Linux에서 gcc로 컴파일된 non-PIE 64비트 ELF 실행 파일의 `0x400000`이 실행 파일 자체의 `0x0`와 정확히 동일한 시작점이라는 것을 알 수 있습니다.

파일 헤더가 실제로 메모리에 로드되고 있습니다. 하지만 파일 전체가 메모리에 로드되는지 여부를 알 수 있을까요? 먼저 파일 크기를 확인해보겠습니다.

```
$ stat memory_layout | grep Size
  Size: 8932            Blocks: 24         IO Block: 4096   regular file
```

파일이 8932바이트, 즉 약 8.7 KiB라는 것을 보여줍니다.

우리의 메모리 레이아웃은 `memory_layout` 실행 파일에서 최대 4 KiB + 4 KiB + 4 KiB가 매핑되었음을 보여주었습니다.

공간이 충분하고, 파일의 전체 내용을 담기에 충분한 공간이 있습니다.

하지만 전체 메모리 내용을 반복하고 메모리의 관련 오프셋이 파일의 내용과 일치하는지 확인함으로써 이를 증명할 수 있습니다.



이를 위해서는 `/proc/$PID/mem`를 조사해야 합니다. 하지만 이는 cat으로 읽을 수 있는 일반적인 파일이 아니라, 출력을 얻기 위해 몇 가지 흥미로운 시스템 콜을 수행해야 합니다. 이를 읽기 위한 표준 유닉스 도구는 없으며, 대신 C 프로그램을 작성하여 읽어야 합니다. 여기에 예제 프로그램이 있습니다: http://unix.stackexchange.com/a/251769/56970

다행히도 `gdb`라는 것이 있고, 프로세스의 메모리 내용을 디스크에 덤프하기 위해 `gcore`를 사용할 수 있습니다. 기본적으로 프로세스의 메모리에 접근하는 것이므로 수퍼유저 권한이 필요하며, 메모리는 보통 격리되어 있어야 하기 때문입니다!

```
$ sudo gcore 1255

Program received signal SIGTTIN, Stopped (tty input).
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
0x00007f849c407350 in read () from /lib/x86_64-linux-gnu/libc.so.6
Saved corefile core.1255

[1]+  Stopped                 ./memory_layout
```

이는 `core.1255`라는 파일을 생성합니다. 이 파일이 메모리 덤프이므로, 이를 보기 위해서는 `hexedit`을 사용해야 합니다.

```
$ hexdump -C ./core.1255 | less
```

이제 전체 메모리 내용을 가지고 있으니, 실행 파일 자체와 비교해보도록 하겠습니다. 그전에 바이너리 프로그램을 읽을 수 있는 ASCII로 변환해야 합니다. 본질적으로 바이너리 프로그램을 ASCII로 무장화하는 것입니다. `hexdump`는 `|` 문자를 출력하여 `diff`를 사용할 때 혼란스러운 출력을 줄 수 있으므로, 이 목적에는 `xxd`가 더 적합합니다.



```
$ xxd ./core.1255 > ./memory.hex
$ xxd ./memory_layout > ./file.hex
```

즉시 두 크기가 같지 않다는 것을 알 수 있습니다. `./memory.hex`는 약 1.1 MiB로 `./file.hex`의 약 37 KiB보다 훨씬 큽니다. 이는 메모리 덤프가 모든 공유 라이브러리와 익명으로 매핑된 영역도 포함하기 때문입니다. 하지만 우리는 이들이 같기를 기대하지 않습니다. 단지 파일 자체가 메모리에 존재하는지 여부만 확인하면 됩니다.

이제 두 파일을 `diff`를 사용하여 비교할 수 있습니다.

```
$ diff --side-by-side ./file.hex ./memory.hex # try piping into less
0000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF.......   0000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF.......
0000010: 0200 3e00 0100 0000 2007 4000 0000 0000  ..>..... .@ | 0000010: 0400 3e00 0100 0000 0000 0000 0000 0000  ..>........
0000020: 4000 0000 0000 0000 a811 0000 0000 0000  @.......... | 0000020: 4000 0000 0000 0000 1022 0400 0000 0000  @........".
0000030: 0000 0000 4000 3800 0900 4000 1e00 1b00  ....@.8...@ | 0000030: 0000 0000 4000 3800 1500 4000 1700 1600  ....@.8...@
0000040: 0600 0000 0500 0000 4000 0000 0000 0000  ........@.. | 0000040: 0400 0000 0400 0000 d804 0000 0000 0000  ...........
0000050: 4000 4000 0000 0000 4000 4000 0000 0000  @.@.....@.@ | 0000050: 0000 0000 0000 0000 0000 0000 0000 0000  ...........
0000060: f801 0000 0000 0000 f801 0000 0000 0000  ........... | 0000060: 200d 0000 0000 0000 0000 0000 0000 0000   ..........
```

이는 메모리 내용과 파일 내용 사이에 일부 유사성이 있지만, 정확히 동일하지는 않다는 것을 보여줍니다. 실제로 우리는 17바이트부터 시작하여 ELF 매직 바이트를 지나서 두 덤프 사이에 차이가 있는 것을 봅니다.

이는 파일에서 메모리로의 매핑이 있더라도 정확히 같은 바이트가 아니라는 것을 보여줍니다. 아니면 덤프 과정과 16진수 변환 과정에서 바이트가 변경되었을 수도 있습니다. 이 시점에서는 정확히 알기 어렵습니다.



어떻든 계속 진행하면서, 실행 파일에서 실제 어셈블리 명령어를 보기 위해 `objdump`를 사용하여 실행 파일을 디스어셈블할 수 있습니다. 한 가지 주목할 점은, `objdump`가 실제 파일의 주소가 아닌 실행될 때의 프로그램의 가상 메모리 주소를 사용한다는 것입니다. `/proc/$PID/maps`에서 메모리 영역을 알고 있으므로, 첫 번째 `400000 - 401000` 영역을 검사할 수 있습니다.

```
$ objdump --disassemble-all --start-address=0x000000 --stop-address=0x401000 ./memory_layout # use less of course

./memory_layout:     file format elf64-x86-64


Disassembly of section .interp:

0000000000400238 <.interp>:
  400238:       2f                      (bad)
  400239:       6c                      insb   (%dx),%es:(%rdi)
  40023a:       69 62 36 34 2f 6c 64    imul   $0x646c2f34,0x36(%rdx),%esp
  400241:       2d 6c 69 6e 75          sub    $0x756e696c,%eax
  400246:       78 2d                   js     400275 <_init-0x3d3>
  400248:       78 38                   js     400282 <_init-0x3c6>
  40024a:       36                      ss
  40024b:       2d 36 34 2e 73          sub    $0x732e3436,%eax
  400250:       6f                      outsl  %ds:(%rsi),(%dx)
  400251:       2e 32 00                xor    %cs:(%rax),%al

Disassembly of section .note.ABI-tag:

0000000000400254 <.note.ABI-tag>:
  400254:       04 00                   add    $0x0,%al
  400256:       00 00                   add    %al,(%rax)
  400258:       10 00                   adc    %al,(%rax)
  40025a:       00 00                   add    %al,(%rax)
  40025c:       01 00                   add    %eax,(%rax)
  40025e:       00 00                   add    %al,(%rax)
  400260:       47                      rex.RXB
  400261:       4e 55                   rex.WRX push %rbp
  400263:       00 00                   add    %al,(%rax)
  400265:       00 00                   add    %al,(%rax)
  400267:       00 02                   add    %al,(%rdx)
  400269:       00 00                   add    %al,(%rax)
...
```



`gcore`나 임의의 포인터를 수동으로 역참조하는 것과 달리, `objdump`는 `400000 - 400238` 사이의 메모리 내용을 보여주지 않거나 보여줄 수 없습니다. 대신 `400238`부터 보여주기 시작합니다. 이는 `400000 - 400238` 사이의 내용이 어셈블리 명령어가 아니라 단순히 메타데이터이기 때문에 `objdump`가 이를 무시하는 것입니다. `objdump`는 어셈블리 코드를 덤프하도록 설계되었기 때문입니다. 또 다른 이해해야 할 점은 줄임표 `        ...`(위 예제에서는 보이지 않음)(제가 출력이 발췌본임을 나타내기 위해 사용한 `...`와 혼동하지 마세요)가 null 바이트를 의미한다는 것입니다. `objdump`는 기계 코드를 바이트별로 보여주고 그에 해당하는 디컴파일된 어셈블리 명령어를 보여줍니다. 이는 디스어셈블러이므로, 최적화가 있을 수 있고 많은 의미 정보가 버려지기 때문에 출력되는 어셈블리는 사람이 작성할 법한 것과 정확히 일치하지 않습니다. 오른쪽에 있는 16진수 주소가 시작 바이트 주소를 나타낸다는 점이 중요합니다. 오른쪽에 여러 개의 16진수 바이트 숫자가 있다면, 그것들이 하나의 어셈블리 명령어로 결합된다는 의미입니다. 따라서 `400251 - 400254` 사이의 갭은 `2e 32 00`의 3개의 16진수 바이트로 표현됩니다.



`readelf --file-header ./memory_layout`가 보고한 대로 실제 "진입점" `0x400720`으로 이동해 보겠습니다.

```
$ objdump --disassemble-all --start-address=0x000000 --stop-address=0x401000 ./memory_layout | less +/400720
...
Disassembly of section .text:

0000000000400720 <_start>:
  400720:       31 ed                   xor    %ebp,%ebp
  400722:       49 89 d1                mov    %rdx,%r9
  400725:       5e                      pop    %rsi
  400726:       48 89 e2                mov    %rsp,%rdx
  400729:       48 83 e4 f0             and    $0xfffffffffffffff0,%rsp
  40072d:       50                      push   %rax
  40072e:       54                      push   %rsp
  40072f:       49 c7 c0 a0 09 40 00    mov    $0x4009a0,%r8
  400736:       48 c7 c1 30 09 40 00    mov    $0x400930,%rcx
  40073d:       48 c7 c7 62 08 40 00    mov    $0x400862,%rdi
  400744:       e8 87 ff ff ff          callq  4006d0 <__libc_start_main@plt>
  400749:       f4                      hlt
  40074a:       66 0f 1f 44 00 00       nopw   0x0(%rax,%rax,1)
...
```

조금 위로 스크롤하면, `objdump`가 이를 실제 `.text` 섹션으로 보고하며, `400720`에서 이것이 프로그램의 진입점이라는 것을 볼 수 있습니다. 여기에 있는 것이 CPU가 실행하는 실제 첫 번째 "절차"이며, `main` 함수 뒤에 있는 함수입니다. 런타임 라이브러리를 포기하여 독립 실행형 C 실행 파일을 생성할 때 이것을 직접 다룰 수 있다고 생각합니다. 여기에 있는 어셈블리는 x86 64비트 어셈블리(https://en.wikipedia.org/wiki/X86_assembly_language)로, 이는 역호환성이 있는 Intel/AMD 64비트 프로세서에서 실행되도록 설계되었습니다. 이 특정 어셈블리에 대해서는 더 이상 모르므로, 나중에 http://www.cs.virginia.edu/~evans/cs216/guides/x86.html 에서 공부해야 할 것입니다.



우리의 다른 두 섹션은 어떨까요(`401000 - 600000` 사이에 건너뛰기가 있다는 것을 볼 수 있는데, 이 역시 링커 구현의 임의적인 선택일 수 있습니다):

```
600000 - 601000 - 4096 B    - 4 KiB
601000 - 602000 - 4096 B    - 4 KiB
```

```
$ objdump --disassemble-all --start-address=0x600000 --stop-address=0x602000 ./memory_layout | less
```

지금 당장은 이야기할 것이 많지 않습니다. `0x600000`이 더 많은 데이터와 어셈블리를 포함하고 있는 것으로 보입니다. 하지만 `.data`와 `.bss`의 실제 주소는 다음과 같이 나타납니다:

```
Disassembly of section .data:

0000000000601068 <__data_start>:
        ...

0000000000601070 <__dso_handle>:
        ...

Disassembly of section .bss:

0000000000601078 <__bss_start>:
        ...
```

`.data`와 `.bss`에 아무것도 없다는 것을 알 수 있습니다. 이는 우리의 `./memory_layout.c` 프로그램에 정적 변수가 없기 때문입니다!



정리하자면, 메모리 레이아웃에 대한 우리의 초기 이해는 다음과 같았습니다:

```
0
Program Text (.text)
Initialised Data (.data)
Uninitialised Data (.bss)
Heap
    |
    v
Memory Mapped Region for Shared Libraries or Anything Else
    ^
    |
User Stack
```

이제 실제로는 다음과 같다는 것을 알게 되었습니다:

```
0
Nothing here, because it was just an arbitrary choice by the linker
ELF and Program and Section Headers - 0x400000 on 64 bit
Program Text (.text) - Entry Point as Reported by readelf
Nothing Here either
Some unknown assembly and data - 0x600000
Initialised Data (.data) - 0x601068
Uninitialised Data (.bss) - 0x601078
Heap
    |
    v
Memory Mapped Region for Shared Libraries or Anything Else
    ^
    |
User Stack
```

계속 진행하겠습니다. 실행 파일 메모리 이후에 `601000 -  7f849c31b000` 까지 큰 건너뛰기가 있습니다.

```
00400000-00401000 r-xp 00000000 fc:00 1457150                            /home/vagrant/c_tests/memory_layout
00600000-00601000 r--p 00000000 fc:00 1457150                            /home/vagrant/c_tests/memory_layout
00601000-00602000 rw-p 00001000 fc:00 1457150                            /home/vagrant/c_tests/memory_layout

... WHAT IS GOING ON HERE? ...

7f849c31b000-7f849c4d6000 r-xp 00000000 fc:00 1579071                    /lib/x86_64-linux-gnu/libc-2.19.so
7f849c4d6000-7f849c6d6000 ---p 001bb000 fc:00 1579071                    /lib/x86_64-linux-gnu/libc-2.19.so
7f849c6d6000-7f849c6da000 r--p 001bb000 fc:00 1579071                    /lib/x86_64-linux-gnu/libc-2.19.so
7f849c6da000-7f849c6dc000 rw-p 001bf000 fc:00 1579071                    /lib/x86_64-linux-gnu/libc-2.19.so
7f849c6dc000-7f849c6e1000 rw-p 00000000 00:00 0
7f849c6e1000-7f849c6fa000 r-xp 00000000 fc:00 1579084                    /lib/x86_64-linux-gnu/libpthread-2.19.so
7f849c6fa000-7f849c8f9000 ---p 00019000 fc:00 1579084                    /lib/x86_64-linux-gnu/libpthread-2.19.so
7f849c8f9000-7f849c8fa000 r--p 00018000 fc:00 1579084                    /lib/x86_64-linux-gnu/libpthread-2.19.so
7f849c8fa000-7f849c8fb000 rw-p 00019000 fc:00 1579084                    /lib/x86_64-linux-gnu/libpthread-2.19.so
7f849c8fb000-7f849c8ff000 rw-p 00000000 00:00 0
7f849c8ff000-7f849c922000 r-xp 00000000 fc:00 1579072                    /lib/x86_64-linux-gnu/ld-2.19.so
7f849cb10000-7f849cb13000 rw-p 00000000 00:00 0
7f849cb1d000-7f849cb21000 rw-p 00000000 00:00 0
7f849cb21000-7f849cb22000 r--p 00022000 fc:00 1579072                    /lib/x86_64-linux-gnu/ld-2.19.so
7f849cb22000-7f849cb23000 rw-p 00023000 fc:00 1579072                    /lib/x86_64-linux-gnu/ld-2.19.so
7f849cb23000-7f849cb24000 rw-p 00000000 00:00 0
7fffb5d61000-7fffb5d82000 rw-p 00000000 00:00 0                          [stack]
7fffb5dfe000-7fffb5e00000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```



대략 127 테비바이트의 거대한 건너뛰기가 있습니다. 왜 주소 공간에 이렇게 큰 간격이 있을까요? 이는 malloc 구현이 관여하는 부분입니다. 이 문서 https://github.com/torvalds/linux/blob/master/Documentation/x86/x86_64/mm.txt 는 메모리가 다음과 같은 방식으로 구조화되어 있음을 보여줍니다:

> ```
> Virtual memory map with 4 level page tables:
> 
> 0000000000000000 - 00007fffffffffff (=47 bits) user space, different per mm hole caused by [48:63] sign extension
> ffff800000000000 - ffff87ffffffffff (=43 bits) guard hole, reserved for hypervisor
> ffff880000000000 - ffffc7ffffffffff (=64 TB) direct mapping of all phys. memory
> ffffc80000000000 - ffffc8ffffffffff (=40 bits) hole
> ffffc90000000000 - ffffe8ffffffffff (=45 bits) vmalloc/ioremap space
> ffffe90000000000 - ffffe9ffffffffff (=40 bits) hole
> ffffea0000000000 - ffffeaffffffffff (=40 bits) virtual memory map (1TB)
> ... unused hole ...
> ffffec0000000000 - fffffc0000000000 (=44 bits) kasan shadow memory (16TB)
> ... unused hole ...
> ffffff0000000000 - ffffff7fffffffff (=39 bits) %esp fixup stacks
> ... unused hole ...
> ffffffef00000000 - ffffffff00000000 (=64 GB) EFI region mapping space
> ... unused hole ...
> ffffffff80000000 - ffffffffa0000000 (=512 MB)  kernel text mapping, from phys 0
> ffffffffa0000000 - ffffffffff5fffff (=1525 MB) module mapping space
> ffffffffff600000 - ffffffffffdfffff (=8 MB) vsyscalls
> ffffffffffe00000 - ffffffffffffffff (=2 MB) unused hole
> ```

보시다시피, Linux의 메모리 맵은 처음 `0000000000000000 - 00007fffffffffff`를 사용자 공간 메모리로 예약합니다. 47비트가 약 128 TiB를 예약하기에 충분하다는 것이 밝혀졌습니다. http://unix.stackexchange.com/a/64490/56970



자 이제 이 메모리 영역의 첫 번째와 마지막 섹션을 살펴보면:

```
7f849c31b000-7f849c4d6000 r-xp 00000000 fc:00 1579071                    /lib/x86_64-linux-gnu/libc-2.19.so
...
7fffb5dfe000-7fffb5e00000 r-xp 00000000 00:00 0                          [vdso]
```

이 영역들이 사용자 공간 메모리용으로 예약된 128 TiB 범위의 거의 하단에 있는 것으로 보입니다. 127 TiB의 간격이 있다는 점을 고려하면, 이는 기본적으로 우리의 malloc이 사용자 공간 범위 `0000000000000000 - 00007fffffffffff`를 양쪽 끝에서 사용한다는 것을 의미합니다. 낮은 끝에서는 힙을 위쪽으로 증가시키고(주소 번호가 올라가는 방향), 높은 끝에서는 스택을 아래쪽으로 증가시킵니다(주소 번호가 내려가는 방향).

동시에 스택은 실제로 고정된 메모리 섹션이므로, 힙만큼 많이 증가할 수 없습니다. 높은 끝에서, 하지만 스택보다 낮은 위치에서, 우리는 공유 라이브러리와 공유 라이브러리가 사용하는 것으로 보이는 익명 버퍼에 할당된 많은 메모리 영역을 볼 수 있습니다.

우리는 또한 실행 파일이 사용하는 공유 라이브러리를 볼 수 있습니다. 이는 시작 시 어떤 공유 라이브러리가 메모리에 로드될지를 결정합니다. 하지만 라이브러리와 코드는 동적으로 로드될 수도 있으며, 이는 링커가 볼 수 없다는 점을 기억하세요. 참고로 `ldd`는 "list dynamic dependencies"의 약자입니다.



```
$ ldd ./memory_layout
        linux-vdso.so.1 =>  (0x00007fff1a573000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f361ab4e000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f361a788000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f361ad7a000)
```

`ldd`를 여러 번 실행하면 매번 공유 라이브러리에 대해 다른 주소가 출력된다는 것을 알 수 있을 것입니다. 이는 프로그램을 여러 번 실행하고 `/proc/$PID/maps`를 확인했을 때 공유 라이브러리가 다른 주소를 보여주는 것과 일치합니다. 이는 위에서 논의한 "PIE" 위치 독립적 코드 때문입니다. 기본적으로 `ldd`를 사용할 때마다 링커를 호출하고, 링커가 주소 무작위화를 수행합니다. 주소 공간 무작위화의 이유에 대한 자세한 정보는 [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization)을 참조하세요. 또한 `cat /proc/sys/kernel/randomize_va_space`를 실행하여 커널이 ASLR을 활성화했는지 확인할 수 있습니다.

실제로 4개의 공유 라이브러리가 있다는 것을 알 수 있습니다. `vdso` 라이브러리는 파일시스템에서 로드되지 않고 OS에서 제공됩니다.

또한 참고: `/lib64/ld-linux-x86-64.so.2 => /lib/x86_64-linux-gnu/ld-2.19.so`, 이는 심볼릭 링크입니다.



마지막으로 마지막 몇 개의 영역을 살펴보겠습니다:

```
7fffb5d61000-7fffb5d82000 rw-p 00000000 00:00 0                          [stack]
7fffb5dfe000-7fffb5e00000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```

각 영역에 대한 관련 크기는 다음과 같습니다:

```
7fffb5d61000     - 7fffb5d82000     - [stack]    - 135168 B - 132 KiB 
7fffb5dfe000     - 7fffb5e00000     - [vdso]     - 8192 B   - 8 KiB
ffffffffff600000 - ffffffffff601000 - [vsyscall] - 4096 B   - 4 KiB
```

우리의 초기 스택 크기는 132 KiB로 할당되어 있습니다. 이는 런타임이나 컴파일러 플래그로 변경할 수 있을 것으로 생각됩니다.

그렇다면 `vdso`와 `vsyscall`은 무엇일까요? 둘 다 더 빠른 시스템 콜을 가능하게 하는 메커니즘입니다. 즉, 사용자 공간과 커널 공간 사이의 컨텍스트 전환 없이 시스템 콜을 수행할 수 있게 합니다. `vsyscall`은 이제 `vdso`로 대체되었지만, 호환성을 위해 `vsyscall`이 남아있습니다. 주요 차이점은 다음과 같습니다:

* `vsyscall` - PIC나 PIE가 활성화되어 있어도 항상 `ffffffffff600000`에 고정되어 있으며 최대 크기는 8 MiB입니다
* `vdso` - 고정되어 있지 않고 공유 라이브러리처럼 작동하므로, 그 주소는 ASLR(주소 공간 레이아웃 무작위화)의 대상이 됩니다
* `vsyscall` - 3개의 시스템 콜을 제공합니다: `gettimeofday` (`0xffffffffff600000`), `time` (`0xffffffffff600400`), `getcpu` (`0xffffffffff600800`), 64비트 ELF 실행 파일에서 Linux가 제공한 예약된 범위 `ffffffffff600000 - ffffffffffdfffff` 8 MiB가 있더라도 이 세 가지만 제공합니다.
* `vdso` - 4개의 시스템 콜을 제공합니다: `__vdso_clock_gettime`, `__vdso_getcpu`, `__vdso_gettimeofday`, `__vdso_time`, 하지만 앞으로 `vdso`에 더 많은 시스템 콜이 추가될 수 있습니다.



`vdso`와 `vsyscall`에 대한 자세한 정보는 다음을 참조하세요: https://0xax.gitbooks.io/linux-insides/content/SysCall/syscall-3.html

지적할 가치가 있는 점은, 이제 사용자 공간 메모리용으로 예약된 128 TiB를 지나서, 이제 우리는 OS가 제공하고 관리하는 메모리 세그먼트를 보고 있다는 것입니다. 여기에 나열된 것처럼 말입니다: https://github.com/torvalds/linux/blob/master/Documentation/x86/x86_64/mm.txt 우리가 이야기하는 것이 바로 이 섹션들입니다.

```
ffff800000000000 - ffff87ffffffffff (=43 bits) guard hole, reserved for hypervisor
ffff880000000000 - ffffc7ffffffffff (=64 TB) direct mapping of all phys. memory
ffffc80000000000 - ffffc8ffffffffff (=40 bits) hole
ffffc90000000000 - ffffe8ffffffffff (=45 bits) vmalloc/ioremap space
ffffe90000000000 - ffffe9ffffffffff (=40 bits) hole
ffffea0000000000 - ffffeaffffffffff (=40 bits) virtual memory map (1TB)
... unused hole ...
ffffec0000000000 - fffffc0000000000 (=44 bits) kasan shadow memory (16TB)
... unused hole ...
ffffff0000000000 - ffffff7fffffffff (=39 bits) %esp fixup stacks
... unused hole ...
ffffffef00000000 - ffffffff00000000 (=64 GB) EFI region mapping space
... unused hole ...
ffffffff80000000 - ffffffffa0000000 (=512 MB)  kernel text mapping, from phys 0
ffffffffa0000000 - ffffffffff5fffff (=1525 MB) module mapping space
ffffffffff600000 - ffffffffffdfffff (=8 MB) vsyscalls
ffffffffffe00000 - ffffffffffffffff (=2 MB) unused hole
```

위의 섹션들 중에서 현재 우리는 `vsyscall` 영역만 볼 수 있습니다. 나머지는 아직 나타나지 않았습니다.



이제 프로그램을 진행하면서 우리의 첫 번째 힙을 할당해보겠습니다. 이제 우리의 `/proc/$PID/maps`는 다음과 같습니다(프로그램을 다시 실행했기 때문에 주소가 변경되었음에 주의하세요):

```
$ ./memory_layout
Welcome to per thread arena example::1546
Before malloc in the main thread

After malloc and before free in main thread
^Z
[1]+  Stopped                 ./memory_layout
$ cat /proc/1546/maps
00400000-00401000 r-xp 00000000 fc:00 1457150                            /home/vagrant/c_tests/memory_layout
00600000-00601000 r--p 00000000 fc:00 1457150                            /home/vagrant/c_tests/memory_layout
00601000-00602000 rw-p 00001000 fc:00 1457150                            /home/vagrant/c_tests/memory_layout
019a3000-019c4000 rw-p 00000000 00:00 0                                  [heap]
...
```

이제 우리는 첫 번째 `[heap]` 영역을 볼 수 있습니다. 정확히 135168 B - 132 KiB입니다. (현재 우리의 스택 크기와 동일합니다!) 처음에 우리가 정확히 1000바이트를 할당했다는 것을 기억하세요: `addr = (char *) malloc(1000);`. 그렇다면 1000바이트가 어떻게 132 킬로바이트가 되었을까요? 앞서 말했듯이, `MMAP_THRESHOLD`보다 작은 것은 `brk` 시스템 콜을 사용합니다. `brk`/`sbrk`는 시스템 콜의 횟수와 컨텍스트 전환의 횟수를 줄이기 위해 패딩된 크기로 호출되는 것으로 보입니다.



대부분의 프로그램은 1000바이트보다 더 많은 힙이 필요할 것이므로, 시스템은 `brk` 호출을 패딩하여 일부 힙 메모리를 캐시하는 것이 합리적이며, 132 KiB의 패딩된 힙을 모두 사용한 후에만 힙 증가를 위한 새로운 `brk` 또는 `mmap` 호출이 발생할 것입니다. 패딩 계산은 다음과 같이 수행됩니다:

```
  /* Request enough space for nb + pad + overhead */
  size = nb + mp_.top_pad + MINSIZE;
```

여기서 `mp_.top_pad`는 기본적으로 128 * 1024 = 128 KiB로 설정됩니다. 여전히 4 KiB의 차이가 있습니다. 하지만 우리의 페이지 크기 `getconf PAGESIZE`가 4096을 제공하는 것을 기억하세요. 즉, 각 페이지는 4 KiB입니다. 이는 우리 프로그램에서 1000바이트를 할당할 때 4 KiB인 전체 페이지가 할당된다는 것을 의미합니다. 그리고 4 KiB + 128 KiB는 132 KiB이며, 이것이 우리 힙의 크기입니다. 이 패딩은 고정 크기로의 패딩이 아니라 `brk`/`sbrk`를 통해 할당되는 양에 항상 추가되는 패딩입니다. 이는 기본적으로 128 KiB가 할당하려는 메모리 양에 항상 추가된다는 것을 의미합니다. 하지만 이 패딩은 `brk`/`sbrk`에만 적용되고 `mmap`에는 적용되지 않습니다. `MMAP_THRESHOLD`를 넘어서면 `mmap`이 `brk`/`sbrk`를 대체한다는 것을 기억하세요. 즉, 패딩이 더 이상 적용되지 않을 것입니다. 하지만 `MMAP_THRESHOLD`가 패딩 전에 또는 후에 체크되는지는 확실하지 않습니다. 패딩 전에 체크되는 것 같습니다.



패딩 크기는 `mallopt(M_TOP_PAD, 1);`와 같은 호출로 변경할 수 있으며, 이는 `M_TOP_PAD`를 1바이트로 변경합니다. 이제 1000바이트를 malloc하면 4 KiB 페이지만 생성됩니다.

자세한 내용은 다음을 참조하세요: http://stackoverflow.com/a/23951267/582917

왜 오래된 `brk`/`sbrk`가 할당이 `MMAP_THRESHOLD`보다 크거나 같을 때 새로운 `mmap`으로 대체되는 걸까요? `brk`/`sbrk` 호출은 힙의 크기를 연속적으로만 증가시킬 수 있습니다. 작은 것들을 위해 `malloc`만 사용하는 경우, 모든 것이 힙에 연속적으로 할당될 수 있어야 하며, 힙 끝에 도달하면 크기를 문제 없이 확장할 수 있습니다. 하지만 더 큰 할당의 경우 `mmap`이 사용되며, 이 힙 공간은 `brk`/`sbrk` 힙 공간과 연속적으로 연결될 필요가 없습니다. 따라서 더 유연합니다. 이 상황에서 작은 객체에 대한 메모리 단편화가 감소됩니다. 또한 `mmap` 호출이 더 유연하므로 `brk`/`sbrk`는 `mmap`으로 구현될 수 있지만, `mmap`은 `brk`/`sbrk`로 구현될 수 없습니다. `brk`/`sbrk`의 한 가지 제한사항은 `brk`/`sbrk` 힙 공간의 최상위 바이트가 해제되지 않으면 힙 크기를 줄일 수 없다는 것입니다.

`MMAP_THRESHOLD`보다 더 많이 할당하는 간단한 프로그램을 살펴보겠습니다(`mallopt`를 사용하여 재정의할 수도 있음):



```c
#include <stdlib.h>
#include <stdio.h>

int main () {

    printf("Look at /proc/%d/maps\n", getpid());

    // allocate 200 KiB, forcing a mmap instead of brk
    char * addr = (char *) malloc(204800);

    getchar();

    free(addr);

    return 0;

}
```

위의 코드를 `strace`로 실행하면 다음과 같은 결과를 얻습니다:

```
$ strace ./mmap
...
mmap(NULL, 3953344, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f3b113ce000
mprotect(0x7f3b11589000, 2097152, PROT_NONE) = 0
mmap(0x7f3b11789000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1bb000) = 0x7f3b11789000
mmap(0x7f3b1178f000, 17088, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f3b1178f000
close(3)                                = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f3b119a7000
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f3b119a5000
arch_prctl(ARCH_SET_FS, 0x7f3b119a5740) = 0
mprotect(0x7f3b11789000, 16384, PROT_READ) = 0
mprotect(0x600000, 4096, PROT_READ)     = 0
mprotect(0x7f3b119b6000, 4096, PROT_READ) = 0
munmap(0x7f3b119a8000, 45778)           = 0
getpid()                                = 1604
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 0), ...}) = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f3b119b3000
write(1, "Look at /proc/1604/maps\n", 24Look at /proc/1604/maps
) = 24
mmap(NULL, 208896, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f3b11972000
fstat(0, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 0), ...}) = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f3b119b2000
...
```



위의 strace에는 많은 `mmap` 호출이 있습니다. 공유 라이브러리나 링커 또는 다른 것들이 아닌 우리 프로그램이 호출한 `mmap`을 어떻게 찾을 수 있을까요? 가장 근접한 호출은 다음과 같습니다:

```
mmap(NULL, 208896, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f3b11972000
```

실제로 이는 204800 B + 4096 B = 208896 B입니다. 페이지 크기인 4 KiB가 왜 추가되는지는 확실하지 않습니다. 200 KiB가 페이지 크기인 4 KiB로 정확히 나눠지기 때문입니다. 이는 다른 기능일 수 있습니다. 한 가지 주목할 점은 우리 프로그램의 시스템 호출을 다른 시스템 호출과 구별할 수 있는 명확한 방법이 없다는 것입니다. 하지만 우리는 호출의 맥락, 즉 이전과 이후의 라인들을 살펴봄으로써 정확한 제어 흐름을 찾을 수 있습니다. `getchar`를 사용하여 `strace`를 일시 중지할 수도 있다는 점을 고려하세요. 204800바이트를 mmapping한 직후 `fstat`와 다른 `mmap` 호출이 있고, 마지막으로 `getchar`가 호출된다는 점을 생각해보세요. 이러한 호출들이 어디서 오는지 모르므로, 앞으로는 시스템 호출을 더 빨리 찾을 수 있도록 쉽게 레이블을 붙일 수 있는 방법을 찾아야 할 것입니다. `strace`는 이 메모리 매핑된 영역이 `0x7f3b11972000`에 매핑되었다고 알려줍니다. 프로세스의 `/proc/$PID/maps`를 살펴보면:



```
$ cat /proc/1604/maps
00400000-00401000 r-xp 00000000 fc:00 1446413                            /home/vagrant/c_tests/test
00600000-00601000 r--p 00000000 fc:00 1446413                            /home/vagrant/c_tests/test
00601000-00602000 rw-p 00001000 fc:00 1446413                            /home/vagrant/c_tests/test
7f3b113ce000-7f3b11589000 r-xp 00000000 fc:00 1579071                    /lib/x86_64-linux-gnu/libc-2.19.so
7f3b11589000-7f3b11789000 ---p 001bb000 fc:00 1579071                    /lib/x86_64-linux-gnu/libc-2.19.so
7f3b11789000-7f3b1178d000 r--p 001bb000 fc:00 1579071                    /lib/x86_64-linux-gnu/libc-2.19.so
7f3b1178d000-7f3b1178f000 rw-p 001bf000 fc:00 1579071                    /lib/x86_64-linux-gnu/libc-2.19.so
7f3b1178f000-7f3b11794000 rw-p 00000000 00:00 0
7f3b11794000-7f3b117b7000 r-xp 00000000 fc:00 1579072                    /lib/x86_64-linux-gnu/ld-2.19.so
7f3b11972000-7f3b119a8000 rw-p 00000000 00:00 0
7f3b119b2000-7f3b119b6000 rw-p 00000000 00:00 0
7f3b119b6000-7f3b119b7000 r--p 00022000 fc:00 1579072                    /lib/x86_64-linux-gnu/ld-2.19.so
7f3b119b7000-7f3b119b8000 rw-p 00023000 fc:00 1579072                    /lib/x86_64-linux-gnu/ld-2.19.so
7f3b119b8000-7f3b119b9000 rw-p 00000000 00:00 0
7fff8f747000-7fff8f768000 rw-p 00000000 00:00 0                          [stack]
7fff8f7fe000-7fff8f800000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```

우리는 여기서 mmap된 힙을 찾을 수 있습니다:

```
7f3b11972000-7f3b119a8000 rw-p 00000000 00:00 0
```

보시다시피, malloc이 `mmap`을 사용하도록 전환되면, 획득된 영역은 `brk`/`sbrk` 호출에 의해서만 제공되는 소위 `[heap]` 영역의 일부가 아닙니다. 레이블이 없습니다! 또한 이러한 종류의 힙이 주소 공간에서 위로 증가하는 것으로 이해되는 `brk`/`sbrk` 힙과 같은 영역에 배치되지 않는다는 것을 알 수 있습니다. 대신 이 mmapped 힙은 공유 라이브러리와 같은 영역에 위치하여, 예약된 사용자 공간 주소 범위의 높은 끝에 위치합니다. 하지만 `/proc/$PID/maps`에 표시된 이 영역은 실제로 221184 B - 216 KiB입니다. 이는 208896에서 정확히 12 KiB가 더해진 것입니다. 또 다른 미스터리입니다! `strace`의 `mmap`이 정확히 `208896`을 호출했는데도 왜 다른 바이트 크기를 가지고 있을까요?



또 다른 `mmap` 호출을 살펴보면 `/proc/$PID/maps`의 해당 영역에도 12 KiB의 차이가 있다는 것을 보여줍니다. 여기서 12 KiB는 malloc이 사용 가능한 메모리의 유형을 추적하고 이해하는 데 사용하는 일종의 메모리 매핑 오버헤드를 나타낼 수 있습니다. 또는 단순히 추가 패딩일 수도 있습니다. 따라서 여기서 우리가 말할 수 있는 것은 mmapping하는 것에 대해 뭔가가 일관되게 12 KiB를 추가하고 있으며, 내가 요청한 200 KiB에도 추가 4 KiB가 있다는 것입니다.

참고로, `binwalk`라는 도구도 있는데, 이는 여러 실행 파일과 메타데이터를 포함할 수 있는 펌웨어 이미지를 검사하는 데 매우 유용합니다. 파일을 실행 파일에 임베드할 수 있다는 것을 기억하세요. 이는 일종의 바이러스가 작동하는 방식과 비슷합니다. 저는 NixOS의 initrd를 검사하고 그것이 어떻게 구조화되어 있는지 파악하기 위해 이를 사용했습니다. `dd`와 결합하면 이진 블롭을 쉽게 잘라내고 이어붙일 수 있습니다!

이 시점에서 우리는 원래 프로그램의 힙과 스레드 힙도 계속 조사할 수 있습니다. 하지만 지금은 여기서 멈추겠습니다.

계속됩니다...

이런 종류의 것들에 관심이 있다면, https://matrix.ai 에서 저와 함께 일하고 싶으실 수도 있습니다. 자유롭게 메시지를 보내주세요!
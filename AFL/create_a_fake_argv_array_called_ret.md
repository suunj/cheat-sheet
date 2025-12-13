
### AFL_INIT_ARGV()

AFL(American Fuzzy Lop) 퍼저에서 argv 퍼징을 가능하게 해주는 매크로 (utils/argv_fuzzing/argv-fuzz-inl.h)

일반적으로 AFL은 stdin이나 파일을 통해 입력을 제공한다. 하지만 많은 프로그램은 명령행 인자(argv)로 입력을 받는다. 

AFL_INIT_ARGV()는 이 문제를 해결한다.

```c
#include "argv-fuzz-inl.h"

int main(int argc, char **argv) {
    AFL_INIT_ARGV();  // 여기서 argv를 퍼징 입력으로 대체
    
    // 이제 argv는 AFL이 생성한 테스트케이스에서 옴
    if (argc > 1) {
        process(argv[1]);
    }
    return 0;
}
```

### 내부 동작

1. AFL이 생성한 입력 데이터를 stdin에서 읽음
2. 해당 데이터를 NULL 문자(`\0`)로 분리하여 argv 배열로 변환
3. `argc`와 `argv`를 새 값으로 덮어씀



### 입력 포맷

```
argument1\0argument2\0argument3\0
```

이렇게 NULL로 구분된 데이터가 다음처럼 변환된다.

```
argv[0] = "argument1"
argv[1] = "argument2"
argv[2] = "argument3"
```




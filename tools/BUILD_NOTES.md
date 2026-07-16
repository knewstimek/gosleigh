# decomp_dbg.exe 재빌드 노트

Ghidra C++ 디컴파일러 콘솔(CPUI_DEBUG 빌드)을 이 머신의 MSVC로 빌드하는 절차.
`ghidra-ref/`의 원본 C++를 소스 수정 없이 컴파일 플래그만으로 빌드한다.

- 산출물: `tools/decomp_dbg.exe` (약 2.5 MB, x86 32-bit, static CRT). `*.exe`는 gitignore라 커밋 안 됨.
- 빌드 스크립트: `tools/build_decomp_dbg.py` (아래 절차를 자동화. 상단 상수의 BUILD/OBJ 경로는 임시 디렉터리를 가리키므로 재빌드 시 원하는 위치로 바꿀 것).
- 대상 Makefile 타깃: `ghidra-ref/.../decompile/cpp/Makefile`의 `decomp_dbg` (COMMANDLINE 빌드).

## 툴체인

- Visual Studio 2022 Community, MSVC 14.38.33130.
- x86 타깃으로 빌드(Hostx64/x86 또는 Hostx86/x86). 이유: 사용 가능한 zlib이 32-bit static뿐(아래). 디컴파일러 호스트 비트수는 결과 정확도에 영향 없음(고정폭 타입 int4/uintb 사용).
- 환경 세팅: `VC\Auxiliary\Build\vcvarsall.bat x86`. 스크립트는 이 배치를 wrapper .bat로 호출해 환경을 덤프하고 그 환경으로 cl을 실행한다(git bash에서 cl 직접 호출 금지, `/flag`가 경로로 변환됨).

## 외부 의존성: zlib

`compression.cc`/`slaformat.cc`가 zlib(deflate/inflate)을 쓴다. 압축된 `.sla` 로더에 필요.
- 헤더: `C:\vcpkg\installed\x86-windows-static\include` (zlib.h, zconf.h)
- 라이브러리: `C:\vcpkg\installed\x86-windows-static\lib\zlib.lib` (static, `/MT` 릴리스 CRT로 빌드됨)
- 그래서 디컴파일러도 `/MT`로 빌드해 CRT를 맞춘다.

binutils BFD(`-lbfd`)는 이 머신에 없음. 아래 소스 제외로 회피.

## 소스 집합

`COMMANDLINE_NAMES = CORE + DECCORE + EXTRA + SLEIGH + consolemain` 에서 아래 4개를 제외.
정확한 목록은 `build_decomp_dbg.py`의 CORE/DECCORE/EXTRA/SLEIGH 리스트 참조(총 94 TU).

제외한 파일과 이유:
- `bfd_arch.cc`, `loadimage_bfd.cc`: binutils `bfd.h` 필요(부재).
- `analyzesigs.cc`, `codedata.cc`: `loadimage_bfd.hh`를 include -> `bfd.h` 필요. 둘 다 선택적 커맨드 모듈(signature 분석, codedata follow-flow)이라 restore/decompile/print 경로에 불필요.

제외해도 무방한 근거: `bfd`를 참조하는 소스는 위 4개(+빌드 안 하는 sleighexample)뿐. xml/raw/sleigh architecture capability는 그대로 링크됨.

미생성 파서는 신경 안 써도 됨: `grammar.cc xml.cc pcodeparse.cc slghparse.cc slghscan.cc`는 이미 커밋되어 있음. `ruleparse`는 `rulecompile.cc`가 통째로 `#ifdef CPUI_RULECOMPILE`라 정의 안 하면 빈 TU가 되어 불필요.

## 컴파일 플래그

```
cl /nologo /c /MP /EHsc /std:c++14 /O2 ^
   /D_WINDOWS /DNOMINMAX /DCPUI_DEBUG /Zc:__cplusplus ^
   /wd4267 /wd4244 /wd4018 /wd4996 /MT ^
   /I<zlib include> /Fo<objdir>\ <all .cc>
```

핵심 정의:
- `CPUI_DEBUG`: 디버그 트레이싱/`debug action`/`trace *` 콘솔 커맨드 활성화(이 빌드의 목적).
- `_WINDOWS`: `filemanage.cc`가 이 매크로로 POSIX(dirent/unistd)와 Win32(FindFirstFileA 등)를 분기. 정의 안 하면 `dirent.h` 없어서 실패.
- `NOMINMAX`: `filemanage.cc`가 `<windows.h>`를 include -> min/max 매크로가 std와 충돌하는 것 방지.
- `__TERMINAL__`은 **정의하지 않는다**. 원본 Makefile은 `-D__TERMINAL__`을 주지만 그러면 `ifaceterm.hh`가 POSIX `<termios.h>`를 include해서 MSVC에서 실패. 정의 안 하면 `IfaceTerm`이 raw 터미널 편집 없이 평범한 stream 입력을 쓴다(스크립트/파이프 입력엔 오히려 적합). `IfaceTerm` 멤버 레이아웃이 이 매크로로 바뀌므로 전 TU 일관되게 미정의로 빌드해야 함(ABI).
- `/std:c++14`: 원본은 c++11. c++17은 `register` 키워드 제거로 flex/구형 파서와 충돌 위험 -> c++14가 안전한 상위호환. MSVC 최소 지원도 c++14.
- `/wd*`: narrowing/부호/deprecation 경고 억제(에러 아님). 유일 잔여 경고는 address.cc(874) C4838(무해).

## 링크

```
cl /nologo /MT /Fe<exe> <all .obj> C:\vcpkg\...\x86-windows-static\lib\zlib.lib
```

kernel32 등 Win32 기본 라이브러리는 자동 링크(FindFirstFileA/GetFileAttributes 등 filemanage용). `-lbfd`/`-lz` 없음.

## 런타임 요구사항

`.sla`/spec를 찾으려면 Ghidra 설치 루트가 필요. exe가 Ghidra 트리 밖(tools/)에 있으므로 `argv[0]` 기반 자동탐지는 실패 -> 환경변수 `SLEIGHHOME`으로 지정.

```
SLEIGHHOME=D:\News\Utility\리버싱\ghidra_12.0.4_PUBLIC
```

(consolemain은 `-s <path>` 인자로도 spec 경로 추가 가능.)

## 검증

```
decomp_dbg.exe -i <script>
```

script:
```
restore D:\News\Business\Gosleigh\tools\captures\debug_op_switch.xml
load function FUN_140001000
decompile
print C
quit
```

기대: 콘솔 프롬프트 `init>`가 뜨고 `restore` 성공("... successfully loaded: Intel/AMD 64-bit x86"),
`print C`가 `uint FUN_140001000(...)` switch/case + `uVar1` 반환을 출력.

콘솔 커맨드는 `ifacedecomp.cc`/`consolemain.cc`에 등록됨: restore/load function/decompile/
print C[/flat/globals/types]/print raw/print high/print tree varnode/trace address/debug action 등.

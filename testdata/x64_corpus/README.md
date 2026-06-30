# x86-64 breadth corpus (Ghidra golden 생성)

실제 x64 함수(register params, 루프, 포인터, 조건, 중첩, 긴 복합)로 Ghidra 골든을 만들어
Gosleigh 트리의 real-world 갭을 측정하는 재현 가능한 파이프라인.

## ABI

MSVC `cl /c /Od`로 컴파일 = **Windows x64 ABI** (정수 인자 RCX/RDX/R8/R9, 반환 RAX).
Ghidra가 COFF obj를 `x86:LE:64:default:windows` cspec으로 자동 인식. 트리 테스트는
`testdata/sla/x86-64-win.cspec` 사용. (MSVC `long` = 4바이트라 출력은 `int`.)

## 파이프라인

```
py -3 testdata/x64_corpus/build.py        # corpus.c -> corpus.obj (MSVC x64, GS- )
py -3 testdata/x64_corpus/run_ghidra.py   # obj -> Ghidra 12 헤드리스 -> x64_goldens.json
X64_CORPUS=1 go test ./pkg/loader/ -run TestX64CorpusGoldenMap -v   # 트리 갭 맵
```

- `corpus.c` -- self-contained 함수들 (외부 호출/전역 없음 -> .text relocation 0 ->
  position-independent. 바이트를 base 0에 먹여도 동일 명령 스트림).
- `corpus.obj` -- 빌드 산출물 (gitignore. 바이트는 x64_goldens.json에 들어감).
- `GenGoldens.java` -- Ghidra Java postScript (Ghidra 12는 Jython 제거 -> Java 사용).
  각 함수의 {name, entry, bytes(hex), 디컴파일 C}를 JSON으로 덤프.
- `x64_goldens.json` -- 생성된 골든 (Ghidra 실측. bytes와 C가 동일 분석에서 나와 일관).

요구: `C:\ghidra12` (analyzeHeadless) + JDK 21 + MSVC VS2022
(`...\MSVC\14.38.33130\bin\Hostx64\x64\cl.exe`).

## 함수 (8개, 단순 -> 복잡)

add4(4 reg args) / poly4(혼합 산술) / max3(중첩 if) / sum_to_n(카운트 루프) /
sum_array(포인터 walk) / classify(switch -> compare 체인) / grid_score(중첩 루프 +
비트연산 + 분기) / process(긴 복합: 클램프 + 누산 + 나눗셈 + early return).

## 현재 트리 갭 (X64_CORPUS 측정, indent-insensitive)

- **register-param 복구 작동**: add4/poly4가 RCX/RDX/R8/R9 -> param_1..4 정확.
- **반환 크기 추론 갭(전 함수)**: 함수는 EAX(4바이트 `int`) 반환인데 트리가 RAX(8바이트)로
  고정 -> `unsigned long long` + promotion 캐스트 도배. buildDefaultModel이 반환 레지스터를
  자연 폭(RAX 8)으로 잡는 것이 원인. Ghidra는 실제 write 폭(EAX 4)으로 좁힘
  (characterizeReturnOutput/ActiveOutput 트라이얼).
- **RSP-relative 스택 프레임 갭(locals 있는 함수)**: x86-32은 EBP 프레임이라 OK였으나
  x64 /Od는 프레임포인터 없는 RSP-relative -> 스택 locals를 포인터 deref(`uVar7[10]`)로
  오복구. ActionStackPtrFlow가 RSP-relative(EBP 부재) 미처리로 추정.
- **promotion 캐스트**: 4바이트 산술에 `(unsigned long long)(unsigned int)` 연쇄 -- 반환 폭
  갭과 sign/width 캐스트 처리에서 파생.

자세한 분류와 다음 단계는 `docs/STATUS.md` #2 참조.

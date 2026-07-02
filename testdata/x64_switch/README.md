# x86-64 real-switch corpus (완전 링크된 .exe -> 진짜 jump table 복구)

`testdata/x64_breadth`의 `dispatch`는 단일 `.obj`를 base 0 raw `.text`로 먹여서
image base/reloc/.rdata가 없어 **Ghidra 자신도** jump table 복구에 실패하고
CALLIND로 폴백했다(truncateIndirectJump). 이 corpus는 그 반대다: **완전히
링크된 PE32+ 실행 이미지**를 만들어 image base(0x140000000)를 해결하고 jump
table을 실제 섹션에 배치한다. 그래서 Ghidra가 **진짜 `switch`로 복구**한다.
Component 1이 포팅한 truncateIndirectJump 폴백이 아니라, 진짜 switch 복구
경로(ActionSwitchNorm + JumpBasic)를 파리티 안에서 검증할 입력이다.

## 파이프라인 (별도 골든)

```
py -3 testdata/x64_switch/build.py        # switch.c -> switch.exe (MSVC cl /Od /GS- + link /NODEFAULTLIB)
py -3 testdata/x64_switch/run_ghidra.py   # exe -> Ghidra 12 헤드리스 -> x64_switch_goldens.json
```

- `GenGoldens.java`는 `../x64_corpus`의 것을 그대로 재사용(제네릭 덤퍼).
- `switch.exe`/`switch.obj`는 gitignore(root `*.exe`/`*.obj`). 함수 바이트는 골든
  JSON에 들어간다. **단, 아래 "골든 스키마 한계" 참고**: jump table 바이트는
  골든에 들어가지 않는다.

## 함수

- `op_switch(long sel, long a, long b)` -- dense 0..7 switch. case마다 **서로 다른**
  연산(add/sub/mul/xor/or/and/shl/sar)이라 상수 value-lookup table로 접히지 않고
  **code jump table**(8개 case 블록으로의 BRANCHIND)로 lowering된다.
- `entry(void)` -- freestanding 진입점. `op_switch(3,7,2)`를 호출해 dead-strip 방지.
  CRT/import 없음.

## 빌드 결과 (측정)

- `switch.exe` 2560 bytes, PE32+, image base 0x140000000, imports 0개.
- 섹션: `.text`(RVA 0x1000, 0xfe), `.rdata`(0x2000, 0xc4), `.pdata`(0x3000, 0x18).
- **jump table은 `.text` 안에 있다**(VA 0x1400010B8, `op_switch` ret 바로 뒤).
  8개 4-byte **RVA** 엔트리: 0x1039 0x1047 0x1055 0x1060 0x106E 0x107C 0x108A
  0x109C. target VA = imageBase + RVA.
- dispatch 코드:
  ```
  cmp [rsp],7 ; ja default
  movsxd rax,[rsp]
  lea   rcx,[0x140000000]            ; __ImageBase (절대 imm)
  mov   eax,[rcx+rax*4+0x10B8]       ; table[sel] = RVA
  add   rax,rcx ; jmp rax            ; BRANCHIND, target = imageBase + RVA
  ```
- table 엔트리가 image-relative(RVA)이므로 엔트리 자체에는 base relocation이
  없다. image base는 `lea rcx,[0x140000000]` 절대 imm으로 코드에 박혀 있다.

## Ghidra 골든 (진짜 switch 복구 확정)

analyzeHeadless 로그에 `Decompiler Switch Analysis` 통과, `FUN_140001000`(184
bytes) + `entry`(30 bytes) 덤프. `.exe`는 stripped(freestanding link)라 이름이
`FUN_140001000`. 복구된 C:

```c
uint FUN_140001000(undefined4 param_1,uint param_2,uint param_3)
{
  uint uVar1;
  switch(param_1) {
  case 0: uVar1 = param_2 + param_3; break;
  case 1: uVar1 = param_2 - param_3; break;
  case 2: uVar1 = param_2 * param_3; break;
  case 3: uVar1 = param_2 ^ param_3; break;
  case 4: uVar1 = param_2 | param_3; break;
  case 5: uVar1 = param_2 & param_3; break;
  case 6: uVar1 = param_2 << ((byte)param_3 & 0x1f); break;
  case 7: uVar1 = (int)param_2 >> ((byte)param_3 & 0x1f); break;
  default: uVar1 = 0xffffffff;
  }
  return uVar1;
}
```

## 골든 스키마 한계 (track B 하네스 함의)

`GenGoldens.java`의 함수 body(`AddressSetView`)는 `ret`(0x10B7)에서 끝난다.
**184 bytes 골든 `bytes`에는 jump table(0x10B8~, 32 bytes)이 들어있지 않다.**
따라서 기존 `x64_corpus_diag_test.go`처럼 골든 `bytes`만 base 0으로 먹이는
경로로는 이 함수의 switch를 복구할 수 없다:

1. `lea rcx,[0x140000000]`가 절대 image base를 요구하는데 bytes는 base 0 로드.
2. table 바이트가 fed 범위 밖(0x10B8는 body 끝 0x10B7 이후).

즉 track B 하네스는 골든 bytes가 아니라 **`.exe`에서 직접**(또는 골든을 table
바이트 + image base로 확장해) 로드해야 한다. 로더/복구 스코핑은 팀 리포트 참조.

# D17: disp32 memory + global var access + ESI/EDI + linked-list E2E

## Objective

Add golden fixture coverage for the remaining common x86 memory and register patterns:
1. MOV EAX, [EBX+0x100] (8B 83 00 01 00 00) -- reg + disp32 (large struct field)
2. MOV [EBX+0x100], EAX (89 83 00 01 00 00) -- reg + disp32 write
3. MOV EAX, [0x12345678] (A1 78 56 34 12)   -- absolute address read (global var)
4. MOV [0x12345678], EAX (A3 78 56 34 12)   -- absolute address write
5. PUSH ESI (56) / PUSH EDI (57)             -- callee-save regs (complex function prologues)
6. POP ESI (5E) / POP EDI (5F)              -- callee-restore
7. MOV ESI, EAX (89 C6)                     -- move to/from ESI

Plus a linked-list-style E2E: a function that traverses a singly linked list.

## Why

After D16 (88 golden subtests), remaining gaps for real compiled C:
- disp32 [reg+offset32]: Used when struct fields are at offsets >= 128 bytes, or for
  large vtable slots. Any non-trivial struct will have some fields beyond disp8 range.
- Absolute memory [addr32]: Every global variable access uses this form. Without it,
  any function that reads/writes a global variable cannot be decompiled.
- ESI/EDI: These are callee-saved registers in cdecl. Any function that uses more than
  3 local variables or iterates over arrays will push ESI/EDI and use them as loop
  variables. Without ESI/EDI golden fixtures, complex function prologues are broken.
- Linked-list traversal: This exercises pointer chasing ([EAX] -> next field -> [EAX]),
  combining struct access, pointer loads, and a loop -- the canonical real-world pattern.

## Part 1: Golden fixtures

### MOV EAX, [EBX+0x100] -- reg + disp32 read
  {"x86_MOV_EAX_EBX_disp32", []byte{0x8B, 0x83, 0x00, 0x01, 0x00, 0x00}},

ModRM 0x83 = mod=10 (disp32), reg=0 (EAX=dst), rm=3 (EBX=base). disp32=0x100.
Expected: LOAD([EBX + 256]) -> EAX. 1 op.

### MOV [EBX+0x100], EAX -- reg + disp32 write
  {"x86_MOV_EBX_disp32_EAX", []byte{0x89, 0x83, 0x00, 0x01, 0x00, 0x00}},

ModRM 0x83 = mod=10 (disp32), reg=0 (EAX=src), rm=3 (EBX=base). disp32=0x100.
Expected: STORE(EAX -> [EBX + 256]). 1 op.

### MOV EAX, [0x12345678] -- absolute address (global var read)
  {"x86_MOV_EAX_abs32", []byte{0xA1, 0x78, 0x56, 0x34, 0x12}},

Opcode A1: MOV EAX, moffs32. Reads from absolute 32-bit address 0x12345678.
Expected: LOAD([0x12345678]) -> EAX. 1-2 ops.

### MOV [0x12345678], EAX -- absolute address write (global var write)
  {"x86_MOV_abs32_EAX", []byte{0xA3, 0x78, 0x56, 0x34, 0x12}},

Opcode A3: MOV moffs32, EAX. Writes to absolute 32-bit address 0x12345678.
Expected: STORE(EAX -> [0x12345678]). 1-2 ops.

### PUSH ESI / POP ESI
  {"x86_PUSH_ESI", []byte{0x56}},  // PUSH ESI (opcode 56)
  {"x86_POP_ESI",  []byte{0x5E}},  // POP ESI (opcode 5E)

Expected: same pattern as PUSH/POP EBX (already done). ~2-3 ops each.

### PUSH EDI / POP EDI
  {"x86_PUSH_EDI", []byte{0x57}},  // PUSH EDI (opcode 57)
  {"x86_POP_EDI",  []byte{0x5F}},  // POP EDI (opcode 5F)

Expected: same as above. ~2-3 ops each.

### MOV ESI, EAX
  {"x86_MOV_ESI_EAX", []byte{0x89, 0xC6}},  // MOV ESI, EAX (ModRM 0xC6 = mod=11,reg=0,rm=6)

Expected: COPY(EAX -> ESI). 1 op.

Total golden subtests after D17: >= 97 (88 + 9 = 97)

## Part 2: E2E linked-list traversal

Add TestX86LinkedListFunction to pkg/loader/loader_test.go.

A function that sums a linked list:

struct Node { int val; struct Node *next; };
int sum_list(struct Node *head) {
    int total = 0;
    while (head != NULL) {
        total += head->val;   // [head+0]
        head = head->next;    // [head+4]
    }
    return total;
}

Assembly (simplified, using EAX=head, EDX=total):
  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 8B 45 08        MOV EAX, [EBP+8]    (head)
  0x06: 31 D2           XOR EDX, EDX        (total = 0)
  0x08: 85 C0           TEST EAX, EAX       (head == NULL?)
  0x0A: 74 0C           JE +12              (exit loop)
  0x0C: 03 10           ADD EDX, [EAX]      (total += head->val)
  0x0E: 8B 40 04        MOV EAX, [EAX+4]   (head = head->next)
  0x11: 85 C0           TEST EAX, EAX       (head == NULL?)
  0x13: 75 F7           JNE -9              (loop back to 0x0C)
  0x15: 89 D0           MOV EAX, EDX        (return total)
  0x17: 5D              POP EBP
  0x18: C3              RET
  Total: 25 bytes

Note: 0x03 0x10 = ADD EDX, [EAX]. ModRM 0x10 = mod=00(no disp), reg=2(EDX), rm=0(EAX).
This is a new opcode form: ADD r32, r/m32 from memory. If ADD EAX, [EAX] is not yet
covered by golden fixtures, this E2E will exercise it. Accept if test passes.

Bytes:
{0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08,
 0x31, 0xD2, 0x85, 0xC0, 0x74, 0x0C,
 0x03, 0x10, 0x8B, 0x40, 0x04,
 0x85, 0xC0, 0x75, 0xF7,
 0x89, 0xD0, 0x5D, 0xC3}

Assertions:
- len(result.Instructions) >= 8
- result.Graph.GetSize() >= 3 (loop: entry + body + exit = at least 3 blocks)
- Heritage + pipeline runs without error
- PrintC output non-empty
- t.Logf("sum_list C output:\n%s", output)

## In-scope

1. pkg/sla/x86_golden_test.go: add 9 fixtures listed above
2. testdata/golden/: 9 new JSON fixture files
3. pkg/loader/loader_test.go: TestX86LinkedListFunction
4. Fix any decode gaps for disp32, A1/A3 opcodes, ESI/EDI registers
5. docs/STATUS.md + docs/X86_ROADMAP.md updates

## Out-of-scope

- EDX/ESP/EBP as PUSH/POP (ESP/EBP are special; EDX already has golden via D6)
- disp32 with SIB (already have disp8+SIB from D16)
- Far absolute address (segment:offset form)
- FPU/SSE
- 64-bit

## Invariants

- All existing tests pass (88 golden subtests, 15 E2E tests)
- New golden fixtures >= 1 op each
- TestX86LinkedListFunction must NOT skip
- No new external dependencies
- ASCII-only, tabs for indentation, English comments

## Done when

- go test ./pkg/sla/... -run TestGoldenX86 passes with >= 97 subtests
- go test ./pkg/loader/... -run TestX86LinkedListFunction passes with non-empty PrintC
- go test ./... passes green

# SLA Boundary Decode

## 목적

`pkg/sla`의 현재 구현은 `.sla` 전체 semantics를 복원하지 않는다.
대신 아래 경계를 안정적으로 복원하는 것을 목표로 한다.

- outer container header + zlib payload
- packed marshal tree
- `<sleigh>` top-level metadata
- `<sourcefiles>`
- `<symbol_table>`의 scope/header/body pairing
- `<subtable_sym>` 내부의 constructor list
- `<construct_tpl>` 내부의 handle/varnode/op template 경계
- `<decision>` tree 골격과 disjoint pattern subtree
- pattern symbol body의 `PatternExpression` 최소 트리

이 단계의 목적은 `constructor tree`와 `symbol table`의 전체 구조를 잃지 않고 읽는 것이다.
이제 `PatternExpression`, `DisjointPattern`, `ConstructTpl`의 경계 트리는 복원하지만, semantics 자체를 실행 가능한 의미로 해석하지는 않는다.

## C++ 기준

참조 구현 기준 경계는 아래 파일에 있다.

- `ghidra-ref/.../slaformat.hh/.cc`
- `ghidra-ref/.../marshal.hh/.cc`
- `ghidra-ref/.../slghsymbol.hh/.cc`
- `ghidra-ref/.../sleighbase.cc`

핵심 decode 흐름:

1. `FormatDecode::ingestStream()`가 `.sla` header 검증 후 압축을 해제한다.
2. `SleighBase::decode()`가 `<sleigh>` root attributes를 읽는다.
3. `SourceFileIndexer::decode()`가 `<sourcefiles>`를 읽는다.
4. `decodeSlaSpaces()`가 `<spaces>`를 읽는다.
5. `symtab.decode()`가 `<symbol_table>`를 읽는다.
6. `SymbolTable::decode()`는 먼저 scope를 만들고, 그 다음 symbol header shells를 만든다.
7. 이후 symbol body를 id 순서로 다시 읽으며 shell에 내용을 채운다.
8. `SubtableSymbol::decode()`는 constructor들과 decision tree를 복원한다.

## 현재 Go 구현 범위

현재 Go 쪽은 아래까지만 decode 한다.

- `<sourcefile name index>`
- `<scope id parent>`
- symbol header: `name`, `id`, `scope`
- `userop` body: `index`
- 일부 pattern-backed symbol body: `PatternExpression` 최소 트리
- `subtable_sym` body: `numct`, constructor list, decision tree
- constructor boundary:
  - `parent`, `first`, `length`, `source`, `line`
  - operand symbol ids
  - print pieces / operand print refs
  - context op expression subtree
  - context commit fields
  - main section `ConstructTpl`
  - named section `ConstructTpl`
- `ConstructTpl` boundary:
  - `section`, `delay`, `labels`
  - result `HandleTpl`
  - `OpTpl` list
  - `ConstTpl` / `VarnodeTpl` / `HandleTpl` 내부 상수 경계
- decision boundary:
  - `number`, `context`, `startbit`, `size`
  - pair의 constructor id
  - pair 아래 `DisjointPattern` 최소 트리
  - child decision nodes

아직 하지 않는 것:

- symbol body별 full semantic decode
- `PatternExpression` 평가와 symbol/context binding
- `DisjointPattern`의 실제 매칭 실행
- `ConstructTpl`에서 실행 가능한 raw p-code emission 생성
- constructor semantics 실행 가능 상태 복원

## 중요한 설계 결정

이번 단계에서는 symbol body를 두 층으로 나눈다.

- 해석하는 body
  - `userop`
  - `subtable_sym`
- opaque로 보존하는 body
  - 나머지 symbol 종류 전부

이렇게 한 이유는 다음과 같다.

- `symbol shell/body pairing`은 constructor decode보다 먼저 정확해야 한다.
- 하지만 모든 symbol semantics를 한 번에 해석하면 범위가 너무 커진다.
- `subtable -> constructor -> decision`만 먼저 읽어도 이후 decode 실행 경로 설계에 필요한 골격은 확보된다.

## 다음 단계

다음 구현 단위는 아래 순서가 맞다.

1. `ConstructTplBoundary`를 `pkg/pcode.RawOp` 계층으로 연결하는 emitter 초안 추가
2. `PatternExpression` / `DisjointPattern`를 실행 가능한 matcher 입력 모델로 낮추기
3. constructor 선택과 section dispatch를 묶는 첫 translator 경계 정의

즉 boundary decode 단계는 이번에 끝났고, 다음부터는 `실행` 가능한 decode/runtime 단계로 넘어간다.
현재는 그 첫 단계로, 고립된 `ConstructTplBoundary` 하나를 `pkg/pcode.RawOp` 목록으로 낮추는 보수적 lowering이 추가되어 있다.

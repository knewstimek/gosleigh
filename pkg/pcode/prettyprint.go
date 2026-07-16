package pcode

// Faithful port of Ghidra's Derek C. Oppen pretty-printer.
//
// C++ parity: prettyprint.hh / prettyprint.cc, classes Emit, EmitNoMarkup,
// TokenSplit, circularqueue and EmitPrettyPrint. The algorithm buffers a stream
// of content tokens plus begin/end group and line-break commands, computes the
// size of each printing group, and inserts line breaks so that no line exceeds
// maxlinesize characters (default 100).
//
// Integration note (why this diverges structurally from the C++):
//   Gosleigh's PrintC builds whole sub-expressions as flat Go strings and feeds
//   them to the emitter as opaque content tokens, with the statement-level
//   structure (lhs, "=", rhs, ";", spaces, newlines, indent) arriving through
//   the TokenEmitter interface. So the token stream this port receives is
//   coarser than Ghidra's fully nested RPN stream: a sub-expression is one
//   tokenstring rather than a tree of grouped tokens. The Oppen core is ported
//   verbatim; only the token *granularity* differs. For the current golden set
//   the coarser stream reproduces Ghidra's break decisions exactly because the
//   only break that fires (the assignment "=" of an overlong store/assign
//   statement) sits between two whitespace break tokens with a content token
//   ("=") in between, which is enough for the Oppen size accounting to place the
//   break after "=" just as Ghidra does.
//
// Output/indentation note:
//   The project's Ghidra goldens are stored with leading indentation stripped
//   (see testdata/ghidra_golden/ghidra_golden.json and normGhidraC in the
//   loader tests), and PrintC in Ghidra-format mode emits no leading indent.
//   To stay byte-identical with that convention, the low-level sink here reuses
//   TextEmitter's exact indent/space/newline semantics and ignores the Oppen
//   continuation-indent value; the Oppen core only DECIDES where newlines go.
//   Consequently the break threshold is measured against the emitted (un-indented)
//   line width, i.e. indentincrement is 0. Ghidra measures against the indented
//   width; the two agree on every current golden (only bump_scores wraps, and it
//   wraps under both). This is the deliberate, documented parity compromise
//   forced by the un-indented golden convention.

const ppMaxLineSizeDefault = 100
const ppLineForce = 999999 // TokenSplit numspaces for a forced line break

// ppPrintClass is TokenSplit::printclass: the broad category driving the
// pretty-printing state machine.
type ppPrintClass int

const (
	ppBegin ppPrintClass = iota
	ppEnd
	ppTokenstring
	ppTokenbreak
	ppBeginIndent
	ppEndIndent
	ppBeginComment
	ppEndComment
	ppIgnore
)

// ppTagType is TokenSplit::tag_type, narrowed to the tags Gosleigh's emit path
// actually produces. line_t must remain distinguishable from spac_t/bump_t
// because the break path treats it as an absolute (rather than relative) indent.
type ppTagType int

const (
	ppTagContent    ppTagType = iota // synt_t / vari_t / op_t ...: actual content
	ppTagSpaces                      // spac_t: whitespace break
	ppTagBump                        // bump_t: forced break (tagLine) or indent delimiter
	ppTagLineIndent                  // line_t: forced break with one-time absolute indent
	ppTagBegin                       // docu_b / oinv_t: group begin
	ppTagEnd                         // docu_e / cinv_t: group end
)

// ppToken is a TokenSplit. Only the fields used by the ported algorithm are kept.
type ppToken struct {
	tagtype    ppTagType
	delimtype  ppPrintClass
	tok        string
	indentbump int
	numspaces  int
	size       int
	count      int
}

// ppCircQueueTok is circularqueue<TokenSplit>: a ring that doubles as stack and
// queue. Slots are reused in place (push returns an index into the backing array)
// so that scanqueue references remain valid, matching the C++ pointer semantics.
type ppCircQueueTok struct {
	cache      []ppToken
	left, righ int
	max        int
}

func newPPCircQueueTok(sz int) *ppCircQueueTok {
	return &ppCircQueueTok{cache: make([]ppToken, sz), left: 1, righ: 0, max: sz}
}
func (q *ppCircQueueTok) setMax(sz int) {
	if q.max != sz {
		q.cache = make([]ppToken, sz)
		q.max = sz
	}
	q.left = 1
	q.righ = 0
}
func (q *ppCircQueueTok) getMax() int        { return q.max }
func (q *ppCircQueueTok) clear()             { q.left = 1; q.righ = 0 }
func (q *ppCircQueueTok) empty() bool        { return q.left == (q.righ+1)%q.max }
func (q *ppCircQueueTok) topref() int        { return q.righ }
func (q *ppCircQueueTok) botref() int        { return q.left }
func (q *ppCircQueueTok) ref(r int) *ppToken { return &q.cache[r] }
func (q *ppCircQueueTok) top() *ppToken      { return &q.cache[q.righ] }
func (q *ppCircQueueTok) bottom() *ppToken   { return &q.cache[q.left] }

// push advances right and returns the (reset) slot for the caller to fill.
func (q *ppCircQueueTok) push() *ppToken {
	q.righ = (q.righ + 1) % q.max
	q.cache[q.righ] = ppToken{}
	return &q.cache[q.righ]
}
func (q *ppCircQueueTok) pop() *ppToken {
	tmp := q.righ
	q.righ = (q.righ + q.max - 1) % q.max
	return &q.cache[tmp]
}
func (q *ppCircQueueTok) popbottom() *ppToken {
	tmp := q.left
	q.left = (q.left + 1) % q.max
	return &q.cache[tmp]
}
func (q *ppCircQueueTok) expand(amount int) {
	newcache := make([]ppToken, q.max+amount)
	i := q.left
	j := 0
	for i != q.righ {
		newcache[j] = q.cache[i]
		j++
		i = (i + 1) % q.max
	}
	newcache[j] = q.cache[i] // copy rightmost
	q.left = 0
	q.righ = j
	q.cache = newcache
	q.max += amount
}

// ppCircQueueInt is circularqueue<int4>: the scan queue of open/whitespace refs.
type ppCircQueueInt struct {
	cache      []int
	left, righ int
	max        int
}

func newPPCircQueueInt(sz int) *ppCircQueueInt {
	return &ppCircQueueInt{cache: make([]int, sz), left: 1, righ: 0, max: sz}
}
func (q *ppCircQueueInt) setMax(sz int) {
	if q.max != sz {
		q.cache = make([]int, sz)
		q.max = sz
	}
	q.left = 1
	q.righ = 0
}
func (q *ppCircQueueInt) clear()         { q.left = 1; q.righ = 0 }
func (q *ppCircQueueInt) empty() bool    { return q.left == (q.righ+1)%q.max }
func (q *ppCircQueueInt) topref() int    { return q.righ }
func (q *ppCircQueueInt) ref(r int) *int { return &q.cache[r] }
func (q *ppCircQueueInt) top() int       { return q.cache[q.righ] }
func (q *ppCircQueueInt) push() *int {
	q.righ = (q.righ + 1) % q.max
	return &q.cache[q.righ]
}
func (q *ppCircQueueInt) pop() int {
	tmp := q.righ
	q.righ = (q.righ + q.max - 1) % q.max
	return q.cache[tmp]
}
func (q *ppCircQueueInt) popbottom() int {
	tmp := q.left
	q.left = (q.left + 1) % q.max
	return q.cache[tmp]
}
func (q *ppCircQueueInt) expand(amount int) {
	newcache := make([]int, q.max+amount)
	i := q.left
	j := 0
	for i != q.righ {
		newcache[j] = q.cache[i]
		j++
		i = (i + 1) % q.max
	}
	newcache[j] = q.cache[i]
	q.left = 0
	q.righ = j
	q.cache = newcache
	q.max += amount
}

// PrettyEmitter is EmitPrettyPrint. It implements TokenEmitter and delegates the
// actual character output to an embedded TextEmitter (the EmitNoMarkup analogue),
// only inserting line breaks to keep lines within maxlinesize.
type PrettyEmitter struct {
	sink *TextEmitter // low-level character sink (EmitNoMarkup analogue)

	indentstack []int
	spaceremain int
	maxlinesize int
	leftotal    int
	rightotal   int
	needbreak   bool
	countbase   int

	scanqueue *ppCircQueueInt
	tokqueue  *ppCircQueueTok
}

// NewPrettyEmitter builds a pretty-printing emitter whose sink uses the given
// indent unit (matching TextEmitter's semantics) and the given maximum line size.
func NewPrettyEmitter(indentUnit string, maxLineSize int) *PrettyEmitter {
	if maxLineSize < 20 {
		maxLineSize = ppMaxLineSizeDefault
	}
	e := &PrettyEmitter{
		sink:        NewTextEmitterWithIndent(indentUnit),
		maxlinesize: maxLineSize,
		scanqueue:   newPPCircQueueInt(3 * maxLineSize),
		tokqueue:    newPPCircQueueTok(3 * maxLineSize),
	}
	e.spaceremain = maxLineSize
	e.beginDocument()
	return e
}

// --- Oppen core (EmitPrettyPrint::expand/overflow/print/advanceleft/scan) ---

func (e *PrettyEmitter) expand() {
	max := e.tokqueue.getMax()
	left := e.tokqueue.botref()
	e.tokqueue.expand(200)
	for i := 0; i < max; i++ {
		*e.scanqueue.ref(i) = (*e.scanqueue.ref(i) + max - left) % max
	}
	e.scanqueue.expand(200)
}

// overflow permanently bumps active indent levels to guarantee at least half a
// line of space, then issues a line break. C++ parity: EmitPrettyPrint::overflow.
func (e *PrettyEmitter) overflow() {
	half := e.maxlinesize / 2
	for i := len(e.indentstack) - 1; i >= 0; i-- {
		if e.indentstack[i] < half {
			e.indentstack[i] = half
		} else {
			break
		}
	}
	var newspaceremain int
	if len(e.indentstack) != 0 {
		newspaceremain = e.indentstack[len(e.indentstack)-1]
	} else {
		newspaceremain = e.maxlinesize
	}
	if newspaceremain == e.spaceremain {
		return
	}
	e.spaceremain = newspaceremain
	e.sinkTagLine()
}

// print emits a single fully-scanned token to the sink, adjusting the indent
// stack and remaining space. C++ parity: EmitPrettyPrint::print(TokenSplit).
func (e *PrettyEmitter) print(tok *ppToken) {
	val := 0
	switch tok.delimtype {
	case ppIgnore:
		e.sinkPrintToken(tok)
	case ppBeginIndent:
		val = e.indentstack[len(e.indentstack)-1] - tok.indentbump
		e.indentstack = append(e.indentstack, val)
		e.sink.Indent() // drive the sink's visible indentation (TextEmitter parity)
	case ppBeginComment, ppBegin:
		e.sinkPrintToken(tok)
		e.indentstack = append(e.indentstack, e.spaceremain)
	case ppEndIndent:
		e.indentstack = e.indentstack[:len(e.indentstack)-1]
		e.sink.Dedent()
	case ppEndComment, ppEnd:
		e.sinkPrintToken(tok)
		e.indentstack = e.indentstack[:len(e.indentstack)-1]
	case ppTokenstring:
		if tok.size > e.spaceremain {
			e.overflow()
		}
		e.sinkPrintToken(tok)
		e.spaceremain -= tok.size
	case ppTokenbreak:
		if tok.size > e.spaceremain {
			if tok.tagtype == ppTagLineIndent { // absolute indent
				e.spaceremain = e.maxlinesize - tok.indentbump
			} else { // relative indent
				val = e.indentstack[len(e.indentstack)-1] - tok.indentbump
				// If a line break here saves little space, keep the spaces.
				if tok.numspaces <= e.spaceremain && val-e.spaceremain < 10 {
					e.sinkSpaces(tok.numspaces)
					e.spaceremain -= tok.numspaces
					return
				}
				e.indentstack[len(e.indentstack)-1] = val
				e.spaceremain = val
			}
			e.sinkTagLine()
		} else {
			e.sinkSpaces(tok.numspaces)
			e.spaceremain -= tok.numspaces
		}
	}
}

// advanceleft flushes tokens whose group size is now known (>= 0).
// C++ parity: EmitPrettyPrint::advanceleft.
func (e *PrettyEmitter) advanceleft() {
	l := e.tokqueue.bottom().size
	for l >= 0 {
		tok := e.tokqueue.bottom()
		e.print(tok)
		switch tok.delimtype {
		case ppTokenbreak:
			e.leftotal += tok.numspaces
		case ppTokenstring:
			e.leftotal += l
		}
		e.tokqueue.popbottom()
		if e.tokqueue.empty() {
			break
		}
		l = e.tokqueue.bottom().size
	}
}

// scan processes the token just pushed on top of tokqueue. This is the heart of
// the Oppen algorithm. C++ parity: EmitPrettyPrint::scan.
func (e *PrettyEmitter) scan() {
	if e.tokqueue.empty() {
		e.expand()
	}
	tok := e.tokqueue.top()
	switch tok.delimtype {
	case ppBeginComment, ppBegin:
		if e.scanqueue.empty() {
			e.leftotal = 1
			e.rightotal = 1
		}
		tok.size = -e.rightotal
		*e.scanqueue.push() = e.tokqueue.topref()
	case ppEndComment, ppEnd:
		tok.size = 0
		if !e.scanqueue.empty() {
			ref := e.tokqueue.ref(e.scanqueue.pop())
			ref.size += e.rightotal
			if ref.delimtype == ppTokenbreak && !e.scanqueue.empty() {
				ref2 := e.tokqueue.ref(e.scanqueue.pop())
				ref2.size += e.rightotal
			}
			if e.scanqueue.empty() {
				e.advanceleft()
			}
		}
	case ppTokenbreak:
		if e.scanqueue.empty() {
			e.leftotal = 1
			e.rightotal = 1
		} else {
			ref := e.tokqueue.ref(e.scanqueue.top())
			if ref.delimtype == ppTokenbreak {
				e.scanqueue.pop()
				ref.size += e.rightotal
			}
		}
		tok.size = -e.rightotal
		*e.scanqueue.push() = e.tokqueue.topref()
		e.rightotal += tok.numspaces
	case ppBeginIndent, ppEndIndent, ppIgnore:
		tok.size = 0
	case ppTokenstring:
		if !e.scanqueue.empty() {
			e.rightotal += tok.size
			for e.rightotal-e.leftotal > e.spaceremain {
				e.tokqueue.ref(e.scanqueue.popbottom()).size = ppLineForce
				e.advanceleft()
				if e.scanqueue.empty() {
					break
				}
			}
		}
	}
}

// --- whitespace-enforcement helpers (checkstart/checkstring/checkend/checkbreak) ---

func (e *PrettyEmitter) checkstart() {
	if e.needbreak {
		tok := e.tokqueue.push()
		e.setSpaces(tok, 0, 0)
		e.scan()
	}
	e.needbreak = false
}

func (e *PrettyEmitter) checkstring() {
	if e.needbreak {
		tok := e.tokqueue.push()
		e.setSpaces(tok, 0, 0)
		e.scan()
	}
	e.needbreak = true
}

func (e *PrettyEmitter) checkend() {
	if !e.needbreak {
		tok := e.tokqueue.push()
		e.setContent(tok, "")
		e.scan()
	}
	e.needbreak = true
}

func (e *PrettyEmitter) checkbreak() {
	if !e.needbreak {
		tok := e.tokqueue.push()
		e.setContent(tok, "")
		e.scan()
	}
	e.needbreak = false
}

// --- token constructors (TokenSplit setters) ---

func (e *PrettyEmitter) setContent(tok *ppToken, s string) {
	tok.tok = s
	tok.size = len(s)
	tok.tagtype = ppTagContent
	tok.delimtype = ppTokenstring
}

func (e *PrettyEmitter) setSpaces(tok *ppToken, num, bump int) {
	tok.tagtype = ppTagSpaces
	tok.delimtype = ppTokenbreak
	tok.numspaces = num
	tok.indentbump = bump
}

func (e *PrettyEmitter) setTagLine(tok *ppToken) {
	tok.tagtype = ppTagBump
	tok.delimtype = ppTokenbreak
	tok.numspaces = ppLineForce
	tok.indentbump = 0
}

// --- Emit-level operations (EmitPrettyPrint public API subset) ---

func (e *PrettyEmitter) beginDocument() int {
	e.checkstart()
	tok := e.tokqueue.push()
	tok.tagtype = ppTagBegin
	tok.delimtype = ppBegin
	tok.size = 0
	e.countbase++
	tok.count = e.countbase
	id := tok.count
	e.scan()
	return id
}

func (e *PrettyEmitter) endDocument() {
	e.checkend()
	tok := e.tokqueue.push()
	tok.tagtype = ppTagEnd
	tok.delimtype = ppEnd
	tok.size = 0
	e.scan()
}

func (e *PrettyEmitter) contentToken(s string) {
	e.checkstring()
	tok := e.tokqueue.push()
	e.setContent(tok, s)
	e.scan()
}

func (e *PrettyEmitter) spacesToken(num, bump int) {
	e.checkbreak()
	tok := e.tokqueue.push()
	e.setSpaces(tok, num, bump)
	e.scan()
}

func (e *PrettyEmitter) tagLine() {
	e.checkbreak()
	tok := e.tokqueue.push()
	e.setTagLine(tok)
	e.scan()
}

func (e *PrettyEmitter) startIndent() {
	tok := e.tokqueue.push()
	tok.tagtype = ppTagBump
	tok.delimtype = ppBeginIndent
	tok.indentbump = 2 // indentincrement (Emit::resetDefaultsInternal)
	tok.size = 0
	e.countbase++
	tok.count = e.countbase
	e.scan()
}

func (e *PrettyEmitter) stopIndent() {
	tok := e.tokqueue.push()
	tok.tagtype = ppTagBump
	tok.delimtype = ppEndIndent
	tok.size = 0
	e.scan()
}

func (e *PrettyEmitter) flush() {
	for !e.tokqueue.empty() {
		tok := e.tokqueue.popbottom()
		e.print(tok)
	}
	e.needbreak = false
}

// --- low-level sink delegation (reuse TextEmitter's exact semantics) ---
//
// The Oppen core hands finished tokens to these methods, which reproduce
// TextEmitter's byte-for-byte behaviour so that non-wrapping output is identical
// to the previous emitter. The Oppen continuation-indent is intentionally
// discarded; the sink applies its own indentLevel-based indentation.

func (e *PrettyEmitter) sinkPrintToken(tok *ppToken) {
	if tok.delimtype == ppTokenstring {
		// TextEmitter.Emit is a no-op for "" and (since content tokens never
		// contain newlines) writes the token with TextEmitter's pending-space
		// and indent-prefix semantics -- byte-identical to the old path.
		e.sink.Emit(tok.tok)
	}
	// begin/end/ignore group tokens carry no characters in the no-markup sink.
}

func (e *PrettyEmitter) sinkSpaces(num int) {
	for i := 0; i < num; i++ {
		e.sink.Space()
	}
}

func (e *PrettyEmitter) sinkTagLine() {
	e.sink.Newline()
}

// --- TokenEmitter interface ---

func (e *PrettyEmitter) Emit(text string) {
	if text == "" {
		return
	}
	// Mirror TextEmitter.Emit: embedded newlines become tagLine breaks.
	start := 0
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			if i > start {
				e.contentToken(text[start:i])
			}
			e.tagLine()
			start = i + 1
		}
	}
	if start < len(text) {
		e.contentToken(text[start:])
	}
}

func (e *PrettyEmitter) Space()   { e.spacesToken(1, 0) }
func (e *PrettyEmitter) Newline() { e.tagLine() }
func (e *PrettyEmitter) Indent()  { e.startIndent() }
func (e *PrettyEmitter) Dedent()  { e.stopIndent() }

func (e *PrettyEmitter) Reset() {
	e.sink.Reset()
	e.indentstack = e.indentstack[:0]
	e.scanqueue.clear()
	e.tokqueue.clear()
	e.leftotal = 1
	e.rightotal = 1
	e.needbreak = false
	e.spaceremain = e.maxlinesize
	e.countbase = 0
	e.beginDocument()
}

func (e *PrettyEmitter) String() string {
	e.endDocument()
	e.flush()
	return e.sink.String()
}

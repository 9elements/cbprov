package cbfs

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// LZMA in coreboot's "ulzman" container: 5 property bytes, 64-bit LE
// uncompressed size, raw LZMA stream without end marker.

const (
	lzmaNumStates      = 12
	lzmaPosBitsMax     = 4
	lzmaLenToPosStates = 4
	lzmaEndPosModel    = 14
	lzmaFullDistances  = 1 << (lzmaEndPosModel >> 1)
	lzmaAlignBits      = 4
	lzmaMatchMin       = 2
	lzmaMatchMax       = 273
	lzmaProbInit       = 1024
	lzmaHeaderSize     = 13
)

// Encoder settings of cbfstool's do_lzma_compress(). lc+lp must stay <= 3:
// coreboot's ulzman() has a fixed 15980 byte probability scratchpad.
const (
	lzmaLC = 1
	lzmaLP = 0
	lzmaPB = 0
)

var errLZMACorrupt = errors.New("lzma: corrupt stream")

type lenProbs struct {
	choice, choice2 uint16
	low, mid        [1 << lzmaPosBitsMax][1 << 3]uint16
	high            [1 << 8]uint16
}

type lzmaProbs struct {
	lit        []uint16
	isMatch    [lzmaNumStates << lzmaPosBitsMax]uint16
	isRep      [lzmaNumStates]uint16
	isRepG0    [lzmaNumStates]uint16
	isRepG1    [lzmaNumStates]uint16
	isRepG2    [lzmaNumStates]uint16
	isRep0Long [lzmaNumStates << lzmaPosBitsMax]uint16
	posSlot    [lzmaLenToPosStates][1 << 6]uint16
	posSpec    [1 + lzmaFullDistances - lzmaEndPosModel]uint16
	align      [1 << lzmaAlignBits]uint16
	length     lenProbs
	repLen     lenProbs
}

func newLZMAProbs(lc, lp uint) *lzmaProbs {
	p := &lzmaProbs{lit: make([]uint16, 0x300<<(lc+lp))}
	fill := func(s []uint16) {
		for i := range s {
			s[i] = lzmaProbInit
		}
	}
	fill(p.lit)
	fill(p.isMatch[:])
	fill(p.isRep[:])
	fill(p.isRepG0[:])
	fill(p.isRepG1[:])
	fill(p.isRepG2[:])
	fill(p.isRep0Long[:])
	for i := range p.posSlot {
		fill(p.posSlot[i][:])
	}
	fill(p.posSpec[:])
	fill(p.align[:])
	for _, l := range []*lenProbs{&p.length, &p.repLen} {
		l.choice, l.choice2 = lzmaProbInit, lzmaProbInit
		for i := range l.low {
			fill(l.low[i][:])
			fill(l.mid[i][:])
		}
		fill(l.high[:])
	}
	return p
}

func stateAfterLit(s int) int {
	switch {
	case s < 4:
		return 0
	case s < 10:
		return s - 3
	}
	return s - 6
}

func stateAfterMatch(s int) int {
	if s < 7 {
		return 7
	}
	return 10
}

func stateAfterRep(s int) int {
	if s < 7 {
		return 8
	}
	return 11
}

func stateAfterShortRep(s int) int {
	if s < 7 {
		return 9
	}
	return 11
}

// ---- decoder ----

type rangeDec struct {
	in        []byte
	pos       int
	rng, code uint32
	err       error
}

func (d *rangeDec) next() byte {
	if d.pos >= len(d.in) {
		d.err = errors.New("lzma: truncated input")
		return 0
	}
	b := d.in[d.pos]
	d.pos++
	return b
}

func (d *rangeDec) normalize() {
	if d.rng < 1<<24 {
		d.rng <<= 8
		d.code = d.code<<8 | uint32(d.next())
	}
}

func (d *rangeDec) bit(p *uint16) uint32 {
	bound := (d.rng >> 11) * uint32(*p)
	var b uint32
	if d.code < bound {
		*p += (2048 - *p) >> 5
		d.rng = bound
	} else {
		*p -= *p >> 5
		d.code -= bound
		d.rng -= bound
		b = 1
	}
	d.normalize()
	return b
}

func (d *rangeDec) direct(n uint) uint32 {
	var res uint32
	for ; n > 0; n-- {
		d.rng >>= 1
		d.code -= d.rng
		t := 0 - (d.code >> 31)
		d.code += d.rng & t
		d.normalize()
		res = res<<1 + t + 1
	}
	return res
}

func (d *rangeDec) tree(probs []uint16, bits uint) uint32 {
	m := uint32(1)
	for i := uint(0); i < bits; i++ {
		m = m<<1 + d.bit(&probs[m])
	}
	return m - 1<<bits
}

func (d *rangeDec) reverseTree(probs []uint16, bits uint) uint32 {
	m, sym := uint32(1), uint32(0)
	for i := uint(0); i < bits; i++ {
		b := d.bit(&probs[m])
		m = m<<1 + b
		sym |= b << i
	}
	return sym
}

func (d *rangeDec) length(l *lenProbs, posState int) uint32 {
	if d.bit(&l.choice) == 0 {
		return d.tree(l.low[posState][:], 3)
	}
	if d.bit(&l.choice2) == 0 {
		return 8 + d.tree(l.mid[posState][:], 3)
	}
	return 16 + d.tree(l.high[:], 8)
}

// lzmaDecompress decodes an ulzman stream. limit caps the output size.
func lzmaDecompress(src []byte, limit uint64) ([]byte, error) {
	if len(src) < lzmaHeaderSize+5 {
		return nil, errors.New("lzma: input too short")
	}
	props := uint(src[0])
	if props >= 9*5*5 {
		return nil, errors.New("lzma: invalid properties")
	}
	lc, lp, pb := props%9, (props/9)%5, props/45
	size := binary.LittleEndian.Uint64(src[5:13])
	// Like ulzman(), decode at most limit bytes.
	exact := size != ^uint64(0) && size <= limit
	if !exact {
		size = limit
	}
	if size > 1<<31 {
		return nil, fmt.Errorf("lzma: output size %d too large", size)
	}
	d := &rangeDec{in: src[lzmaHeaderSize:], rng: 0xFFFFFFFF}
	if d.next() != 0 {
		return nil, errLZMACorrupt
	}
	for i := 0; i < 4; i++ {
		d.code = d.code<<8 | uint32(d.next())
	}
	if d.code == d.rng {
		return nil, errLZMACorrupt
	}

	p := newLZMAProbs(lc, lp)
	out := make([]byte, 0, size)
	pbMask, lpMask := 1<<pb-1, 1<<lp-1
	var reps [4]uint32
	state := 0
	for uint64(len(out)) < size {
		if d.err != nil {
			return nil, d.err
		}
		posState := len(out) & pbMask
		if d.bit(&p.isMatch[state<<lzmaPosBitsMax+posState]) == 0 {
			var prev byte
			if len(out) > 0 {
				prev = out[len(out)-1]
			}
			lit := p.lit[0x300*((len(out)&lpMask)<<lc+int(prev)>>(8-lc)):]
			sym := uint32(1)
			if state >= 7 {
				if int(reps[0]) >= len(out) {
					return nil, errLZMACorrupt
				}
				mb := uint32(out[len(out)-int(reps[0])-1])
				for sym < 0x100 {
					mbit := (mb >> 7) & 1
					mb <<= 1
					b := d.bit(&lit[(1+mbit)<<8+sym])
					sym = sym<<1 | b
					if mbit != b {
						break
					}
				}
			}
			for sym < 0x100 {
				sym = sym<<1 | d.bit(&lit[sym])
			}
			out = append(out, byte(sym))
			state = stateAfterLit(state)
			continue
		}
		var l uint32
		if d.bit(&p.isRep[state]) == 0 {
			reps[3], reps[2], reps[1] = reps[2], reps[1], reps[0]
			l = d.length(&p.length, posState)
			state = stateAfterMatch(state)
			reps[0] = decodeDist(d, p, l)
			if reps[0] == 0xFFFFFFFF {
				break // end marker
			}
		} else {
			if len(out) == 0 {
				return nil, errLZMACorrupt
			}
			if d.bit(&p.isRepG0[state]) == 0 {
				if d.bit(&p.isRep0Long[state<<lzmaPosBitsMax+posState]) == 0 {
					state = stateAfterShortRep(state)
					if int(reps[0]) >= len(out) {
						return nil, errLZMACorrupt
					}
					out = append(out, out[len(out)-int(reps[0])-1])
					continue
				}
			} else {
				var dist uint32
				if d.bit(&p.isRepG1[state]) == 0 {
					dist = reps[1]
				} else {
					if d.bit(&p.isRepG2[state]) == 0 {
						dist = reps[2]
					} else {
						dist = reps[3]
						reps[3] = reps[2]
					}
					reps[2] = reps[1]
				}
				reps[1] = reps[0]
				reps[0] = dist
			}
			l = d.length(&p.repLen, posState)
			state = stateAfterRep(state)
		}
		n := int(l) + lzmaMatchMin
		if int(reps[0]) >= len(out) {
			return nil, errLZMACorrupt
		}
		if rem := int(size) - len(out); n > rem {
			if exact {
				return nil, errLZMACorrupt
			}
			n = rem
		}
		from := len(out) - int(reps[0]) - 1
		for i := 0; i < n; i++ {
			out = append(out, out[from+i])
		}
	}
	if d.err != nil {
		return nil, d.err
	}
	if exact && uint64(len(out)) != size {
		return nil, errLZMACorrupt
	}
	return out, nil
}

func decodeDist(d *rangeDec, p *lzmaProbs, l uint32) uint32 {
	lenState := min(l, lzmaLenToPosStates-1)
	slot := d.tree(p.posSlot[lenState][:], 6)
	if slot < 4 {
		return slot
	}
	nd := uint(slot>>1) - 1
	dist := (2 | slot&1) << nd
	if slot < lzmaEndPosModel {
		return dist + d.reverseTree(p.posSpec[dist-slot:], nd)
	}
	dist += d.direct(nd-lzmaAlignBits) << lzmaAlignBits
	return dist + d.reverseTree(p.align[:], lzmaAlignBits)
}

// ---- encoder ----

type rangeEnc struct {
	out       []byte
	low       uint64
	rng       uint32
	cache     byte
	cacheSize int
}

func (e *rangeEnc) shiftLow() {
	if uint32(e.low) < 0xFF000000 || e.low>>32 != 0 {
		carry := byte(e.low >> 32)
		temp := e.cache
		for {
			e.out = append(e.out, temp+carry)
			temp = 0xFF
			e.cacheSize--
			if e.cacheSize == 0 {
				break
			}
		}
		e.cache = byte(e.low >> 24)
	}
	e.cacheSize++
	e.low = (e.low & 0x00FFFFFF) << 8
}

func (e *rangeEnc) bit(p *uint16, b uint32) {
	bound := (e.rng >> 11) * uint32(*p)
	if b == 0 {
		e.rng = bound
		*p += (2048 - *p) >> 5
	} else {
		e.low += uint64(bound)
		e.rng -= bound
		*p -= *p >> 5
	}
	for e.rng < 1<<24 {
		e.rng <<= 8
		e.shiftLow()
	}
}

func (e *rangeEnc) direct(v uint32, n uint) {
	for n > 0 {
		n--
		e.rng >>= 1
		if (v>>n)&1 != 0 {
			e.low += uint64(e.rng)
		}
		if e.rng < 1<<24 {
			e.rng <<= 8
			e.shiftLow()
		}
	}
}

func (e *rangeEnc) tree(probs []uint16, bits uint, sym uint32) {
	m := uint32(1)
	for i := bits; i > 0; i-- {
		b := (sym >> (i - 1)) & 1
		e.bit(&probs[m], b)
		m = m<<1 | b
	}
}

func (e *rangeEnc) reverseTree(probs []uint16, bits uint, sym uint32) {
	m := uint32(1)
	for i := uint(0); i < bits; i++ {
		b := sym & 1
		sym >>= 1
		e.bit(&probs[m], b)
		m = m<<1 | b
	}
}

func (e *rangeEnc) length(l *lenProbs, v uint32, posState int) {
	switch {
	case v < 8:
		e.bit(&l.choice, 0)
		e.tree(l.low[posState][:], 3, v)
	case v < 16:
		e.bit(&l.choice, 1)
		e.bit(&l.choice2, 0)
		e.tree(l.mid[posState][:], 3, v-8)
	default:
		e.bit(&l.choice, 1)
		e.bit(&l.choice2, 1)
		e.tree(l.high[:], 8, v-16)
	}
}

// matchFinder is a hash chain over 3-byte prefixes.
type matchFinder struct {
	data     []byte
	head     []int32
	prev     []int32
	inserted int
	depth    int
	nice     int
	maxLen   int
	minLen   int
	hashBits uint
}

func newMatchFinder(data []byte, depth, nice, maxLen, minLen int, maxDist int) *matchFinder {
	hb := uint(16)
	for hb < 20 && 1<<hb < len(data) {
		hb++
	}
	mf := &matchFinder{data: data, head: make([]int32, 1<<hb), depth: depth, nice: nice,
		maxLen: maxLen, minLen: minLen, hashBits: hb}
	if maxDist < len(data) {
		mf.prev = make([]int32, maxDist+1)
	} else {
		mf.prev = make([]int32, len(data))
	}
	for i := range mf.head {
		mf.head[i] = -1
	}
	return mf
}

func (mf *matchFinder) hash(i int) uint32 {
	d := mf.data
	var v uint32
	if mf.minLen >= 4 {
		v = uint32(d[i]) | uint32(d[i+1])<<8 | uint32(d[i+2])<<16 | uint32(d[i+3])<<24
	} else {
		v = uint32(d[i]) | uint32(d[i+1])<<8 | uint32(d[i+2])<<16
	}
	return (v * 2654435761) >> (32 - mf.hashBits)
}

func (mf *matchFinder) insertUpTo(pos int) {
	for ; mf.inserted < pos; mf.inserted++ {
		i := mf.inserted
		if i+mf.minLen > len(mf.data) {
			continue
		}
		h := mf.hash(i)
		mf.prev[i%len(mf.prev)] = mf.head[h]
		mf.head[h] = int32(i)
	}
}

// find returns the longest match at pos (length, distance) with
// pos+length <= end; maxDist bounds the distance.
func (mf *matchFinder) find(pos, end, maxDist int) (int, int) {
	mf.insertUpTo(pos)
	limit := min(mf.maxLen, end-pos)
	if limit < mf.minLen {
		return 0, 0
	}
	d := mf.data
	bestLen, bestDist := 0, 0
	j := mf.head[mf.hash(pos)]
	for n := 0; n < mf.depth && j >= 0; n++ {
		dist := pos - int(j)
		if dist > maxDist || dist > len(mf.prev) {
			break
		}
		if d[int(j)+bestLen] == d[pos+bestLen] {
			l := 0
			for l < limit && d[int(j)+l] == d[pos+l] {
				l++
			}
			if l > bestLen {
				bestLen, bestDist = l, dist
				if l >= mf.nice || l == limit {
					break
				}
			}
		}
		next := mf.prev[int(j)%len(mf.prev)]
		if next >= j {
			break
		}
		j = next
	}
	if bestLen < mf.minLen {
		return 0, 0
	}
	return bestLen, bestDist
}

type lzmaEncoder struct {
	rc    rangeEnc
	p     *lzmaProbs
	data  []byte
	state int
	reps  [4]uint32
}

func (e *lzmaEncoder) literal(i int) {
	posState := i & (1<<lzmaPB - 1)
	e.rc.bit(&e.p.isMatch[e.state<<lzmaPosBitsMax+posState], 0)
	var prev byte
	if i > 0 {
		prev = e.data[i-1]
	}
	lit := e.p.lit[0x300*((i&(1<<lzmaLP-1))<<lzmaLC+int(prev)>>(8-lzmaLC)):]
	b := uint32(e.data[i])
	sym := uint32(1)
	if e.state >= 7 {
		mb := uint32(e.data[i-int(e.reps[0])-1])
		matched := true
		for k := 7; k >= 0; k-- {
			bit := (b >> uint(k)) & 1
			if matched {
				mbit := (mb >> uint(k)) & 1
				e.rc.bit(&lit[(1+mbit)<<8+sym], bit)
				matched = mbit == bit
			} else {
				e.rc.bit(&lit[sym], bit)
			}
			sym = sym<<1 | bit
		}
	} else {
		e.rc.tree(lit, 8, b)
	}
	e.state = stateAfterLit(e.state)
}

func (e *lzmaEncoder) match(i, length, dist int) {
	posState := i & (1<<lzmaPB - 1)
	e.rc.bit(&e.p.isMatch[e.state<<lzmaPosBitsMax+posState], 1)
	e.rc.bit(&e.p.isRep[e.state], 0)
	l := uint32(length - lzmaMatchMin)
	e.rc.length(&e.p.length, l, posState)
	d := uint32(dist - 1)
	lenState := min(l, lzmaLenToPosStates-1)
	var slot uint32
	if d < 4 {
		slot = d
	} else {
		n := uint32(31)
		for d>>n == 0 {
			n--
		}
		slot = n<<1 | (d>>(n-1))&1
	}
	e.rc.tree(e.p.posSlot[lenState][:], 6, slot)
	if slot >= 4 {
		nd := uint(slot>>1) - 1
		base := (2 | slot&1) << nd
		red := d - base
		if slot < lzmaEndPosModel {
			e.rc.reverseTree(e.p.posSpec[base-slot:], nd, red)
		} else {
			e.rc.direct(red>>lzmaAlignBits, nd-lzmaAlignBits)
			e.rc.reverseTree(e.p.align[:], lzmaAlignBits, red&(1<<lzmaAlignBits-1))
		}
	}
	e.reps[3], e.reps[2], e.reps[1], e.reps[0] = e.reps[2], e.reps[1], e.reps[0], d
	e.state = stateAfterMatch(e.state)
}

func (e *lzmaEncoder) rep(i, length, idx int) {
	posState := i & (1<<lzmaPB - 1)
	e.rc.bit(&e.p.isMatch[e.state<<lzmaPosBitsMax+posState], 1)
	e.rc.bit(&e.p.isRep[e.state], 1)
	if idx == 0 {
		e.rc.bit(&e.p.isRepG0[e.state], 0)
		e.rc.bit(&e.p.isRep0Long[e.state<<lzmaPosBitsMax+posState], 1)
	} else {
		e.rc.bit(&e.p.isRepG0[e.state], 1)
		if idx == 1 {
			e.rc.bit(&e.p.isRepG1[e.state], 0)
		} else {
			e.rc.bit(&e.p.isRepG1[e.state], 1)
			e.rc.bit(&e.p.isRepG2[e.state], uint32(idx-2))
		}
		d := e.reps[idx]
		copy(e.reps[1:idx+1], e.reps[:idx])
		e.reps[0] = d
	}
	e.rc.length(&e.p.repLen, uint32(length-lzmaMatchMin), posState)
	e.state = stateAfterRep(e.state)
}

func (e *lzmaEncoder) shortRep(i int) {
	posState := i & (1<<lzmaPB - 1)
	e.rc.bit(&e.p.isMatch[e.state<<lzmaPosBitsMax+posState], 1)
	e.rc.bit(&e.p.isRep[e.state], 1)
	e.rc.bit(&e.p.isRepG0[e.state], 0)
	e.rc.bit(&e.p.isRep0Long[e.state<<lzmaPosBitsMax+posState], 0)
	e.state = stateAfterShortRep(e.state)
}

func (e *lzmaEncoder) repMatch(i int) (int, int) {
	best, bestIdx := 0, 0
	limit := min(lzmaMatchMax, len(e.data)-i)
	for r, d := range e.reps {
		from := i - int(d) - 1
		if from < 0 {
			continue
		}
		l := 0
		for l < limit && e.data[from+l] == e.data[i+l] {
			l++
		}
		if l > best {
			best, bestIdx = l, r
		}
	}
	return best, bestIdx
}

// lzmaCompress produces an ulzman stream (greedy/lazy parse, hash chains).
func lzmaCompress(data []byte) []byte {
	dict := uint32(1 << 12)
	for i := uint(11); i <= 30; i++ {
		if uint64(len(data)) <= 2<<i {
			dict = 2 << i
			break
		}
		if uint64(len(data)) <= 3<<i {
			dict = 3 << i
			break
		}
	}
	hdr := make([]byte, lzmaHeaderSize, lzmaHeaderSize+len(data)/2+64)
	hdr[0] = byte((lzmaPB*5+lzmaLP)*9 + lzmaLC)
	binary.LittleEndian.PutUint32(hdr[1:], dict)
	binary.LittleEndian.PutUint64(hdr[5:], uint64(len(data)))

	e := &lzmaEncoder{rc: rangeEnc{out: hdr, rng: 0xFFFFFFFF, cacheSize: 1},
		p: newLZMAProbs(lzmaLC, lzmaLP), data: data}
	n := len(data)
	mf := newMatchFinder(data, 128, lzmaMatchMax, lzmaMatchMax, 3, n)
	i := 0
	for i < n {
		if i == 0 {
			e.literal(0)
			i++
			continue
		}
		repLen, repIdx := e.repMatch(i)
		mainLen, mainDist := mf.find(i, n, n)
		if mainLen == 3 && mainDist > 1<<14 {
			mainLen = 0
		}
		switch {
		case repLen >= 2 && (repLen+1 >= mainLen ||
			repLen+2 >= mainLen && mainDist >= 1<<9 ||
			repLen+3 >= mainLen && mainDist >= 1<<15):
			e.rep(i, repLen, repIdx)
			i += repLen
		case mainLen >= 3:
			if mainLen < mf.nice && i+1 < n {
				nl, nd := mf.find(i+1, n, n)
				if nl > mainLen+1 || nl == mainLen+1 && nd>>7 <= mainDist {
					e.literalOrShortRep(i)
					i++
					continue
				}
			}
			e.match(i, mainLen, mainDist)
			i += mainLen
		default:
			e.literalOrShortRep(i)
			i++
		}
	}
	for k := 0; k < 5; k++ {
		e.rc.shiftLow()
	}
	return e.rc.out
}

func (e *lzmaEncoder) literalOrShortRep(i int) {
	if e.state >= 7 && i > int(e.reps[0]) && e.data[i] == e.data[i-int(e.reps[0])-1] {
		e.shortRep(i)
		return
	}
	e.literal(i)
}

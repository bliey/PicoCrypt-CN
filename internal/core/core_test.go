package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Picocrypt/infectious"
)

// All tests in this file run serially (no t.Parallel): Argon2id needs 1 GiB
// of memory per derivation, and tests must not compete for it.

type collector struct {
	states []StateInfo
	progs  []ProgressInfo
}

func newTestSession() (*Session, *collector) {
	c := &collector{}
	s := NewSession()
	s.OnState(func(si StateInfo) { c.states = append(c.states, si) })
	s.OnProgress(func(pi ProgressInfo) { c.progs = append(c.progs, pi) })
	return s, c
}

func (c *collector) lastState() StateInfo {
	if len(c.states) == 0 {
		return StateInfo{}
	}
	return c.states[len(c.states)-1]
}

func (c *collector) lastStatus() string { return c.lastState().Status }

func (c *collector) sawProgressPrefix(prefix string) bool {
	for _, p := range c.progs {
		if strings.HasPrefix(p.Status, prefix) {
			return true
		}
	}
	return false
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func sha256Data(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// encrypt drops paths, sets the password, applies cfg, and runs to completion.
// It returns the session, the event collector, and the output path.
func encrypt(t *testing.T, paths []string, password string, cfg func(*Session)) (*Session, *collector, string) {
	t.Helper()
	s, c := newTestSession()
	s.DropFiles(paths, false)
	s.Password = password
	s.CPassword = password
	if cfg != nil {
		cfg(s)
	}
	ok, _ := s.PrepareStart()
	if !ok {
		t.Fatalf("encrypt PrepareStart failed: status=%q", c.lastStatus())
	}
	out := s.OutputFile
	s.Run()
	if st := c.lastStatus(); st != "Completed" {
		t.Fatalf("encrypt did not complete: status=%q color=%q", st, c.lastState().StatusColor)
	}
	return s, c, out
}

// decrypt drops a volume, sets the password, applies cfg, and runs. It does
// not assert the final status (failure cases are asserted by the caller).
func decrypt(t *testing.T, volume, password string, cfg func(*Session)) (*Session, *collector, string) {
	t.Helper()
	s, c := newTestSession()
	s.DropFiles([]string{volume}, false)
	s.Password = password
	if cfg != nil {
		cfg(s)
	}
	ok, _ := s.PrepareStart()
	if !ok {
		t.Fatalf("decrypt PrepareStart failed: status=%q", c.lastStatus())
	}
	out := s.OutputFile
	s.Run()
	return s, c, out
}

func corrupt(t *testing.T, path string, offsets ...int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, off := range offsets {
		if off < 0 || off >= len(b) {
			t.Fatalf("corrupt offset %d out of range (len=%d)", off, len(b))
		}
		b[off] ^= 0xFF
	}
	writeFile(t, path, b)
}

func mustNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("expected %s to not exist", path)
	}
}

// 1. Plain single-file round trip.
func TestRoundTripBasic(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "test.txt")
	data := []byte(strings.Repeat("The quick brown fox jumps over the lazy dog. ", 5000))
	writeFile(t, src, data)

	s, c := newTestSession()
	s.DropFiles([]string{src}, false)
	st := c.lastState()
	if st.Mode != "encrypt" || st.StartLabel != "Encrypt" {
		t.Fatalf("unexpected state after drop: mode=%q start=%q", st.Mode, st.StartLabel)
	}
	s.Password = "correct horse battery staple"
	s.CPassword = s.Password
	ok, needConfirm := s.PrepareStart()
	if !ok || needConfirm {
		t.Fatalf("PrepareStart = (%v, %v), want (true, false)", ok, needConfirm)
	}
	out := s.OutputFile
	if out != src+".pcv" {
		t.Fatalf("output = %q, want %q", out, src+".pcv")
	}
	s.Run()
	if st := c.lastStatus(); st != "Completed" || c.lastState().StatusColor != ColorGreen {
		t.Fatalf("encrypt final status = %q/%q", st, c.lastState().StatusColor)
	}

	_, c2, decOut := decrypt(t, out, "correct horse battery staple", nil)
	if st := c2.lastStatus(); st != "Completed" {
		t.Fatalf("decrypt final status = %q", st)
	}
	if decOut != src {
		t.Fatalf("decrypted output = %q, want %q", decOut, src)
	}
	if sha256File(t, decOut) != sha256Data(data) {
		t.Fatal("round-trip hash mismatch")
	}
}

// 2. Paranoid mode round trip (Serpent cascade + HMAC-SHA3 + 8-pass Argon2).
func TestRoundTripParanoid(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "paranoid.bin")
	data := randomBytes(t, 300*KiB)
	writeFile(t, src, data)

	_, _, out := encrypt(t, []string{src}, "paranoid-password", func(s *Session) {
		s.Paranoid = true
	})
	_, c, decOut := decrypt(t, out, "paranoid-password", nil)
	if st := c.lastStatus(); st != "Completed" {
		t.Fatalf("decrypt final status = %q", st)
	}
	if sha256File(t, decOut) != sha256Data(data) {
		t.Fatal("paranoid round-trip hash mismatch")
	}
}

// 3. Reed-Solomon (128+8 data encoding) round trip with a >1 MiB file.
func TestRoundTripReedSolomon(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "rs.bin")
	data := randomBytes(t, 5*MiB/2) // 2.5 MiB
	writeFile(t, src, data)

	_, _, out := encrypt(t, []string{src}, "rs-password", func(s *Session) {
		s.Reedsolo = true
	})
	_, c, decOut := decrypt(t, out, "rs-password", nil)
	if st := c.lastStatus(); st != "Completed" {
		t.Fatalf("decrypt final status = %q", st)
	}
	if sha256File(t, decOut) != sha256Data(data) {
		t.Fatal("reedsolo round-trip hash mismatch")
	}
}

// 4. Padded boundary: size%MiB >= MiB-128 must set flags[4]=1 and round trip.
func TestPaddedBoundary(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "padded.bin")
	data := randomBytes(t, MiB-64)
	writeFile(t, src, data)

	s, _, out := encrypt(t, []string{src}, "pad-password", func(s *Session) {
		s.Reedsolo = true
	})

	// flags are at offset 30 (15 version + 15 comment length, no comments)
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	flags, err := s.rsDecode(rs5, raw[30:45])
	if err != nil {
		t.Fatal(err)
	}
	if flags[4] != 1 {
		t.Fatalf("flags[4] = %d, want 1 (padded)", flags[4])
	}

	_, c, decOut := decrypt(t, out, "pad-password", nil)
	if st := c.lastStatus(); st != "Completed" {
		t.Fatalf("decrypt final status = %q", st)
	}
	if sha256File(t, decOut) != sha256Data(data) {
		t.Fatal("padded boundary round-trip hash mismatch")
	}
}

// 5a. Unordered keyfiles round trip (reversed order must also work).
func TestKeyfilesUnordered(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "kf.bin")
	data := randomBytes(t, 100*KiB)
	writeFile(t, src, data)
	kf1 := filepath.Join(dir, "kf1.bin")
	kf2 := filepath.Join(dir, "kf2.bin")
	writeFile(t, kf1, randomBytes(t, 64))
	writeFile(t, kf2, randomBytes(t, 96))

	_, _, out := encrypt(t, []string{src}, "kf-password", func(s *Session) {
		s.Keyfiles = []string{kf1, kf2}
	})

	// Correct keyfiles, original order
	_, c, decOut := decrypt(t, out, "kf-password", func(s *Session) {
		s.Keyfiles = []string{kf1, kf2}
	})
	if st := c.lastStatus(); st != "Completed" {
		t.Fatalf("decrypt final status = %q", st)
	}
	if sha256File(t, decOut) != sha256Data(data) {
		t.Fatal("keyfile round-trip hash mismatch")
	}

	// Reversed order must still work when ordering is not required
	_, c2, _ := decrypt(t, out, "kf-password", func(s *Session) {
		s.Keyfiles = []string{kf2, kf1}
	})
	if st := c2.lastStatus(); st != "Completed" {
		t.Fatalf("decrypt with reversed unordered keyfiles = %q", st)
	}
}

// 5b. Ordered keyfiles: wrong order must fail with the original status string.
func TestKeyfilesOrdered(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "kfo.bin")
	data := randomBytes(t, 100*KiB)
	writeFile(t, src, data)
	kf1 := filepath.Join(dir, "okf1.bin")
	kf2 := filepath.Join(dir, "okf2.bin")
	writeFile(t, kf1, randomBytes(t, 64))
	writeFile(t, kf2, randomBytes(t, 96))

	_, _, out := encrypt(t, []string{src}, "kfo-password", func(s *Session) {
		s.Keyfiles = []string{kf1, kf2}
		s.KeyfileOrdered = true
	})

	// Correct order works
	_, c, decOut := decrypt(t, out, "kfo-password", func(s *Session) {
		s.Keyfiles = []string{kf1, kf2}
	})
	if st := c.lastStatus(); st != "Completed" {
		t.Fatalf("decrypt final status = %q", st)
	}
	if sha256File(t, decOut) != sha256Data(data) {
		t.Fatal("ordered keyfile round-trip hash mismatch")
	}

	// Wrong order fails even with the correct password
	_, c2, _ := decrypt(t, out, "kfo-password", func(s *Session) {
		s.Keyfiles = []string{kf2, kf1}
	})
	if st := c2.lastStatus(); st != "Incorrect keyfiles or ordering" {
		t.Fatalf("wrong-order status = %q, want %q", st, "Incorrect keyfiles or ordering")
	}
}

// 6. Wrong password must produce the original status string and no output.
func TestWrongPassword(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "wp.txt")
	data := randomBytes(t, 50*KiB)
	writeFile(t, src, data)

	_, _, out := encrypt(t, []string{src}, "right-password", nil)

	// Move the original away so we can assert no output is produced
	orig := src + ".orig"
	if err := os.Rename(src, orig); err != nil {
		t.Fatal(err)
	}

	_, c, decOut := decrypt(t, out, "wrong-password", nil)
	if st := c.lastStatus(); st != "The provided password is incorrect" {
		t.Fatalf("wrong-password status = %q", st)
	}
	mustNotExist(t, decOut)
}

// 7. Comments round trip: the decrypt preflight must read them back.
func TestComments(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "comments.txt")
	data := randomBytes(t, 20*KiB)
	writeFile(t, src, data)
	const comment = "Hello, Picocrypt! 保密 12345"

	_, _, out := encrypt(t, []string{src}, "comments-password", func(s *Session) {
		s.Comments = comment
	})

	s, c := newTestSession()
	s.DropFiles([]string{out}, false)
	st := c.lastState()
	if st.Mode != "decrypt" || st.StartLabel != "Decrypt" {
		t.Fatalf("unexpected state: mode=%q start=%q", st.Mode, st.StartLabel)
	}
	if !st.CommentsDisabled {
		t.Fatal("comments should be read-only on decrypt")
	}
	if st.Comments != comment {
		t.Fatalf("comments = %q, want %q", st.Comments, comment)
	}

	s.Password = "comments-password"
	if ok, _ := s.PrepareStart(); !ok {
		t.Fatalf("PrepareStart failed: %q", c.lastStatus())
	}
	s.Run()
	if st := c.lastStatus(); st != "Completed" {
		t.Fatalf("decrypt final status = %q", st)
	}
	if sha256File(t, src) != sha256Data(data) {
		t.Fatal("comments round-trip hash mismatch")
	}
}

// 8. Multiple files + compress -> zip volume -> decrypt -> autoUnzip.
func TestZipAutoUnzip(t *testing.T) {
	dir := t.TempDir()
	fileA := filepath.Join(dir, "fileA.txt")
	fileB := filepath.Join(dir, "fileB.txt")
	dataA := randomBytes(t, 150*KiB)
	dataB := randomBytes(t, 250*KiB)
	writeFile(t, fileA, dataA)
	writeFile(t, fileB, dataB)

	_, _, out := encrypt(t, []string{fileA, fileB}, "zip-password", func(s *Session) {
		s.Compress = true
	})
	if !strings.HasSuffix(out, ".zip.pcv") {
		t.Fatalf("output = %q, want a .zip.pcv volume", out)
	}

	s2, c2 := newTestSession()
	s2.DropFiles([]string{out}, false)
	if st := c2.lastState(); !st.AutoUnzipEligible {
		t.Fatal("volume should be eligible for auto unzip")
	}
	s2.Password = "zip-password"
	s2.AutoUnzip = true
	if ok, _ := s2.PrepareStart(); !ok {
		t.Fatalf("PrepareStart failed: %q", c2.lastStatus())
	}
	zipOut := s2.OutputFile
	s2.Run()
	if st := c2.lastStatus(); st != "Completed" {
		t.Fatalf("decrypt final status = %q", st)
	}

	// The zip is removed after unzipping; contents land in a folder named
	// after the zip file (sameLevel=false).
	mustNotExist(t, zipOut)
	extractDir := filepath.Join(filepath.Dir(zipOut), strings.TrimSuffix(filepath.Base(zipOut), ".zip"))
	if sha256File(t, filepath.Join(extractDir, "fileA.txt")) != sha256Data(dataA) {
		t.Fatal("fileA contents mismatch after autoUnzip")
	}
	if sha256File(t, filepath.Join(extractDir, "fileB.txt")) != sha256Data(dataB) {
		t.Fatal("fileB contents mismatch after autoUnzip")
	}
}

// 9. Plausible deniability round trip.
func TestDeniability(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "deniable.bin")
	data := randomBytes(t, 120*KiB)
	writeFile(t, src, data)

	_, _, out := encrypt(t, []string{src}, "deniable-password", func(s *Session) {
		s.Deniability = true
	})

	s, c := newTestSession()
	s.DropFiles([]string{out}, false)
	st := c.lastState()
	if st.Mode != "decrypt" || !st.DeniabilityVolume {
		t.Fatalf("unexpected state: mode=%q deniable=%v", st.Mode, st.DeniabilityVolume)
	}
	if st.Status != "Can't read header, assuming volume is deniable" {
		t.Fatalf("status = %q", st.Status)
	}

	s.Password = "deniable-password"
	if ok, _ := s.PrepareStart(); !ok {
		t.Fatalf("PrepareStart failed: %q", c.lastStatus())
	}
	s.Run()
	if st := c.lastStatus(); st != "Completed" {
		t.Fatalf("decrypt final status = %q", st)
	}
	if sha256File(t, src) != sha256Data(data) {
		t.Fatal("deniability round-trip hash mismatch")
	}
}

// 10a. Split into fixed-size KiB chunks, then recombine via the .0 chunk.
func TestSplitKiB(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "split.bin")
	data := randomBytes(t, 200*KiB)
	writeFile(t, src, data)

	_, _, out := encrypt(t, []string{src}, "split-password", func(s *Session) {
		s.Split = true
		s.SplitSize = "64"
		s.SplitSelected = 0 // KiB
	})

	// The volume itself is replaced by chunks
	mustNotExist(t, out)
	size := int64(200*KiB + 789)
	wantChunks := int((size + 64*KiB - 1) / (64 * KiB))
	for i := 0; i < wantChunks; i++ {
		if _, err := os.Stat(chunkName(out, i)); err != nil {
			t.Fatalf("missing chunk %d: %v", i, err)
		}
	}
	if _, err := os.Stat(chunkName(out, wantChunks)); err == nil {
		t.Fatalf("unexpected extra chunk %d", wantChunks)
	}

	_, c, decOut := decrypt(t, chunkName(out, 0), "split-password", nil)
	if st := c.lastStatus(); st != "Completed" {
		t.Fatalf("recombine+decrypt final status = %q", st)
	}
	if sha256File(t, decOut) != sha256Data(data) {
		t.Fatal("split round-trip hash mismatch")
	}
}

// 10b. Split into N total chunks ("Total" units), then recombine.
func TestSplitTotal(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "splittotal.bin")
	data := randomBytes(t, 200*KiB)
	writeFile(t, src, data)

	_, _, out := encrypt(t, []string{src}, "split2-password", func(s *Session) {
		s.Split = true
		s.SplitSize = "3"
		s.SplitSelected = 4 // Total
	})

	mustNotExist(t, out)
	for i := 0; i < 3; i++ {
		if _, err := os.Stat(chunkName(out, i)); err != nil {
			t.Fatalf("missing chunk %d: %v", i, err)
		}
	}
	if _, err := os.Stat(chunkName(out, 3)); err == nil {
		t.Fatal("unexpected 4th chunk")
	}

	_, c, decOut := decrypt(t, chunkName(out, 0), "split2-password", nil)
	if st := c.lastStatus(); st != "Completed" {
		t.Fatalf("recombine+decrypt final status = %q", st)
	}
	if sha256File(t, decOut) != sha256Data(data) {
		t.Fatal("split-total round-trip hash mismatch")
	}
}

func chunkName(base string, i int) string {
	return base + "." + strconv.Itoa(i)
}

// 11. Header layout per Internals.md: 789 + 3*len(comments) bytes total.
func TestHeaderLayout(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "header.bin")
	data := randomBytes(t, 100)
	writeFile(t, src, data)

	s, _, out := encrypt(t, []string{src}, "header-password", func(s *Session) {
		s.Comments = "abc"
		s.Reedsolo = true
	})

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	const headerLen = 789 + 3*3
	if len(raw) != headerLen+136 { // one padded RS(128,136) block of data
		t.Fatalf("file size = %d, want %d", len(raw), headerLen+136)
	}

	decode := func(rs *infectious.FEC, b []byte) []byte {
		t.Helper()
		d, err := s.rsDecode(rs, b)
		if err != nil {
			t.Fatalf("rsDecode failed: %v", err)
		}
		return d
	}

	if v := string(decode(rs5, raw[0:15])); v != "v1.49" {
		t.Fatalf("version = %q", v)
	}
	if cl := string(decode(rs5, raw[15:30])); cl != "00003" {
		t.Fatalf("comments length = %q", cl)
	}
	comments := ""
	for i := 30; i < 39; i += 3 {
		comments += string(decode(rs1, raw[i:i+3]))
	}
	if comments != "abc" {
		t.Fatalf("comments = %q", comments)
	}
	flags := decode(rs5, raw[39:54])
	if flags[0] != 0 || flags[1] != 0 || flags[2] != 0 || flags[3] != 1 || flags[4] != 0 {
		t.Fatalf("flags = %v, want [0 0 0 1 0]", flags)
	}
	if salt := decode(rs16, raw[54:102]); len(salt) != 16 {
		t.Fatalf("salt length = %d", len(salt))
	}
	if hkdfSalt := decode(rs32, raw[102:198]); len(hkdfSalt) != 32 {
		t.Fatalf("hkdfSalt length = %d", len(hkdfSalt))
	}
	if serpentIV := decode(rs16, raw[198:246]); len(serpentIV) != 16 {
		t.Fatalf("serpentIV length = %d", len(serpentIV))
	}
	if nonce := decode(rs24, raw[246:318]); len(nonce) != 24 {
		t.Fatalf("nonce length = %d", len(nonce))
	}
	if keyHash := decode(rs64, raw[318:510]); len(keyHash) != 64 {
		t.Fatalf("keyHash length = %d", len(keyHash))
	}
	if keyfileHash := decode(rs32, raw[510:606]); len(keyfileHash) != 32 {
		t.Fatalf("keyfileHash length = %d", len(keyfileHash))
	}
	if authTag := decode(rs64, raw[606:798]); len(authTag) != 64 {
		t.Fatalf("authTag length = %d", len(authTag))
	}
}

// 12a. Reed-Solomon repair: corruption within tolerance forces the fastDecode
// pass to fail, then the automatic repair pass must succeed.
func TestRepairReedSolomon(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "repair.bin")
	data := randomBytes(t, 3*MiB/2)
	writeFile(t, src, data)

	_, _, out := encrypt(t, []string{src}, "repair-password", func(s *Session) {
		s.Reedsolo = true
	})

	// Corrupt <=4 bytes inside two distinct 136-byte blocks of the data
	// section (starts at offset 789, no comments).
	corrupt(t, out, 789+10, 789+11, 789+12, 789+136+5, 789+136+6, 789+136+7, 789+136+8)

	_, c, decOut := decrypt(t, out, "repair-password", nil)
	if st := c.lastStatus(); st != "Completed" {
		t.Fatalf("repair decrypt final status = %q", st)
	}
	if !c.sawProgressPrefix("Repairing at") {
		t.Fatal("expected a Reed-Solomon repair pass")
	}
	if sha256File(t, decOut) != sha256Data(data) {
		t.Fatal("repair round-trip hash mismatch")
	}
}

// 12b. MAC mismatch without keep: report the damage and produce no output.
func TestMACMismatchFails(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "macfail.bin")
	data := randomBytes(t, MiB)
	writeFile(t, src, data)

	_, _, out := encrypt(t, []string{src}, "mac-password", nil)

	// Move the original away so we can assert no output is produced
	if err := os.Rename(src, src+".orig"); err != nil {
		t.Fatal(err)
	}

	// Flip one byte in the encrypted data section
	corrupt(t, out, 789+100)

	_, c, decOut := decrypt(t, out, "mac-password", nil)
	if st := c.lastStatus(); st != "The input file is damaged or modified" {
		t.Fatalf("status = %q, want %q", st, "The input file is damaged or modified")
	}
	if c.lastState().StatusColor != ColorRed {
		t.Fatalf("status color = %q", c.lastState().StatusColor)
	}
	mustNotExist(t, decOut)
}

// 13. keep (Force decrypt) with a damaged header still yields an output file.
func TestKeepForceDecrypt(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "keep.bin")
	data := randomBytes(t, 100*KiB)
	writeFile(t, src, data)

	_, _, out := encrypt(t, []string{src}, "keep-password", nil)

	// Corrupt 20 bytes of the RS-encoded salt (offset 45, no comments);
	// 20 > 16 correctable byte errors, so rs16 decoding fails.
	offsets := make([]int, 20)
	for i := range offsets {
		offsets[i] = 45 + i
	}
	corrupt(t, out, offsets...)

	if err := os.Rename(src, src+".orig"); err != nil {
		t.Fatal(err)
	}

	_, c, decOut := decrypt(t, out, "keep-password", func(s *Session) {
		s.Keep = true
	})
	if st := c.lastStatus(); st != "The input file was modified. Please be careful" {
		t.Fatalf("status = %q, want %q", st, "The input file was modified. Please be careful")
	}
	if c.lastState().StatusColor != ColorYellow {
		t.Fatalf("status color = %q", c.lastState().StatusColor)
	}
	if _, err := os.Stat(decOut); err != nil {
		t.Fatalf("force decrypt should keep an output file: %v", err)
	}
}

// Smoke test for the password helpers (no Argon2 involved).
func TestPasswordUtils(t *testing.T) {
	pw := GenPassword(32, true, true, true, true)
	if len(pw) != 32 {
		t.Fatalf("GenPassword length = %d", len(pw))
	}
	for _, r := range pw {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890-=_+!@#$^&()?<>", r) {
			t.Fatalf("GenPassword produced %q outside the charset", r)
		}
	}
	if only := GenPassword(16, false, false, true, false); strings.Trim(only, "1234567890") != "" {
		t.Fatalf("GenPassword nums-only produced %q", only)
	}
	if score := PasswordStrength("password"); score < 0 || score > 4 {
		t.Fatalf("PasswordStrength = %d, out of range", score)
	}
	if PasswordStrength("password") >= PasswordStrength("X9#kQ2$mZ7&vL4pR8wT1yN6!") {
		t.Fatal("PasswordStrength ordering looks wrong")
	}
}

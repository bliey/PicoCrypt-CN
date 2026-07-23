// Package core is a line-by-line port of the encryption core of Picocrypt
// v1.49 (Picocrypt-main/src/Picocrypt.go) with the giu/imgui/dialog UI layer
// removed. All cryptographic logic, file formats, and status strings are
// transcribed verbatim so that volumes produced by this package are 100%
// compatible with the original Picocrypt.
//
// Mapping to the original source:
//   - This file:           L50-205 (constants, variables, FEC, passthrough types),
//     L207-315 (onClickStartButton -> PrepareStart/Run),
//     L2899-2902 (Reed-Solomon init check)
//   - ondrop.go:           L847-1174 (onDrop), L2634-2692 (resetUI)
//   - work.go:             L1176-2594 (work)
//   - util.go:             L2596-2632 (accessDenied/insufficientSpace/broken/cancel),
//     L2694-2897 (rsEncode/rsDecode/pad/unpad/genPassword/statify/timeify/sizeify/unpackArchive)
package core

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Picocrypt/infectious"
	"golang.org/x/crypto/chacha20"
)

// Constants (Picocrypt.go L51-54)
const KiB = 1 << 10
const MiB = 1 << 20
const GiB = 1 << 30
const TiB = 1 << 40

var version = "v1.49" // Picocrypt.go L64

// Reed-Solomon encoders (Picocrypt.go L144-150)
var rs1, rsErr1 = infectious.NewFEC(1, 3)
var rs5, rsErr2 = infectious.NewFEC(5, 15)
var rs16, rsErr3 = infectious.NewFEC(16, 48)
var rs24, rsErr4 = infectious.NewFEC(24, 72)
var rs32, rsErr5 = infectious.NewFEC(32, 96)
var rs64, rsErr6 = infectious.NewFEC(64, 192)
var rs128, rsErr7 = infectious.NewFEC(128, 136)

// Status colors, replacing the original color.RGBA values (Picocrypt.go L56-60).
const (
	ColorWhite  = "white"
	ColorRed    = "red"
	ColorGreen  = "green"
	ColorYellow = "yellow"
)

// StateInfo is emitted via OnState when the input, mode, or preflight results
// change (after DropFiles/Reset) and when a Run finishes (final mainStatus).
type StateInfo struct {
	Mode, InputLabel, Comments                      string
	CommentsDisabled, KeyfileRequired               bool
	KeyfileOrderedVolume                            bool
	DeniabilityVolume, Recombine, AutoUnzipEligible bool
	StartLabel, Status, StatusColor                 string
	RequiredFreeSpace                               int64
	OutputFile                                      string
	MultipleInputs                                  bool
}

// ProgressInfo is emitted via OnProgress while work() is running.
type ProgressInfo struct {
	Progress  float32
	Speed     float64
	ETA       string
	Status    string
	CanCancel bool
}

// Session holds all state that the original Picocrypt kept in package-level
// variables (Picocrypt.go L62-156). Exported fields are meant to be set by
// the service layer; unexported fields are internal state.
type Session struct {
	// Password and confirm password (Picocrypt.go L87-88)
	Password  string
	CPassword string

	// Comments (Picocrypt.go L108)
	Comments string

	// Advanced options (Picocrypt.go L113-126)
	Paranoid      bool
	Reedsolo      bool
	Deniability   bool
	Recursively   bool
	Split         bool
	SplitSize     string
	SplitSelected int // index into {"KiB", "MiB", "GiB", "TiB", "Total"}
	Compress      bool
	Delete        bool
	AutoUnzip     bool
	SameLevel     bool
	Keep          bool

	// Keyfiles (Picocrypt.go L102-104). 'Keyfile' (unexported in the original
	// sense of "keyfiles required by the volume") is set from header flags.
	KeyfileOrdered bool
	Keyfiles       []string

	// Output path (Picocrypt.go L80); set by DropFiles, may be overridden by
	// the service layer before Run.
	OutputFile string

	// Internal state (was package-level in the original).
	mode              string
	working           atomic.Bool // Picocrypt.go L67; the only concurrency change
	scanning          bool
	inputFile         string
	inputFileOld      string
	onlyFiles         []string
	onlyFolders       []string
	allFiles          []string
	inputLabel        string
	keyfile           bool
	keyfileLabel      string
	commentsLabel     string
	commentsDisabled  bool
	startLabel        string
	mainStatus        string
	mainStatusColor   string
	popupStatus       string
	requiredFreeSpace int64
	progress          float32
	progressInfo      string
	speed             float64
	eta               string
	canCancel         bool
	fastDecode        bool
	recombine         bool
	kept              bool

	// Compression variables (Picocrypt.go L154-156)
	compressDone  int64
	compressTotal int64
	compressStart time.Time

	onState    func(StateInfo)
	onProgress func(ProgressInfo)
}

// NewSession creates a Session with the same initial values the original
// program had after startup/resetUI. It panics if a Reed-Solomon encoder
// failed to initialize (Picocrypt.go L2900-2902).
func NewSession() *Session {
	if rsErr1 != nil || rsErr2 != nil || rsErr3 != nil || rsErr4 != nil || rsErr5 != nil || rsErr6 != nil || rsErr7 != nil {
		panic(errors.New("rs failed to init"))
	}
	s := &Session{}
	s.resetUI()
	return s
}

// OnState registers the state callback.
func (s *Session) OnState(f func(StateInfo)) { s.onState = f }

// OnProgress registers the progress callback.
func (s *Session) OnProgress(f func(ProgressInfo)) { s.onProgress = f }

func (s *Session) stateInfo() StateInfo {
	startLabel := s.startLabel
	if s.Recursively { // Picocrypt.go L800-805
		startLabel = "Process"
	}
	return StateInfo{
		Mode:                 s.mode,
		InputLabel:           s.inputLabel,
		Comments:             s.Comments,
		CommentsDisabled:     s.commentsDisabled,
		KeyfileRequired:      s.keyfile,
		KeyfileOrderedVolume: s.KeyfileOrdered,
		DeniabilityVolume:    s.mode == "decrypt" && s.Deniability,
		Recombine:            s.recombine,
		AutoUnzipEligible:    strings.HasSuffix(s.inputFile, ".zip.pcv"), // Picocrypt.go L707
		StartLabel:           startLabel,
		Status:               s.mainStatus,
		StatusColor:          s.mainStatusColor,
		RequiredFreeSpace:    s.requiredFreeSpace,
		OutputFile:           s.OutputFile,
		MultipleInputs:       len(s.allFiles) > 1 || len(s.onlyFolders) > 0,
	}
}

func (s *Session) emitState() {
	if s.onState != nil {
		s.onState(s.stateInfo())
	}
}

func (s *Session) emitProgress() {
	if s.onProgress != nil {
		s.onProgress(ProgressInfo{
			Progress:  s.progress,
			Speed:     s.speed,
			ETA:       s.eta,
			Status:    s.popupStatus,
			CanCancel: s.canCancel,
		})
	}
}

// setPopupStatus replaces 'popupStatus = X' (which was followed by a UI
// refresh in the original); it stores the value and emits a progress update.
func (s *Session) setPopupStatus(status string) {
	s.popupStatus = status
	s.emitProgress()
}

// setMainStatus replaces 'mainStatus = X; mainStatusColor = Y'.
func (s *Session) setMainStatus(status, color string) {
	s.mainStatus = status
	s.mainStatusColor = color
}

// update replaces giu.Update(): the original repainted the UI, which surfaces
// the progress variables; here we emit a progress update instead.
func (s *Session) update() {
	s.emitProgress()
}

// Cancel stops the current operation (Picocrypt.go L440-443).
func (s *Session) Cancel() {
	s.working.Store(false)
	s.canCancel = false
}

// Working reports whether work() is currently running.
func (s *Session) Working() bool {
	return s.working.Load()
}

// InputFile returns the current input file path (service-layer convenience
// accessor; not part of the original UI state).
func (s *Session) InputFile() string {
	return s.inputFile
}

// Snapshot returns the current StateInfo (service-layer convenience accessor).
func (s *Session) Snapshot() StateInfo {
	return s.stateInfo()
}

// SetWorking marks the session as working (original: 'working = true' in
// onClickStartButton before starting the goroutine).
func (s *Session) SetWorking() {
	s.working.Store(true)
}

// CurrentMode returns the current mode ("", "encrypt" or "decrypt").
func (s *Session) CurrentMode() string {
	return s.mode
}

// HasMultipleInputs reports whether the input will be packed into a
// temporary zip (original: 'len(allFiles) > 1 || len(onlyFolders) > 0').
func (s *Session) HasMultipleInputs() bool {
	return len(s.allFiles) > 1 || len(s.onlyFolders) > 0
}

// OutputExists reports whether the output file (or, when splitting, any
// output chunks) already exists. Mirrors the checks in onClickStartButton
// (Picocrypt.go L228-241).
func (s *Session) OutputExists() bool {
	_, err := os.Stat(s.OutputFile)
	if s.Split {
		names, err2 := filepath.Glob(s.OutputFile + ".*")
		if err2 != nil {
			panic(err2)
		}
		return len(names) > 0
	}
	return err == nil
}

// PrepareStart is the validation section of onClickStartButton
// (Picocrypt.go L207-253), without the overwrite modal and without starting
// the goroutine. ok=false means validation failed (mainStatus was set).
// needOverwriteConfirm=true means the output already exists and the caller
// should ask the user before calling Run.
func (s *Session) PrepareStart() (ok bool, needOverwriteConfirm bool) {
	// Start button should be disabled if these conditions are true; don't do anything if so
	if (len(s.Keyfiles) == 0 && s.Password == "") || (s.mode == "encrypt" && s.Password != s.CPassword) {
		return false, false
	}

	if s.keyfile && s.Keyfiles == nil {
		s.setMainStatus("Please select your keyfiles", ColorRed)
		s.emitState()
		return false, false
	}
	tmp, err := strconv.Atoi(s.SplitSize)
	if s.Split && (s.SplitSize == "" || err != nil || tmp <= 0) {
		s.setMainStatus("Invalid chunk size", ColorRed)
		s.emitState()
		return false, false
	}

	// Check if output file already exists
	_, err = os.Stat(s.OutputFile)

	// Check if any split chunks already exist
	if s.Split {
		names, err2 := filepath.Glob(s.OutputFile + ".*")
		if err2 != nil {
			panic(err2)
		}
		if len(names) > 0 {
			err = nil
		} else {
			err = os.ErrNotExist
		}
	}

	// If files already exist, the caller must confirm the overwrite
	if err == nil && !s.Recursively {
		return true, true
	}
	// Nothing to worry about, start working
	return true, false
}

// Run is the goroutine section of onClickStartButton (Picocrypt.go L249-253,
// L261-313): it runs work() synchronously, or, for Recursively, loops over
// each dropped file. The caller is responsible for running it in a goroutine
// if asynchronous execution is desired.
func (s *Session) Run() {
	defer s.emitState()
	s.fastDecode = true
	s.canCancel = true
	if !s.Recursively {
		s.work()
		s.working.Store(false)
		s.update()
		return
	}

	// Store variables as they will be cleared
	oldPassword := s.Password
	oldKeyfile := s.keyfile
	oldKeyfiles := s.Keyfiles
	oldKeyfileOrdered := s.KeyfileOrdered
	oldKeyfileLabel := s.keyfileLabel
	oldComments := s.Comments
	oldParanoid := s.Paranoid
	oldReedsolo := s.Reedsolo
	oldDeniability := s.Deniability
	oldSplit := s.Split
	oldSplitSize := s.SplitSize
	oldSplitSelected := s.SplitSelected
	oldDelete := s.Delete
	files := s.allFiles
	for _, file := range files {
		// Simulate dropping the file
		s.DropFiles([]string{file}, false)

		// Restore variables and options
		s.Password = oldPassword
		s.CPassword = oldPassword
		s.keyfile = oldKeyfile
		s.Keyfiles = oldKeyfiles
		s.KeyfileOrdered = oldKeyfileOrdered
		s.keyfileLabel = oldKeyfileLabel
		s.Comments = oldComments
		s.Paranoid = oldParanoid
		s.Reedsolo = oldReedsolo
		if s.mode != "decrypt" {
			s.Deniability = oldDeniability
		}
		s.Split = oldSplit
		s.SplitSize = oldSplitSize
		s.SplitSelected = oldSplitSelected
		s.Delete = oldDelete

		s.work()
		if !s.working.Load() {
			s.resetUI()
			s.cancel(nil, nil)
			s.update()
			return
		}
	}
	s.working.Store(false)
	s.update()
}

// compressorProgress (Picocrypt.go L158-176) reports zip combine/compress progress.
type compressorProgress struct {
	s *Session
	io.Reader
}

func (p *compressorProgress) Read(data []byte) (int, error) {
	if !p.s.working.Load() {
		return 0, io.EOF
	}
	read, err := p.Reader.Read(data)
	p.s.compressDone += int64(read)
	p.s.progress, p.s.speed, p.s.eta = statify(p.s.compressDone, p.s.compressTotal, p.s.compressStart)
	if p.s.Compress {
		p.s.setPopupStatus(fmt.Sprintf("Compressing at %.2f MiB/s (ETA: %s)", p.s.speed, p.s.eta))
	} else {
		p.s.setPopupStatus(fmt.Sprintf("Combining at %.2f MiB/s (ETA: %s)", p.s.speed, p.s.eta))
	}
	return read, err
}

// encryptedZipWriter (Picocrypt.go L178-187)
type encryptedZipWriter struct {
	_w      io.Writer
	_cipher *chacha20.Cipher
}

func (ezw *encryptedZipWriter) Write(data []byte) (n int, err error) {
	dst := make([]byte, len(data))
	ezw._cipher.XORKeyStream(dst, data)
	return ezw._w.Write(dst)
}

// encryptedZipReader (Picocrypt.go L189-205)
type encryptedZipReader struct {
	_r      io.Reader
	_cipher *chacha20.Cipher
}

func (ezr *encryptedZipReader) Read(data []byte) (n int, err error) {
	src := make([]byte, len(data))
	n, err = ezr._r.Read(src)
	if err == nil && n > 0 {
		dst := make([]byte, n)
		ezr._cipher.XORKeyStream(dst, src[:n])
		if copy(data, dst) != n {
			panic(errors.New("built-in copy() function failed"))
		}
	}
	return n, err
}

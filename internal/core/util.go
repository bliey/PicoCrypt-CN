package core

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Picocrypt/infectious"
	"github.com/Picocrypt/zxcvbn-go"
)

// If the OS denies reading or writing to a file (Picocrypt.go L2597-2600)
func (s *Session) accessDenied(str string) {
	s.setMainStatus(str+" access denied by operating system", ColorRed)
}

// If there isn't enough disk space (Picocrypt.go L2603-2608)
func (s *Session) insufficientSpace(fin *os.File, fout *os.File) {
	fin.Close()
	fout.Close()
	s.setMainStatus("Insufficient disk space", ColorRed)
}

// If corruption is detected during decryption (Picocrypt.go L2611-2624)
func (s *Session) broken(fin *os.File, fout *os.File, message string, keepOutput bool) {
	fin.Close()
	fout.Close()
	s.setMainStatus(message, ColorRed)

	// Clean up files since decryption failed
	if s.recombine {
		os.Remove(s.inputFile)
	}
	if !keepOutput {
		os.Remove(s.OutputFile)
	}
}

// Stop working if user hits "Cancel" (Picocrypt.go L2627-2632)
func (s *Session) cancel(fin *os.File, fout *os.File) {
	fin.Close()
	fout.Close()
	s.setMainStatus("Operation cancelled by user", ColorWhite)
}

// Reed-Solomon encoder (Picocrypt.go L2695-2701)
func rsEncode(rs *infectious.FEC, data []byte) []byte {
	res := make([]byte, rs.Total())
	rs.Encode(data, func(s infectious.Share) {
		res[s.Number] = s.Data[0]
	})
	return res
}

// Reed-Solomon decoder (Picocrypt.go L2704-2727). A method because 'fastDecode'
// is session state.
func (s *Session) rsDecode(rs *infectious.FEC, data []byte) ([]byte, error) {
	// If fast decode, just return the first 128 bytes
	if rs.Total() == 136 && s.fastDecode {
		return data[:128], nil
	}

	tmp := make([]infectious.Share, rs.Total())
	for i := range rs.Total() {
		tmp[i].Number = i
		tmp[i].Data = append(tmp[i].Data, data[i])
	}
	res, err := rs.Decode(nil, tmp)

	// Force decode the data but return the error as well
	if err != nil {
		if rs.Total() == 136 {
			return data[:128], err
		}
		return data[:rs.Total()/3], err
	}

	// No issues, return the decoded data
	return res, nil
}

// PKCS#7 pad (for use with Reed-Solomon) (Picocrypt.go L2730-2734)
func pad(data []byte) []byte {
	padLen := 128 - len(data)%128
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

// PKCS#7 unpad (Picocrypt.go L2737-2740)
func unpad(data []byte) []byte {
	padLen := int(data[127])
	return data[:128-padLen]
}

// PasswordStrength wraps zxcvbn (Picocrypt.go L345, L503, L519).
func PasswordStrength(pw string) int {
	return zxcvbn.PasswordStrength(pw, nil).Score
}

// GenPassword generates a cryptographically secure password
// (Picocrypt.go L2743-2766). The passgen options are parameters instead of
// package variables; the clipboard copy (UI) is not part of core.
func GenPassword(length int32, upper, lower, nums, symbols bool) string {
	chars := ""
	if upper {
		chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if lower {
		chars += "abcdefghijklmnopqrstuvwxyz"
	}
	if nums {
		chars += "1234567890"
	}
	if symbols {
		chars += "-=_+!@#$^&()?<>"
	}
	tmp := make([]byte, length)
	for i := range int(length) {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		tmp[i] = chars[j.Int64()]
	}
	return string(tmp)
}

// Convert done, total, and starting time to progress, speed, and ETA
// (Picocrypt.go L2769-2775)
func statify(done int64, total int64, start time.Time) (float32, float64, string) {
	progress := float32(done) / float32(total)
	elapsed := float64(time.Since(start)) / float64(MiB) / 1000
	speed := float64(done) / elapsed / float64(MiB)
	eta := int(math.Floor(float64(total-done) / (speed * float64(MiB))))
	return float32(math.Min(float64(progress), 1)), speed, timeify(eta)
}

// Convert seconds to HH:MM:SS (Picocrypt.go L2778-2787)
func timeify(seconds int) string {
	hours := int(math.Floor(float64(seconds) / 3600))
	seconds %= 3600
	minutes := int(math.Floor(float64(seconds) / 60))
	seconds %= 60
	hours = int(math.Max(float64(hours), 0))
	minutes = int(math.Max(float64(minutes), 0))
	seconds = int(math.Max(float64(seconds), 0))
	return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
}

// Convert bytes to KiB, MiB, etc. (Picocrypt.go L2790-2800)
func sizeify(size int64) string {
	if size >= int64(TiB) {
		return fmt.Sprintf("%.2f TiB", float64(size)/float64(TiB))
	} else if size >= int64(GiB) {
		return fmt.Sprintf("%.2f GiB", float64(size)/float64(GiB))
	} else if size >= int64(MiB) {
		return fmt.Sprintf("%.2f MiB", float64(size)/float64(MiB))
	} else {
		return fmt.Sprintf("%.2f KiB", float64(size)/float64(KiB))
	}
}

// unpackArchive (Picocrypt.go L2802-2897). A method because it reads
// 'sameLevel' and reports progress through the session.
func (s *Session) unpackArchive(zipPath string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	var totalSize int64
	for _, f := range reader.File {
		totalSize += int64(f.UncompressedSize64)
	}

	var extractDir string
	if s.SameLevel {
		extractDir = filepath.Dir(zipPath)
	} else {
		extractDir = filepath.Join(filepath.Dir(zipPath), strings.TrimSuffix(filepath.Base(zipPath), ".zip"))
	}

	var done int64
	startTime := time.Now()

	for _, f := range reader.File {
		if strings.Contains(f.Name, "..") {
			return errors.New("potentially malicious zip item path")
		}
		outPath := filepath.Join(extractDir, f.Name)

		// Make directory if current entry is a folder
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(outPath, 0700); err != nil {
				return err
			}
		}
	}

	for i, f := range reader.File {
		if strings.Contains(f.Name, "..") {
			return errors.New("potentially malicious zip item path")
		}

		// Already handled above
		if f.FileInfo().IsDir() {
			continue
		}

		outPath := filepath.Join(extractDir, f.Name)

		// Otherwise create necessary parent directories
		if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil {
			return err
		}

		// Open the file inside the archive
		fileInArchive, err := f.Open()
		if err != nil {
			return err
		}
		defer fileInArchive.Close()

		dstFile, err := os.Create(outPath)
		if err != nil {
			return err
		}

		// Read from zip in chunks to update progress
		buffer := make([]byte, MiB)
		for {
			n, readErr := fileInArchive.Read(buffer)
			if n > 0 {
				_, writeErr := dstFile.Write(buffer[:n])
				if writeErr != nil {
					dstFile.Close()
					os.Remove(dstFile.Name())
					return writeErr
				}

				done += int64(n)
				s.progress, s.speed, s.eta = statify(done, totalSize, startTime)
				s.progressInfo = fmt.Sprintf("%d/%d", i+1, len(reader.File))
				s.setPopupStatus(fmt.Sprintf("Unpacking at %.2f MiB/s (ETA: %s)", s.speed, s.eta))
				s.update()
			}
			if readErr != nil {
				if readErr == io.EOF {
					break
				}
				dstFile.Close()
				return readErr
			}
		}
		dstFile.Close()
	}

	return nil
}

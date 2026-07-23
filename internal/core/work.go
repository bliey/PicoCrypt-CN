package core

import (
	"archive/zip"
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Picocrypt/serpent"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// work is a verbatim port of Picocrypt.go L1176-2594. All package-level
// variable accesses are replaced by Session fields; giu.Update() calls are
// replaced by s.update(); popupStatus assignments by s.setPopupStatus();
// mainStatus/mainStatusColor assignments by s.setMainStatus().
//
// The only intentional deviation: the original local variable 's' holding the
// serpent block cipher (L2000) is renamed to 'sb' because 's' is the method
// receiver here.
func (s *Session) work() {
	s.setPopupStatus("Starting...")
	s.setMainStatus("Working...", ColorWhite)
	s.working.Store(true)
	padded := false
	s.update()

	// Cryptography values
	var salt []byte                    // Argon2 salt, 16 bytes
	var hkdfSalt []byte                // HKDF-SHA3 salt, 32 bytes
	var serpentIV []byte               // Serpent IV, 16 bytes
	var nonce []byte                   // 24-byte XChaCha20 nonce
	var keyHash []byte                 // SHA3-512 hash of encryption key
	var keyHashRef []byte              // Same as 'keyHash', but used for comparison
	var keyfileKey []byte              // The SHA3-256 hashes of keyfiles
	var keyfileHash = make([]byte, 32) // The SHA3-256 of 'keyfileKey'
	var keyfileHashRef []byte          // Same as 'keyfileHash', but used for comparison
	var authTag []byte                 // 64-byte authentication tag (BLAKE2b or HMAC-SHA3)

	var tempZipCipherW *chacha20.Cipher
	var tempZipCipherR *chacha20.Cipher
	var tempZipInUse bool = false
	func() { // enclose to keep out of parent scope
		key, nonce := make([]byte, 32), make([]byte, 12)
		if n, err := rand.Read(key); err != nil || n != 32 {
			panic(errors.New("fatal crypto/rand error"))
		}
		if n, err := rand.Read(nonce); err != nil || n != 12 {
			panic(errors.New("fatal crypto/rand error"))
		}
		if bytes.Equal(key, make([]byte, 32)) || bytes.Equal(nonce, make([]byte, 12)) {
			panic(errors.New("fatal crypto/rand error")) // this should never happen but be safe
		}
		var errW error
		var errR error
		tempZipCipherW, errW = chacha20.NewUnauthenticatedCipher(key, nonce)
		tempZipCipherR, errR = chacha20.NewUnauthenticatedCipher(key, nonce)
		if errW != nil || errR != nil {
			panic(errors.New("fatal chacha20 init error"))
		}
	}()

	// Combine/compress all files into a .zip file if needed
	if len(s.allFiles) > 1 || len(s.onlyFolders) > 0 {
		// Consider case where compressing only one file
		files := s.allFiles
		if len(s.allFiles) == 0 {
			files = s.onlyFiles
		}

		// Get the root directory of the selected files
		var rootDir string
		if len(s.onlyFolders) > 0 {
			rootDir = filepath.Dir(s.onlyFolders[0])
		} else {
			rootDir = filepath.Dir(s.onlyFiles[0])
		}

		// Open a temporary .zip for writing
		s.inputFile = strings.TrimSuffix(s.OutputFile, ".pcv") + ".tmp"
		file, err := os.Create(s.inputFile)
		if err != nil { // Make sure file is writable
			s.accessDenied("Write")
			return
		}

		// Add each file to the .zip
		tempZip := encryptedZipWriter{
			_w:      file,
			_cipher: tempZipCipherW,
		}
		tempZipInUse = true
		writer := zip.NewWriter(&tempZip)
		s.compressStart = time.Now()
		for i, path := range files {
			s.progressInfo = fmt.Sprintf("%d/%d", i+1, len(files))
			s.update()

			// Create file info header (size, last modified, etc.)
			stat, err := os.Stat(path)
			if err != nil {
				writer.Close()
				file.Close()
				os.Remove(s.inputFile)
				s.resetUI()
				s.setMainStatus("Failed to stat input files", ColorRed)
				return
			}
			header, err := zip.FileInfoHeader(stat)
			if err != nil {
				writer.Close()
				file.Close()
				os.Remove(s.inputFile)
				s.resetUI()
				s.setMainStatus("Failed to create zip.FileInfoHeader", ColorRed)
				return
			}
			header.Name = strings.TrimPrefix(path, rootDir)
			header.Name = filepath.ToSlash(header.Name)
			header.Name = strings.TrimPrefix(header.Name, "/")

			if s.Compress {
				header.Method = zip.Deflate
			} else {
				header.Method = zip.Store
			}

			// Open the file for reading
			entry, err := writer.CreateHeader(header)
			if err != nil {
				writer.Close()
				file.Close()
				os.Remove(s.inputFile)
				s.resetUI()
				s.setMainStatus("Failed to writer.CreateHeader", ColorRed)
				return
			}
			fin, err := os.Open(path)
			if err != nil {
				writer.Close()
				file.Close()
				os.Remove(s.inputFile)
				s.resetUI()
				s.accessDenied("Read")
				return
			}

			// Use a passthrough to catch compression progress
			passthrough := &compressorProgress{s: s, Reader: fin}
			buf := make([]byte, MiB)
			_, err = io.CopyBuffer(entry, passthrough, buf)
			fin.Close()

			if err != nil {
				writer.Close()
				s.insufficientSpace(nil, file)
				os.Remove(s.inputFile)
				return
			}

			if !s.working.Load() {
				writer.Close()
				s.cancel(nil, file)
				os.Remove(s.inputFile)
				return
			}
		}
		if err := writer.Close(); err != nil {
			panic(err)
		}
		if err := file.Close(); err != nil {
			panic(err)
		}
	}

	// Recombine a split file if necessary
	if s.recombine {
		totalFiles := 0
		totalBytes := int64(0)
		done := 0

		// Find out the number of splitted chunks
		for {
			stat, err := os.Stat(fmt.Sprintf("%s.%d", s.inputFile, totalFiles))
			if err != nil {
				break
			}
			totalFiles++
			totalBytes += stat.Size()
		}

		// Make sure not to overwrite anything
		_, err := os.Stat(s.OutputFile + ".pcv")
		if err == nil { // File already exists
			s.setMainStatus("Please remove "+filepath.Base(s.OutputFile+".pcv"), ColorRed)
			return
		}

		// Create a .pcv to combine chunks into
		fout, err := os.Create(s.OutputFile + ".pcv")
		if err != nil { // Make sure file is writable
			s.accessDenied("Write")
			return
		}

		// Merge all chunks into one file
		startTime := time.Now()
		for i := range totalFiles {
			fin, err := os.Open(fmt.Sprintf("%s.%d", s.inputFile, i))
			if err != nil {
				fout.Close()
				os.Remove(s.OutputFile + ".pcv")
				s.resetUI()
				s.accessDenied("Read")
				return
			}

			for {
				if !s.working.Load() {
					s.cancel(fin, fout)
					os.Remove(s.OutputFile + ".pcv")
					return
				}

				// Copy from the chunk into the .pcv
				data := make([]byte, MiB)
				read, err := fin.Read(data)
				if err != nil {
					break
				}
				data = data[:read]
				var n int
				n, err = fout.Write(data)
				done += read

				if err != nil || n != len(data) {
					s.insufficientSpace(fin, fout)
					os.Remove(s.OutputFile + ".pcv")
					return
				}

				// Update the stats
				s.progress, s.speed, s.eta = statify(int64(done), totalBytes, startTime)
				s.progressInfo = fmt.Sprintf("%d/%d", i+1, totalFiles)
				s.setPopupStatus(fmt.Sprintf("Recombining at %.2f MiB/s (ETA: %s)", s.speed, s.eta))
				s.update()
			}
			if err := fin.Close(); err != nil {
				panic(err)
			}
		}
		if err := fout.Close(); err != nil {
			panic(err)
		}
		s.inputFileOld = s.inputFile
		s.inputFile = s.OutputFile + ".pcv"
	}

	// Input volume has plausible deniability
	if s.mode == "decrypt" && s.Deniability {
		s.setPopupStatus("Removing deniability protection...")
		s.progressInfo = ""
		s.progress = 0
		s.canCancel = false
		s.update()

		// Get size of volume for showing progress
		stat, err := os.Stat(s.inputFile)
		if err != nil {
			// we already read from inputFile successfully in onDrop
			// so it is very unlikely this err != nil, we can just panic
			panic(err)
		}
		total := stat.Size()

		// Rename input volume to free up the filename
		fin, err := os.Open(s.inputFile)
		if err != nil {
			panic(err)
		}
		for strings.HasSuffix(s.inputFile, ".tmp") {
			s.inputFile = strings.TrimSuffix(s.inputFile, ".tmp")
		}
		s.inputFile += ".tmp"
		fout, err := os.Create(s.inputFile)
		if err != nil {
			panic(err)
		}

		// Get the Argon2 salt and XChaCha20 nonce from input volume
		salt := make([]byte, 16)
		nonce := make([]byte, 24)
		if n, err := fin.Read(salt); err != nil || n != 16 {
			panic(errors.New("failed to read 16 bytes from file"))
		}
		if n, err := fin.Read(nonce); err != nil || n != 24 {
			panic(errors.New("failed to read 24 bytes from file"))
		}

		// Generate key and XChaCha20
		key := argon2.IDKey([]byte(s.Password), salt, 4, 1<<20, 4, 32)
		chacha, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			panic(err)
		}

		// Decrypt the entire volume
		done, counter := 0, 0
		for {
			src := make([]byte, MiB)
			size, err := fin.Read(src)
			if err != nil {
				break
			}
			src = src[:size]
			dst := make([]byte, len(src))
			chacha.XORKeyStream(dst, src)
			if n, err := fout.Write(dst); err != nil || n != len(dst) {
				fout.Close()
				os.Remove(fout.Name())
				panic(errors.New("failed to write dst"))
			}

			// Update stats
			done += size
			counter += MiB
			s.progress = float32(float64(done) / float64(total))
			s.update()

			// Change nonce after 60 GiB to prevent overflow
			if counter >= 60*GiB {
				tmp := sha3.New256()
				if n, err := tmp.Write(nonce); err != nil || n != len(nonce) {
					panic(errors.New("failed to write nonce to tmp during rekeying"))
				}
				nonce = tmp.Sum(nil)[:24]
				chacha, err = chacha20.NewUnauthenticatedCipher(key, nonce)
				if err != nil {
					panic(err)
				}
				counter = 0
			}
		}

		if err := fin.Close(); err != nil {
			panic(err)
		}
		if err := fout.Close(); err != nil {
			panic(err)
		}

		// Check if the version can be read from the volume
		fin, err = os.Open(s.inputFile)
		if err != nil {
			panic(err)
		}
		tmp := make([]byte, 15)
		if n, err := fin.Read(tmp); err != nil || n != 15 {
			panic(errors.New("failed to read 15 bytes from file"))
		}
		if err := fin.Close(); err != nil {
			panic(err)
		}
		tmp, err = s.rsDecode(rs5, tmp)
		if valid, _ := regexp.Match(`^v1\.\d{2}`, tmp); err != nil || !valid {
			os.Remove(s.inputFile)
			s.inputFile = strings.TrimSuffix(s.inputFile, ".tmp")
			s.broken(nil, nil, "Password is incorrect or the file is not a volume", true)
			if s.recombine {
				s.inputFile = s.inputFileOld
			}
			return
		}
	}

	s.canCancel = false
	s.progress = 0
	s.progressInfo = ""
	s.update()

	// Subtract the header size from the total size if decrypting
	stat, err := os.Stat(s.inputFile)
	if err != nil {
		s.resetUI()
		s.accessDenied("Read")
		return
	}
	total := stat.Size()
	if s.mode == "decrypt" {
		total -= 789
	}

	// Open input file in read-only mode
	fin, err := os.Open(s.inputFile)
	if err != nil {
		s.resetUI()
		s.accessDenied("Read")
		return
	}

	// Setup output file
	var fout *os.File

	// If encrypting, generate values and write to file
	if s.mode == "encrypt" {
		s.setPopupStatus("Generating values...")
		s.update()

		// Stores any errors when writing to file
		errs := make([]error, 11)

		// Make sure not to overwrite anything
		_, err = os.Stat(s.OutputFile)
		if s.Split && err == nil { // File already exists
			fin.Close()
			if len(s.allFiles) > 1 || len(s.onlyFolders) > 0 || s.Compress {
				os.Remove(s.inputFile)
			}
			s.setMainStatus("Please remove "+filepath.Base(s.OutputFile), ColorRed)
			return
		}

		// Create the output file
		fout, err = os.Create(s.OutputFile + ".incomplete")
		if err != nil {
			fin.Close()
			if len(s.allFiles) > 1 || len(s.onlyFolders) > 0 || s.Compress {
				os.Remove(s.inputFile)
			}
			s.accessDenied("Write")
			return
		}

		// Set up cryptographic values
		salt = make([]byte, 16)
		hkdfSalt = make([]byte, 32)
		serpentIV = make([]byte, 16)
		nonce = make([]byte, 24)

		// Write the program version to file
		_, errs[0] = fout.Write(rsEncode(rs5, []byte(version)))

		if len(s.Comments) > 99999 {
			panic(errors.New("comments exceed maximum length"))
		}

		// Encode and write the comment length to file
		commentsLength := []byte(fmt.Sprintf("%05d", len(s.Comments)))
		_, errs[1] = fout.Write(rsEncode(rs5, commentsLength))

		// Encode the comment and write to file
		for _, i := range []byte(s.Comments) {
			_, err := fout.Write(rsEncode(rs1, []byte{i}))
			if err != nil {
				errs[2] = err
			}
		}

		// Configure flags and write to file
		flags := make([]byte, 5)
		if s.Paranoid { // Paranoid mode selected
			flags[0] = 1
		}
		if len(s.Keyfiles) > 0 { // Keyfiles are being used
			flags[1] = 1
		}
		if s.KeyfileOrdered { // Order of keyfiles matter
			flags[2] = 1
		}
		if s.Reedsolo { // Full Reed-Solomon encoding is selected
			flags[3] = 1
		}
		if total%int64(MiB) >= int64(MiB)-128 { // Reed-Solomon internals
			flags[4] = 1
		}
		_, errs[3] = fout.Write(rsEncode(rs5, flags))

		// Fill values with Go's CSPRNG
		if _, err := rand.Read(salt); err != nil {
			panic(err)
		}
		if _, err := rand.Read(hkdfSalt); err != nil {
			panic(err)
		}
		if _, err := rand.Read(serpentIV); err != nil {
			panic(err)
		}
		if _, err := rand.Read(nonce); err != nil {
			panic(err)
		}
		if bytes.Equal(salt, make([]byte, 16)) {
			panic(errors.New("fatal crypto/rand error"))
		}
		if bytes.Equal(hkdfSalt, make([]byte, 32)) {
			panic(errors.New("fatal crypto/rand error"))
		}
		if bytes.Equal(serpentIV, make([]byte, 16)) {
			panic(errors.New("fatal crypto/rand error"))
		}
		if bytes.Equal(nonce, make([]byte, 24)) {
			panic(errors.New("fatal crypto/rand error"))
		}

		// Encode values with Reed-Solomon and write to file
		_, errs[4] = fout.Write(rsEncode(rs16, salt))
		_, errs[5] = fout.Write(rsEncode(rs32, hkdfSalt))
		_, errs[6] = fout.Write(rsEncode(rs16, serpentIV))
		_, errs[7] = fout.Write(rsEncode(rs24, nonce))

		// Write placeholders for future use
		_, errs[8] = fout.Write(make([]byte, 192))  // Hash of encryption key
		_, errs[9] = fout.Write(make([]byte, 96))   // Hash of keyfile key
		_, errs[10] = fout.Write(make([]byte, 192)) // BLAKE2b/HMAC-SHA3 tag

		for _, err := range errs {
			if err != nil {
				s.insufficientSpace(fin, fout)
				if len(s.allFiles) > 1 || len(s.onlyFolders) > 0 || s.Compress {
					os.Remove(s.inputFile)
				}
				os.Remove(fout.Name())
				return
			}
		}
	} else { // Decrypting, read values from file and decode
		s.setPopupStatus("Reading values...")
		s.update()

		// Stores any Reed-Solomon decoding errors
		errs := make([]error, 10)

		version := make([]byte, 15)
		fin.Read(version)
		_, errs[0] = s.rsDecode(rs5, version)

		tmp := make([]byte, 15)
		fin.Read(tmp)
		tmp, errs[1] = s.rsDecode(rs5, tmp)

		if valid, err := regexp.Match(`^\d{5}$`, tmp); !valid || err != nil {
			s.broken(fin, nil, "Unable to read comments length", true)
			return
		}

		commentsLength, _ := strconv.Atoi(string(tmp))
		fin.Read(make([]byte, commentsLength*3))
		total -= int64(commentsLength) * 3

		flags := make([]byte, 15)
		fin.Read(flags)
		flags, errs[2] = s.rsDecode(rs5, flags)
		s.Paranoid = flags[0] == 1
		s.Reedsolo = flags[3] == 1
		padded = flags[4] == 1
		if s.Deniability {
			s.keyfile = flags[1] == 1
			s.KeyfileOrdered = flags[2] == 1
		}

		salt = make([]byte, 48)
		fin.Read(salt)
		salt, errs[3] = s.rsDecode(rs16, salt)

		hkdfSalt = make([]byte, 96)
		fin.Read(hkdfSalt)
		hkdfSalt, errs[4] = s.rsDecode(rs32, hkdfSalt)

		serpentIV = make([]byte, 48)
		fin.Read(serpentIV)
		serpentIV, errs[5] = s.rsDecode(rs16, serpentIV)

		nonce = make([]byte, 72)
		fin.Read(nonce)
		nonce, errs[6] = s.rsDecode(rs24, nonce)

		keyHashRef = make([]byte, 192)
		fin.Read(keyHashRef)
		keyHashRef, errs[7] = s.rsDecode(rs64, keyHashRef)

		keyfileHashRef = make([]byte, 96)
		fin.Read(keyfileHashRef)
		keyfileHashRef, errs[8] = s.rsDecode(rs32, keyfileHashRef)

		authTag = make([]byte, 192)
		fin.Read(authTag)
		authTag, errs[9] = s.rsDecode(rs64, authTag)

		// If there was an issue during decoding, the header is corrupted
		for _, err := range errs {
			if err != nil {
				if s.Keep { // If the user chooses to force decrypt
					s.kept = true
				} else {
					s.broken(fin, nil, "The volume header is damaged", true)
					return
				}
			}
		}
	}

	s.setPopupStatus("Deriving key...")
	s.update()

	// Derive encryption keys and subkeys
	var key []byte
	if s.Paranoid {
		key = argon2.IDKey(
			[]byte(s.Password),
			salt,
			8,     // 8 passes
			1<<20, // 1 GiB memory
			8,     // 8 threads
			32,    // 32-byte output key
		)
	} else {
		key = argon2.IDKey(
			[]byte(s.Password),
			salt,
			4,
			1<<20,
			4,
			32,
		)
	}
	if bytes.Equal(key, make([]byte, 32)) {
		panic(errors.New("fatal crypto/argon2 error"))
	}

	// If keyfiles are being used
	if len(s.Keyfiles) > 0 || s.keyfile {
		s.setPopupStatus("Reading keyfiles...")
		s.update()

		var keyfileTotal int64
		for _, path := range s.Keyfiles {
			stat, err := os.Stat(path)
			if err != nil {
				panic(err) // we already checked os.Stat in onDrop
			}
			keyfileTotal += stat.Size()
		}

		if s.KeyfileOrdered { // If order matters, hash progressively
			var tmp = sha3.New256()
			var keyfileDone int

			// For each keyfile...
			for _, path := range s.Keyfiles {
				fin, err := os.Open(path)
				if err != nil {
					panic(err)
				}
				for { // Read in chunks of 1 MiB
					data := make([]byte, MiB)
					size, err := fin.Read(data)
					if err != nil {
						break
					}
					data = data[:size]
					if _, err := tmp.Write(data); err != nil { // Hash the data
						panic(err)
					}

					// Update progress
					keyfileDone += size
					s.progress = float32(keyfileDone) / float32(keyfileTotal)
					s.update()
				}
				if err := fin.Close(); err != nil {
					panic(err)
				}
			}
			keyfileKey = tmp.Sum(nil) // Get the SHA3-256

			// Store a hash of 'keyfileKey' for comparison
			tmp = sha3.New256()
			if _, err := tmp.Write(keyfileKey); err != nil {
				panic(err)
			}
			keyfileHash = tmp.Sum(nil)
		} else { // If order doesn't matter, hash individually and combine
			var keyfileDone int

			// For each keyfile...
			for _, path := range s.Keyfiles {
				fin, err := os.Open(path)
				if err != nil {
					panic(err)
				}
				tmp := sha3.New256()
				for { // Read in chunks of 1 MiB
					data := make([]byte, MiB)
					size, err := fin.Read(data)
					if err != nil {
						break
					}
					data = data[:size]
					if _, err := tmp.Write(data); err != nil { // Hash the data
						panic(err)
					}

					// Update progress
					keyfileDone += size
					s.progress = float32(keyfileDone) / float32(keyfileTotal)
					s.update()
				}
				if err := fin.Close(); err != nil {
					panic(err)
				}

				sum := tmp.Sum(nil) // Get the SHA3-256

				// XOR keyfile hash with 'keyfileKey'
				if keyfileKey == nil {
					keyfileKey = sum
				} else {
					for i, j := range sum {
						keyfileKey[i] ^= j
					}
				}
			}

			// Store a hash of 'keyfileKey' for comparison
			tmp := sha3.New256()
			if _, err := tmp.Write(keyfileKey); err != nil {
				panic(err)
			}
			keyfileHash = tmp.Sum(nil)
		}
	}

	s.setPopupStatus("Calculating values...")
	s.update()

	// Hash the encryption key for comparison when decrypting
	tmp := sha3.New512()
	if _, err := tmp.Write(key); err != nil {
		panic(err)
	}
	keyHash = tmp.Sum(nil)

	// Validate the password and/or keyfiles
	if s.mode == "decrypt" {
		keyCorrect := subtle.ConstantTimeCompare(keyHash, keyHashRef) == 1
		keyfileCorrect := subtle.ConstantTimeCompare(keyfileHash, keyfileHashRef) == 1
		incorrect := !keyCorrect
		if s.keyfile || len(s.Keyfiles) > 0 {
			incorrect = !keyCorrect || !keyfileCorrect
		}

		// If something is incorrect
		if incorrect {
			if s.Keep {
				s.kept = true
			} else {
				if !keyCorrect {
					s.mainStatus = "The provided password is incorrect"
				} else {
					if s.KeyfileOrdered {
						s.mainStatus = "Incorrect keyfiles or ordering"
					} else {
						s.mainStatus = "Incorrect keyfiles"
					}
					if s.Deniability {
						fin.Close()
						os.Remove(s.inputFile)
						s.inputFile = strings.TrimSuffix(s.inputFile, ".tmp")
					}
				}
				s.broken(fin, nil, s.mainStatus, true)
				if s.recombine {
					s.inputFile = s.inputFileOld
				}
				return
			}
		}

		// Create the output file for decryption
		fout, err = os.Create(s.OutputFile + ".incomplete")
		if err != nil {
			fin.Close()
			if s.recombine {
				os.Remove(s.inputFile)
			}
			s.accessDenied("Write")
			return
		}
	}

	if len(s.Keyfiles) > 0 || s.keyfile {
		// Prevent an even number of duplicate keyfiles
		if bytes.Equal(keyfileKey, make([]byte, 32)) {
			s.setMainStatus("Duplicate keyfiles detected", ColorRed)
			fin.Close()
			if len(s.allFiles) > 1 || len(s.onlyFolders) > 0 || s.Compress {
				os.Remove(s.inputFile)
			}
			fout.Close()
			os.Remove(fout.Name())
			return
		}

		// XOR the encryption key with the keyfile key
		tmp := key
		key = make([]byte, 32)
		for i := range key {
			key[i] = tmp[i] ^ keyfileKey[i]
		}
	}

	done, counter := 0, 0
	chacha, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}

	// Use HKDF-SHA3 to generate a subkey for the MAC
	var mac hash.Hash
	subkey := make([]byte, 32)
	hkdf := hkdf.New(sha3.New256, key, hkdfSalt, nil)
	if n, err := hkdf.Read(subkey); err != nil || n != 32 {
		panic(errors.New("fatal hkdf.Read error"))
	}
	if s.Paranoid {
		mac = hmac.New(sha3.New512, subkey) // HMAC-SHA3
	} else {
		mac, err = blake2b.New512(subkey) // Keyed BLAKE2b
		if err != nil {
			panic(err)
		}
	}

	// Generate another subkey for use as Serpent's key
	serpentKey := make([]byte, 32)
	if n, err := hkdf.Read(serpentKey); err != nil || n != 32 {
		panic(errors.New("fatal hkdf.Read error"))
	}
	sb, err := serpent.NewCipher(serpentKey) // 's' in the original; renamed (receiver conflict)
	if err != nil {
		panic(err)
	}
	serpent := cipher.NewCTR(sb, serpentIV)

	// Start the main encryption process
	s.canCancel = true
	startTime := time.Now()
	tempZip := encryptedZipReader{
		_r:      fin,
		_cipher: tempZipCipherR,
	}
	for {
		if !s.working.Load() {
			s.cancel(fin, fout)
			if s.recombine || len(s.allFiles) > 1 || len(s.onlyFolders) > 0 || s.Compress {
				os.Remove(s.inputFile)
			}
			os.Remove(fout.Name())
			return
		}

		// Read in data from the file
		var src []byte
		if s.mode == "decrypt" && s.Reedsolo {
			src = make([]byte, MiB/128*136)
		} else {
			src = make([]byte, MiB)
		}

		var size int
		if tempZipInUse {
			size, err = tempZip.Read(src)
		} else {
			size, err = fin.Read(src)
		}
		if err != nil {
			break
		}
		src = src[:size]
		dst := make([]byte, len(src))

		// Do the actual encryption
		if s.mode == "encrypt" {
			if s.Paranoid {
				serpent.XORKeyStream(dst, src)
				copy(src, dst)
			}

			chacha.XORKeyStream(dst, src)
			if _, err := mac.Write(dst); err != nil {
				panic(err)
			}

			if s.Reedsolo {
				copy(src, dst)
				dst = nil
				// If a full MiB is available
				if len(src) == MiB {
					// Encode every chunk
					for i := 0; i < MiB; i += 128 {
						dst = append(dst, rsEncode(rs128, src[i:i+128])...)
					}
				} else {
					// Encode the full chunks
					chunks := math.Floor(float64(len(src)) / 128)
					for i := 0; float64(i) < chunks; i++ {
						dst = append(dst, rsEncode(rs128, src[i*128:(i+1)*128])...)
					}

					// Pad and encode the final partial chunk
					dst = append(dst, rsEncode(rs128, pad(src[int(chunks*128):]))...)
				}
			}
		} else { // Decryption
			if s.Reedsolo {
				copy(dst, src)
				src = nil
				// If a complete 1 MiB block is available
				if len(dst) == MiB/128*136 {
					// Decode every chunk
					for i := 0; i < MiB/128*136; i += 136 {
						tmp, err := s.rsDecode(rs128, dst[i:i+136])
						if err != nil {
							if s.Keep {
								s.kept = true
							} else {
								s.broken(fin, fout, "The input file is irrecoverably damaged", false)
								return
							}
						}
						if i == MiB/128*136-136 && done+MiB/128*136 >= int(total) && padded {
							tmp = unpad(tmp)
						}
						src = append(src, tmp...)

						if !s.fastDecode && i%17408 == 0 {
							s.progress, s.speed, s.eta = statify(int64(done+i), total, startTime)
							s.progressInfo = fmt.Sprintf("%.2f%%", s.progress*100)
							s.setPopupStatus(fmt.Sprintf("Repairing at %.2f MiB/s (ETA: %s)", s.speed, s.eta))
							s.update()
						}
					}
				} else {
					// Decode the full chunks
					chunks := len(dst)/136 - 1
					for i := range chunks {
						tmp, err := s.rsDecode(rs128, dst[i*136:(i+1)*136])
						if err != nil {
							if s.Keep {
								s.kept = true
							} else {
								s.broken(fin, fout, "The input file is irrecoverably damaged", false)
								return
							}
						}
						src = append(src, tmp...)

						if !s.fastDecode && i%128 == 0 {
							s.progress, s.speed, s.eta = statify(int64(done+i*136), total, startTime)
							s.progressInfo = fmt.Sprintf("%.2f%%", s.progress*100)
							s.setPopupStatus(fmt.Sprintf("Repairing at %.2f MiB/s (ETA: %s)", s.speed, s.eta))
							s.update()
						}
					}

					// Unpad and decode the final partial chunk
					tmp, err := s.rsDecode(rs128, dst[int(chunks)*136:])
					if err != nil {
						if s.Keep {
							s.kept = true
						} else {
							s.broken(fin, fout, "The input file is irrecoverably damaged", false)
							return
						}
					}
					src = append(src, unpad(tmp)...)
				}
				dst = make([]byte, len(src))
			}

			if _, err := mac.Write(src); err != nil {
				panic(err)
			}
			chacha.XORKeyStream(dst, src)

			if s.Paranoid {
				copy(src, dst)
				serpent.XORKeyStream(dst, src)
			}
		}

		// Write the data to output file
		_, err = fout.Write(dst)
		if err != nil {
			s.insufficientSpace(fin, fout)
			if s.recombine || len(s.allFiles) > 1 || len(s.onlyFolders) > 0 || s.Compress {
				os.Remove(s.inputFile)
			}
			os.Remove(fout.Name())
			return
		}

		// Update stats
		if s.mode == "decrypt" && s.Reedsolo {
			done += MiB / 128 * 136
		} else {
			done += MiB
		}
		counter += MiB
		s.progress, s.speed, s.eta = statify(int64(done), total, startTime)
		s.progressInfo = fmt.Sprintf("%.2f%%", s.progress*100)
		if s.mode == "encrypt" {
			s.setPopupStatus(fmt.Sprintf("Encrypting at %.2f MiB/s (ETA: %s)", s.speed, s.eta))
		} else {
			if s.fastDecode {
				s.setPopupStatus(fmt.Sprintf("Decrypting at %.2f MiB/s (ETA: %s)", s.speed, s.eta))
			}
		}
		s.update()

		// Change nonce/IV after 60 GiB to prevent overflow
		if counter >= 60*GiB {
			// ChaCha20
			nonce = make([]byte, 24)
			if n, err := hkdf.Read(nonce); err != nil || n != 24 {
				panic(errors.New("fatal hkdf.Read error"))
			}
			chacha, err = chacha20.NewUnauthenticatedCipher(key, nonce)
			if err != nil {
				panic(err)
			}

			// Serpent
			serpentIV = make([]byte, 16)
			if n, err := hkdf.Read(serpentIV); err != nil || n != 16 {
				panic(errors.New("fatal hkdf.Read error"))
			}
			serpent = cipher.NewCTR(sb, serpentIV)

			// Reset counter to 0
			counter = 0
		}
	}

	s.progress = 0
	s.progressInfo = ""
	s.update()

	if s.mode == "encrypt" {
		s.setPopupStatus("Writing values...")
		s.update()

		// Seek back to header and write important values
		if _, err := fout.Seek(int64(309+len(s.Comments)*3), 0); err != nil {
			panic(err)
		}
		if _, err := fout.Write(rsEncode(rs64, keyHash)); err != nil {
			panic(err)
		}
		if _, err := fout.Write(rsEncode(rs32, keyfileHash)); err != nil {
			panic(err)
		}
		if _, err := fout.Write(rsEncode(rs64, mac.Sum(nil))); err != nil {
			panic(err)
		}
	} else {
		s.setPopupStatus("Comparing values...")
		s.update()

		// Validate the authenticity of decrypted data
		if subtle.ConstantTimeCompare(mac.Sum(nil), authTag) == 0 {
			// Decrypt again but this time rebuilding the input data
			if s.Reedsolo && s.fastDecode {
				s.fastDecode = false
				fin.Close()
				fout.Close()
				s.work()
				return
			}

			if s.Keep {
				s.kept = true
			} else {
				s.broken(fin, fout, "The input file is damaged or modified", false)
				return
			}
		}
	}

	if err := fin.Close(); err != nil {
		panic(err)
	}
	if err := fout.Close(); err != nil {
		panic(err)
	}

	if err := os.Rename(s.OutputFile+".incomplete", s.OutputFile); err != nil {
		panic(err)
	}

	// Add plausible deniability
	if s.mode == "encrypt" && s.Deniability {
		s.setPopupStatus("Adding plausible deniability...")
		s.canCancel = false
		s.update()

		// Get size of volume for showing progress
		stat, err := os.Stat(s.OutputFile)
		if err != nil {
			panic(err)
		}
		total := stat.Size()

		// Rename the output volume to free up the filename
		os.Rename(s.OutputFile, s.OutputFile+".tmp")
		fin, err := os.Open(s.OutputFile + ".tmp")
		if err != nil {
			panic(err)
		}
		fout, err := os.Create(s.OutputFile + ".incomplete")
		if err != nil {
			panic(err)
		}

		// Use a random Argon2 salt and XChaCha20 nonce
		salt := make([]byte, 16)
		nonce := make([]byte, 24)
		if n, err := rand.Read(salt); err != nil || n != 16 {
			panic(errors.New("fatal crypto/rand error"))
		}
		if n, err := rand.Read(nonce); err != nil || n != 24 {
			panic(errors.New("fatal crypto/rand error"))
		}
		if bytes.Equal(salt, make([]byte, 16)) || bytes.Equal(nonce, make([]byte, 24)) {
			panic(errors.New("fatal crypto/rand error"))
		}
		if _, err := fout.Write(salt); err != nil {
			panic(err)
		}
		if _, err := fout.Write(nonce); err != nil {
			panic(err)
		}

		// Generate key and XChaCha20
		key := argon2.IDKey([]byte(s.Password), salt, 4, 1<<20, 4, 32)
		if bytes.Equal(key, make([]byte, 32)) {
			panic(errors.New("fatal crypto/argon2 error"))
		}
		chacha, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			panic(err)
		}

		// Encrypt the entire volume
		done, counter := 0, 0
		for {
			src := make([]byte, MiB)
			size, err := fin.Read(src)
			if err != nil {
				break
			}
			src = src[:size]
			dst := make([]byte, len(src))
			chacha.XORKeyStream(dst, src)
			if _, err := fout.Write(dst); err != nil {
				panic(err)
			}

			// Update stats
			done += size
			counter += MiB
			s.progress = float32(float64(done) / float64(total))
			s.update()

			// Change nonce after 60 GiB to prevent overflow
			if counter >= 60*GiB {
				tmp := sha3.New256()
				if _, err := tmp.Write(nonce); err != nil {
					panic(err)
				}
				nonce = tmp.Sum(nil)[:24]
				chacha, err = chacha20.NewUnauthenticatedCipher(key, nonce)
				if err != nil {
					panic(err)
				}
				counter = 0
			}
		}

		if err := fin.Close(); err != nil {
			panic(err)
		}
		if err := fout.Close(); err != nil {
			panic(err)
		}
		if err := os.Remove(fin.Name()); err != nil {
			panic(err)
		}
		if err := os.Rename(s.OutputFile+".incomplete", s.OutputFile); err != nil {
			panic(err)
		}
		s.canCancel = true
		s.update()
	}

	// Split the file into chunks
	if s.Split {
		var splitted []string
		stat, err := os.Stat(s.OutputFile)
		if err != nil {
			panic(err)
		}
		size := stat.Size()
		finishedFiles := 0
		finishedBytes := 0
		chunkSize, err := strconv.Atoi(s.SplitSize)
		if err != nil {
			panic(err)
		}

		// Calculate chunk size
		if s.SplitSelected == 0 {
			chunkSize *= KiB
		} else if s.SplitSelected == 1 {
			chunkSize *= MiB
		} else if s.SplitSelected == 2 {
			chunkSize *= GiB
		} else if s.SplitSelected == 3 {
			chunkSize *= TiB
		} else {
			chunkSize = int(math.Ceil(float64(size) / float64(chunkSize)))
		}

		// Get the number of required chunks
		chunks := int(math.Ceil(float64(size) / float64(chunkSize)))
		s.progressInfo = fmt.Sprintf("%d/%d", finishedFiles+1, chunks)
		s.update()

		// Open the volume for reading
		fin, err := os.Open(s.OutputFile)
		if err != nil {
			panic(err)
		}

		// Delete existing chunks to prevent mixed chunks
		names, err := filepath.Glob(s.OutputFile + ".*")
		if err != nil {
			panic(err)
		}
		for _, i := range names {
			if err := os.Remove(i); err != nil {
				panic(err)
			}
		}

		// Start the splitting process
		startTime := time.Now()
		for i := range chunks {
			// Make the chunk
			fout, _ := os.Create(fmt.Sprintf("%s.%d.incomplete", s.OutputFile, i))
			done := 0

			// Copy data into the chunk
			for {
				data := make([]byte, MiB)
				for done+len(data) > chunkSize {
					data = make([]byte, int(math.Ceil(float64(len(data))/2)))
				}

				read, err := fin.Read(data)
				if err != nil {
					break
				}
				if !s.working.Load() {
					s.cancel(fin, fout)
					if len(s.allFiles) > 1 || len(s.onlyFolders) > 0 || s.Compress {
						os.Remove(s.inputFile)
					}
					os.Remove(s.OutputFile)
					for _, j := range splitted { // Remove existing chunks
						os.Remove(j)
					}
					os.Remove(fmt.Sprintf("%s.%d", s.OutputFile, i))
					return
				}

				data = data[:read]
				_, err = fout.Write(data)
				if err != nil {
					s.insufficientSpace(fin, fout)
					if len(s.allFiles) > 1 || len(s.onlyFolders) > 0 || s.Compress {
						os.Remove(s.inputFile)
					}
					os.Remove(s.OutputFile)
					for _, j := range splitted { // Remove existing chunks
						os.Remove(j)
					}
					os.Remove(fmt.Sprintf("%s.%d", s.OutputFile, i))
					return
				}
				done += read
				if done >= chunkSize {
					break
				}

				// Update stats
				finishedBytes += read
				s.progress, s.speed, s.eta = statify(int64(finishedBytes), int64(size), startTime)
				s.setPopupStatus(fmt.Sprintf("Splitting at %.2f MiB/s (ETA: %s)", s.speed, s.eta))
				s.update()
			}
			if err := fout.Close(); err != nil {
				panic(err)
			}

			// Update stats
			finishedFiles++
			if finishedFiles == chunks {
				finishedFiles--
			}
			splitted = append(splitted, fmt.Sprintf("%s.%d", s.OutputFile, i))
			s.progressInfo = fmt.Sprintf("%d/%d", finishedFiles+1, chunks)
			s.update()
		}

		if err := fin.Close(); err != nil {
			panic(err)
		}
		if err := os.Remove(s.OutputFile); err != nil {
			panic(err)
		}
		names, err = filepath.Glob(s.OutputFile + ".*.incomplete")
		if err != nil {
			panic(err)
		}
		for _, i := range names {
			if err := os.Rename(i, strings.TrimSuffix(i, ".incomplete")); err != nil {
				panic(err)
			}
		}
	}

	s.canCancel = false
	s.progress = 0
	s.progressInfo = ""
	s.update()

	// Delete temporary files used during encryption and decryption
	if s.recombine || len(s.allFiles) > 1 || len(s.onlyFolders) > 0 || s.Compress {
		if err := os.Remove(s.inputFile); err != nil {
			panic(err)
		}
		if s.Deniability {
			os.Remove(strings.TrimSuffix(s.inputFile, ".tmp"))
		}
	}

	// Delete the input files if the user chooses
	if s.Delete {
		s.setPopupStatus("Deleting files...")
		s.update()

		if s.mode == "decrypt" {
			if s.recombine { // Remove each chunk of volume
				i := 0
				for {
					_, err := os.Stat(fmt.Sprintf("%s.%d", s.inputFileOld, i))
					if err != nil {
						break
					}
					if err := os.Remove(fmt.Sprintf("%s.%d", s.inputFileOld, i)); err != nil {
						panic(err)
					}
					i++
				}
			} else {
				if err := os.Remove(s.inputFile); err != nil {
					panic(err)
				}
				if s.Deniability {
					if err := os.Remove(strings.TrimSuffix(s.inputFile, ".tmp")); err != nil {
						panic(err)
					}
				}
			}
		} else {
			for _, i := range s.onlyFiles {
				if err := os.Remove(i); err != nil {
					panic(err)
				}
			}
			for _, i := range s.onlyFolders {
				if err := os.RemoveAll(i); err != nil {
					panic(err)
				}
			}
		}
	}
	if s.mode == "decrypt" && s.Deniability {
		os.Remove(s.inputFile)
	}

	if s.mode == "decrypt" && !s.kept && s.AutoUnzip {
		s.setPopupStatus("Unzipping...")
		s.update()

		if err := s.unpackArchive(s.OutputFile); err != nil {
			s.setMainStatus("Auto unzipping failed!", ColorRed)
			s.update()
			return
		}

		if err := os.Remove(s.OutputFile); err != nil {
			panic(err)
		}
	}

	// All done, reset the UI
	oldKept := s.kept
	s.resetUI()
	s.kept = oldKept

	// If the user chose to keep a corrupted/modified file, let them know
	if s.kept {
		s.setMainStatus("The input file was modified. Please be careful", ColorYellow)
	} else {
		s.setMainStatus("Completed", ColorGreen)
	}
}

package core

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DropFiles is onDrop (Picocrypt.go L847-1174). The 'showKeyfile' branch of
// the original is selected with asKeyfiles=true. All UI interactions are
// replaced by state fields plus a single OnState emission at the end.
func (s *Session) DropFiles(names []string, asKeyfiles bool) {
	defer s.emitState()

	if asKeyfiles {
		s.Keyfiles = append(s.Keyfiles, names...)

		// Make sure keyfiles are accessible, remove duplicates
		var tmp []string
		for _, i := range s.Keyfiles {
			duplicate := false
			for _, j := range tmp {
				if i == j {
					duplicate = true
				}
			}
			stat, statErr := os.Stat(i)
			fin, err := os.Open(i)
			if err == nil {
				fin.Close()
			} else {
				s.resetUI()
				s.accessDenied("Keyfile read")
				s.update()
				return
			}
			if !duplicate && statErr == nil && !stat.IsDir() {
				tmp = append(tmp, i)
			}
		}
		s.Keyfiles = tmp

		// Update the keyfile status
		if len(s.Keyfiles) == 0 {
			s.keyfileLabel = "None selected"
		} else if len(s.Keyfiles) == 1 {
			s.keyfileLabel = "Using 1 keyfile"
		} else {
			s.keyfileLabel = fmt.Sprintf("Using %d keyfiles", len(s.Keyfiles))
		}

		s.update()
		return
	}

	s.scanning = true
	files, folders := 0, 0
	s.compressDone, s.compressTotal = 0, 0
	s.resetUI()

	// One item dropped
	if len(names) == 1 {
		stat, err := os.Stat(names[0])
		if err != nil {
			s.setMainStatus("Failed to stat dropped item", ColorRed)
			s.update()
			return
		}

		// A folder was dropped
		if stat.IsDir() {
			folders++
			s.mode = "encrypt"
			s.inputLabel = "1 folder"
			s.startLabel = "Zip and Encrypt"
			s.onlyFolders = append(s.onlyFolders, names[0])
			s.inputFile = filepath.Join(filepath.Dir(names[0]), "encrypted-"+strconv.Itoa(int(time.Now().Unix()))) + ".zip"
			s.OutputFile = s.inputFile + ".pcv"
		} else { // A file was dropped
			files++
			s.requiredFreeSpace = stat.Size()

			// Is the file a part of a split volume?
			nums := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
			endsNum := false
			for _, i := range nums {
				if strings.HasSuffix(names[0], i) {
					endsNum = true
				}
			}
			isSplit := strings.Contains(names[0], ".pcv.") && endsNum

			// Decide if encrypting or decrypting
			if strings.HasSuffix(names[0], ".pcv") || isSplit {
				s.mode = "decrypt"
				s.inputLabel = "Volume for decryption"
				s.startLabel = "Decrypt"
				s.commentsLabel = "Comments (read-only):"
				s.commentsDisabled = true

				// Get the correct input and output filenames
				if isSplit {
					ind := strings.Index(names[0], ".pcv")
					names[0] = names[0][:ind+4]
					s.inputFile = names[0]
					s.OutputFile = names[0][:ind]
					s.recombine = true

					// Find out the number of splitted chunks
					totalFiles := 0
					for {
						stat, err := os.Stat(fmt.Sprintf("%s.%d", s.inputFile, totalFiles))
						if err != nil {
							break
						}
						totalFiles++
						s.compressTotal += stat.Size()
					}
					s.requiredFreeSpace = s.compressTotal
				} else {
					s.OutputFile = names[0][:len(names[0])-4]
				}

				// Open the input file in read-only mode
				var fin *os.File
				var err error
				if isSplit {
					fin, err = os.Open(names[0] + ".0")
				} else {
					fin, err = os.Open(names[0])
				}
				if err != nil {
					s.resetUI()
					s.accessDenied("Read")
					s.update()
					return
				}

				// Check if version can be read from header
				tmp := make([]byte, 15)
				if n, err := fin.Read(tmp); err != nil || n != 15 {
					fin.Close()
					s.setMainStatus("Failed to read 15 bytes from file", ColorRed)
					s.update()
					return
				}
				tmp, err = s.rsDecode(rs5, tmp)
				if valid, _ := regexp.Match(`^v\d\.\d{2}`, tmp); err != nil || !valid {
					// Volume has plausible deniability
					s.Deniability = true
					s.mainStatus = "Can't read header, assuming volume is deniable"
					fin.Close()
					s.update()
				} else {
					// Read comments from file and check for corruption
					tmp = make([]byte, 15)
					if n, err := fin.Read(tmp); err != nil || n != 15 {
						fin.Close()
						s.setMainStatus("Failed to read 15 bytes from file", ColorRed)
						s.update()
						return
					}
					tmp, err = s.rsDecode(rs5, tmp)
					if err == nil {
						commentsLength, err := strconv.Atoi(string(tmp))
						if err != nil {
							s.Comments = "Comment length is corrupted"
							s.update()
						} else {
							tmp = make([]byte, commentsLength*3)
							if n, err := fin.Read(tmp); err != nil || n != commentsLength*3 {
								fin.Close()
								s.setMainStatus("Failed to read comments from file", ColorRed)
								s.update()
								return
							}
							s.Comments = ""
							for i := 0; i < commentsLength*3; i += 3 {
								t, err := s.rsDecode(rs1, tmp[i:i+3])
								if err != nil {
									s.Comments = "Comments are corrupted"
									break
								}
								s.Comments += string(t)
							}
							s.update()
						}
					} else {
						s.Comments = "Comments are corrupted"
						s.update()
					}

					// Read flags from file and check for corruption
					flags := make([]byte, 15)
					if n, err := fin.Read(flags); err != nil || n != 15 {
						fin.Close()
						s.setMainStatus("Failed to read 15 bytes from file", ColorRed)
						s.update()
						return
					}
					if err := fin.Close(); err != nil {
						panic(err)
					}
					flags, err = s.rsDecode(rs5, flags)
					if err != nil {
						s.setMainStatus("The volume header is damaged", ColorRed)
						s.update()
						return
					}

					// Update UI and variables according to flags
					if flags[1] == 1 {
						s.keyfile = true
						s.keyfileLabel = "Keyfiles required"
					} else {
						s.keyfileLabel = "Not applicable"
					}
					if flags[2] == 1 {
						s.KeyfileOrdered = true
					}
					s.update()
				}
			} else { // One file was dropped for encryption
				s.mode = "encrypt"
				s.inputLabel = "1 file"
				s.startLabel = "Encrypt"
				s.inputFile = names[0]
				s.OutputFile = names[0] + ".pcv"
				s.update()
			}

			// Add the file
			s.onlyFiles = append(s.onlyFiles, names[0])
			s.inputFile = names[0]
			if !isSplit {
				s.compressTotal += stat.Size()
			}
			s.update()
		}
	} else { // There are multiple dropped items
		s.mode = "encrypt"
		s.startLabel = "Zip and Encrypt"

		// Go through each dropped item and add to corresponding slices
		for _, name := range names {
			stat, err := os.Stat(name)
			if err != nil {
				s.resetUI()
				s.setMainStatus("Failed to stat dropped items", ColorRed)
				s.update()
				return
			}
			if stat.IsDir() {
				folders++
				s.onlyFolders = append(s.onlyFolders, name)
			} else {
				files++
				s.onlyFiles = append(s.onlyFiles, name)
				s.allFiles = append(s.allFiles, name)

				s.compressTotal += stat.Size()
				s.requiredFreeSpace += stat.Size()
				s.inputLabel = fmt.Sprintf("Scanning files... (%s)", sizeify(s.compressTotal))
				s.update()
			}
		}

		// Update UI with the number of files and folders selected
		if folders == 0 {
			s.inputLabel = fmt.Sprintf("%d files", files)
		} else if files == 0 {
			s.inputLabel = fmt.Sprintf("%d folders", folders)
		} else {
			if files == 1 && folders > 1 {
				s.inputLabel = fmt.Sprintf("1 file and %d folders", folders)
			} else if folders == 1 && files > 1 {
				s.inputLabel = fmt.Sprintf("%d files and 1 folder", files)
			} else if folders == 1 && files == 1 {
				s.inputLabel = "1 file and 1 folder"
			} else {
				s.inputLabel = fmt.Sprintf("%d files and %d folders", files, folders)
			}
		}

		// Set the input and output paths
		s.inputFile = filepath.Join(filepath.Dir(names[0]), "encrypted-"+strconv.Itoa(int(time.Now().Unix()))) + ".zip"
		s.OutputFile = s.inputFile + ".pcv"
		s.update()
	}

	// Recursively add all files in 'onlyFolders' to 'allFiles'.
	// The original runs this in a goroutine (Picocrypt.go L1134-1173) to keep
	// the UI responsive; core runs it synchronously so that DropFiles returns
	// with a complete, consistent state.
	oldInputLabel := s.inputLabel
	for _, name := range s.onlyFolders {
		if filepath.Walk(name, func(path string, _ os.FileInfo, err error) error {
			if err != nil {
				s.resetUI()
				s.setMainStatus("Failed to walk through dropped items", ColorRed)
				s.update()
				return err
			}
			stat, err := os.Stat(path)
			if err != nil {
				s.resetUI()
				s.setMainStatus("Failed to walk through dropped items", ColorRed)
				s.update()
				return err
			}
			// If 'path' is a valid file path, add to 'allFiles'
			if !stat.IsDir() {
				s.allFiles = append(s.allFiles, path)
				s.compressTotal += stat.Size()
				s.requiredFreeSpace += stat.Size()
				s.inputLabel = fmt.Sprintf("Scanning files... (%s)", sizeify(s.compressTotal))
				s.update()
			}
			return nil
		}) != nil {
			s.resetUI()
			s.setMainStatus("Failed to walk through dropped items", ColorRed)
			s.update()
			return
		}
	}
	s.inputLabel = fmt.Sprintf("%s (%s)", oldInputLabel, sizeify(s.compressTotal))
	s.scanning = false
	s.update()
}

// Reset is resetUI (Picocrypt.go L2634-2692): reset the session to a clean
// state with nothing selected or checked, then emit the new state.
func (s *Session) Reset() {
	s.resetUI()
	s.emitState()
}

// ResetQuiet is Reset without the state emission (service-layer convenience:
// the service emits one consolidated final state itself).
func (s *Session) ResetQuiet() {
	s.resetUI()
}

// resetUI resets all fields. The original also cleared passgen/password
// visibility variables, which are UI-only and thus not part of core.
func (s *Session) resetUI() {
	s.mode = ""

	s.inputFile = ""
	s.inputFileOld = ""
	s.OutputFile = ""
	s.onlyFiles = nil
	s.onlyFolders = nil
	s.allFiles = nil
	s.inputLabel = "Drop files and folders into this window"

	s.Password = ""
	s.CPassword = ""

	s.keyfile = false
	s.Keyfiles = nil
	s.KeyfileOrdered = false
	s.keyfileLabel = "None selected"

	s.Comments = ""
	s.commentsLabel = "Comments:"
	s.commentsDisabled = false

	s.Paranoid = false
	s.Reedsolo = false
	s.Deniability = false
	s.Recursively = false
	s.Split = false
	s.SplitSize = ""
	s.SplitSelected = 1
	s.recombine = false
	s.Compress = false
	s.Delete = false
	s.AutoUnzip = false
	s.SameLevel = false
	s.Keep = false
	s.kept = false

	s.startLabel = "Start"
	s.mainStatus = "Ready"
	s.mainStatusColor = ColorWhite
	s.popupStatus = ""
	s.requiredFreeSpace = 0

	s.progress = 0
	s.progressInfo = ""
	s.update()
}

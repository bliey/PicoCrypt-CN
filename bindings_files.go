// bindings_files.go — 暴露给前端的绑定方法：文件与输入类
// （拖放、文件/文件夹选择、密钥文件、输出路径、清除）。
package main

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// HandleDrop 处理窗口拖放事件（供 main.go 使用）。
func (svc *CryptoService) HandleDrop(paths []string) {
	svc.mu.Lock()
	kf := svc.keyfileDrops
	svc.mu.Unlock()
	if len(paths) > 0 {
		svc.rememberStartDir(paths)
		svc.session.DropFiles(paths, kf)
		if !kf {
			svc.applyDefaultOutputDir()
		}
	}
}

// DropFiles 由前端拖放或选择文件后调用（与原版 onDrop 等价）。
func (svc *CryptoService) DropFiles(paths []string, asKeyfiles bool) {
	if svc.session.Working() || len(paths) == 0 {
		return
	}
	svc.rememberStartDir(paths)
	svc.session.DropFiles(paths, asKeyfiles)
	if !asKeyfiles {
		svc.applyDefaultOutputDir()
	}
}

// applyDefaultOutputDir 在设置了默认输出目录且用户未手动指定时，替换输出目录。
func (svc *CryptoService) applyDefaultOutputDir() {
	svc.mu.Lock()
	dir := svc.settings.DefaultOutputDir
	svc.mu.Unlock()
	if dir == "" || svc.session.OutputFile == "" {
		return
	}
	svc.session.OutputFile = filepath.Join(dir, filepath.Base(svc.session.OutputFile))
	svc.pushState()
}

// SetKeyfileDropMode 设置拖放是否进入密钥文件列表（密钥文件面板开关）。
func (svc *CryptoService) SetKeyfileDropMode(on bool) {
	svc.mu.Lock()
	svc.keyfileDrops = on
	svc.mu.Unlock()
}

// PickFiles 弹出多选文件对话框并作为输入。
func (svc *CryptoService) PickFiles() {
	paths, err := svc.app.Dialog.OpenFile().
		SetTitle("选择文件").
		SetDirectory(svc.startDir).
		PromptForMultipleSelection()
	if err != nil || len(paths) == 0 {
		return
	}
	svc.DropFiles(paths, false)
}

// PickFolder 弹出文件夹选择对话框并作为输入。
func (svc *CryptoService) PickFolder() {
	path, err := svc.app.Dialog.OpenFile().
		SetTitle("选择文件夹").
		SetDirectory(svc.startDir).
		CanChooseDirectories(true).
		CanChooseFiles(false).
		PromptForSingleSelection()
	if err != nil || path == "" {
		return
	}
	svc.DropFiles([]string{path}, false)
}

// PickKeyfiles 弹出多选对话框添加密钥文件。
func (svc *CryptoService) PickKeyfiles() {
	paths, err := svc.app.Dialog.OpenFile().
		SetTitle("选择密钥文件").
		SetDirectory(svc.startDir).
		PromptForMultipleSelection()
	if err != nil || len(paths) == 0 {
		return
	}
	svc.session.DropFiles(paths, true)
}

// CreateKeyfile 在指定位置生成 32 字节随机密钥文件（与原版一致）。
func (svc *CryptoService) CreateKeyfile() string {
	path, err := svc.app.Dialog.SaveFile().
		SetMessage("选择密钥文件的保存位置").
		SetDirectory(svc.startDir).
		SetFilename("keyfile-" + strconv.Itoa(int(time.Now().Unix())) + ".bin").
		PromptForSingleSelection()
	if err != nil || path == "" {
		return ""
	}
	fout, err := os.Create(path)
	if err != nil {
		return "创建密钥文件失败"
	}
	data := make([]byte, 32)
	if n, err := rand.Read(data); err != nil || n != 32 {
		fout.Close()
		return "创建密钥文件失败"
	}
	n, err := fout.Write(data)
	if err != nil || n != 32 {
		fout.Close()
		return "创建密钥文件失败"
	}
	if err := fout.Close(); err != nil {
		return "创建密钥文件失败"
	}
	return ""
}

// ClearKeyfiles 清空已选密钥文件。
func (svc *CryptoService) ClearKeyfiles() {
	svc.session.Keyfiles = nil
	svc.pushState()
}

// PickOutput 弹出保存对话框修改输出路径（与原版 "Change" 按钮逻辑一致）。
func (svc *CryptoService) PickOutput() {
	s := svc.session
	if s.Working() {
		return
	}
	path, err := svc.app.Dialog.SaveFile().
		SetMessage("选择输出文件的保存位置（无需输入扩展名）").
		SetDirectory(svc.startDir).
		SetFilename("").
		PromptForSingleSelection()
	if err != nil || path == "" {
		return
	}
	// 去掉用户输入的所有扩展名（原版行为）
	path = filepath.Join(filepath.Dir(path), strings.Split(filepath.Base(path), ".")[0])

	// 根据模式补全扩展名（原版 draw() 的 Change 逻辑）
	multiple := s.HasMultipleInputs()
	if s.CurrentMode() == "encrypt" {
		if multiple || s.Compress {
			path += ".zip.pcv"
		} else {
			path += filepath.Ext(s.InputFile()) + ".pcv"
		}
	} else {
		if strings.HasSuffix(s.InputFile(), ".zip.pcv") {
			path += ".zip"
		} else {
			tmp := strings.TrimSuffix(filepath.Base(s.InputFile()), ".pcv")
			path += filepath.Ext(tmp)
		}
	}
	s.OutputFile = path
	svc.pushState()
}

// Clear 重置全部状态（对应原版 "Clear" 按钮）。
func (svc *CryptoService) Clear() {
	if svc.session.Working() {
		return
	}
	svc.mu.Lock()
	svc.resetNonce++
	svc.opts = Options{}
	svc.mu.Unlock()
	svc.session.Reset()
}

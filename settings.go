package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Settings 是持久化到本地配置文件的全部设置项。
type Settings struct {
	RememberOptions  bool     `json:"rememberOptions"`  // 记住上次的选项状态
	DefaultOutputDir string   `json:"defaultOutputDir"` // 默认输出目录（空 = 不设置）
	Language         string   `json:"language"`         // "zh" | "en"
	SavedOptions     Options  `json:"savedOptions"`     // RememberOptions 开启时保存的选项
	SavedComments    string   `json:"savedComments"`    // RememberOptions 开启时保存的注释
}

// SavedForm 是启动时恢复给前端表单的选项与注释。
type SavedForm struct {
	Has      bool    `json:"has"`
	Options  Options `json:"options"`
	Comments string  `json:"comments"`
}

// settingsFile 返回配置文件路径（可被测试覆盖）。
var settingsFile = defaultSettingsPath()

func defaultSettingsPath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		dir = "."
	}
	return filepath.Join(dir, "picocrypt-wails", "settings.json")
}

func defaultSettings() Settings {
	return Settings{Language: "zh"}
}

// loadSettings 读取配置文件；不存在或损坏时静默返回默认值。
func loadSettings() Settings {
	s := defaultSettings()
	data, err := os.ReadFile(settingsFile)
	if err != nil {
		return s
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return defaultSettings()
	}
	if s.Language != "en" {
		s.Language = "zh"
	}
	return s
}

// saveSettings 原子写入配置文件。
func saveSettings(s Settings) {
	if err := os.MkdirAll(filepath.Dir(settingsFile), 0o755); err != nil {
		return
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return
	}
	tmp := settingsFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	os.Rename(tmp, settingsFile)
}

// ---------- 设置相关的前端绑定 ----------

// GetSettings 返回当前设置（设置面板初始化用）。
func (svc *CryptoService) GetSettings() Settings {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	return svc.settings
}

// SetRememberOptions 开关「记住上次的选项状态」；关闭时清空已保存的选项与注释。
func (svc *CryptoService) SetRememberOptions(on bool) {
	svc.mu.Lock()
	svc.settings.RememberOptions = on
	if on {
		svc.settings.SavedOptions = svc.opts
		svc.settings.SavedComments = svc.session.Comments
	} else {
		svc.settings.SavedOptions = Options{}
		svc.settings.SavedComments = ""
	}
	s := svc.settings
	svc.mu.Unlock()
	saveSettings(s)
}

// PickDefaultOutputDir 弹出文件夹选择框设置默认输出目录；取消时返回当前值。
func (svc *CryptoService) PickDefaultOutputDir() string {
	svc.mu.Lock()
	cur := svc.settings.DefaultOutputDir
	svc.mu.Unlock()
	path, err := svc.app.Dialog.OpenFile().
		SetTitle(chooseFolderTitle(svc.lang())).
		SetDirectory(cur).
		CanChooseDirectories(true).
		CanChooseFiles(false).
		PromptForSingleSelection()
	if err != nil || path == "" {
		return cur
	}
	svc.mu.Lock()
	svc.settings.DefaultOutputDir = path
	s := svc.settings
	svc.mu.Unlock()
	saveSettings(s)
	return path
}

// ClearDefaultOutputDir 清空默认输出目录。
func (svc *CryptoService) ClearDefaultOutputDir() {
	svc.mu.Lock()
	svc.settings.DefaultOutputDir = ""
	s := svc.settings
	svc.mu.Unlock()
	saveSettings(s)
}

// SetLanguage 切换界面语言并立即生效（重新推送翻译后的状态）。
func (svc *CryptoService) SetLanguage(lang string) {
	if lang != "en" {
		lang = "zh"
	}
	svc.mu.Lock()
	svc.settings.Language = lang
	s := svc.settings
	svc.mu.Unlock()
	saveSettings(s)
	svc.pushState()
}

// GetSavedForm 返回启动时需要恢复的选项与注释。
func (svc *CryptoService) GetSavedForm() SavedForm {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if !svc.settings.RememberOptions {
		return SavedForm{}
	}
	return SavedForm{
		Has:      true,
		Options:  svc.settings.SavedOptions,
		Comments: svc.settings.SavedComments,
	}
}

// Save 持久化当前设置（OnShutdown 兜底调用）。
func (svc *CryptoService) Save() {
	svc.mu.Lock()
	s := svc.settings
	svc.mu.Unlock()
	saveSettings(s)
}

func (svc *CryptoService) lang() string {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if svc.settings.Language == "en" {
		return "en"
	}
	return "zh"
}

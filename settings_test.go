package main

import (
	"os"
	"path/filepath"
	"testing"
)

// 保存/加载 round-trip
func TestSettingsRoundTrip(t *testing.T) {
	settingsFile = filepath.Join(t.TempDir(), "settings.json")

	s := defaultSettings()
	s.RememberOptions = true
	s.DefaultOutputDir = `C:\some\dir`
	s.Language = "en"
	s.SavedOptions = Options{Paranoid: true, Reedsolo: true, Split: true, SplitSize: "10", SplitSelected: 2, Keep: true, AutoUnzip: true, SameLevel: true}
	s.SavedComments = "测试注释"
	saveSettings(s)

	got := loadSettings()
	if !got.RememberOptions || got.DefaultOutputDir != s.DefaultOutputDir || got.Language != "en" {
		t.Fatalf("基本字段不一致: %+v", got)
	}
	if !got.SavedOptions.Paranoid || !got.SavedOptions.Reedsolo || !got.SavedOptions.Split ||
		got.SavedOptions.SplitSize != "10" || got.SavedOptions.SplitSelected != 2 ||
		!got.SavedOptions.Keep || !got.SavedOptions.AutoUnzip || !got.SavedOptions.SameLevel {
		t.Fatalf("选项不一致: %+v", got.SavedOptions)
	}
	if got.SavedComments != "测试注释" {
		t.Fatalf("注释不一致: %q", got.SavedComments)
	}
}

// 文件不存在 → 默认值
func TestSettingsMissingFile(t *testing.T) {
	settingsFile = filepath.Join(t.TempDir(), "nonexistent", "settings.json")
	got := loadSettings()
	if got.Language != "zh" || got.RememberOptions || got.DefaultOutputDir != "" {
		t.Fatalf("应返回默认值: %+v", got)
	}
}

// 文件损坏 → 默认值
func TestSettingsCorrupted(t *testing.T) {
	settingsFile = filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(settingsFile, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := loadSettings()
	if got.Language != "zh" || got.RememberOptions {
		t.Fatalf("损坏文件应回退默认: %+v", got)
	}
}

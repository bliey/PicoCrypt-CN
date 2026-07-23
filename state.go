// state.go — 状态管理与事件推送：Options/UIState/UIProgress 结构、
// 状态构建（buildState/buildProgress/composeStatus）、事件发射（state/progress，含节流）。
package main

import (
	"fmt"
	"time"

	"picocrypt-wails/internal/core"
)

// Options 是前端同步过来的全部高级选项（对应原版的高级复选框矩阵）。
type Options struct {
	Paranoid       bool   `json:"paranoid"`
	Reedsolo       bool   `json:"reedsolo"`
	Deniability    bool   `json:"deniability"`
	Recursively    bool   `json:"recursively"`
	Split          bool   `json:"split"`
	SplitSize      string `json:"splitSize"`
	SplitSelected  int    `json:"splitSelected"` // 0=KiB 1=MiB 2=GiB 3=TiB 4=Total
	Compress       bool   `json:"compress"`
	Delete         bool   `json:"delete"`
	AutoUnzip      bool   `json:"autoUnzip"`
	SameLevel      bool   `json:"sameLevel"`
	Keep           bool   `json:"keep"`
	KeyfileOrdered bool   `json:"keyfileOrdered"`
}

// UIState 是推送给前端的完整界面状态（全部中文）。
type UIState struct {
	Mode                 string   `json:"mode"` // "" / "encrypt" / "decrypt"
	InputLabel           string   `json:"inputLabel"`
	HasInput             bool     `json:"hasInput"`
	Comments             string   `json:"comments"`
	CommentsDisabled     bool     `json:"commentsDisabled"`
	KeyfileRequired      bool     `json:"keyfileRequired"`
	KeyfileOrderedVolume bool     `json:"keyfileOrderedVolume"`
	Keyfiles             []string `json:"keyfiles"`
	DeniabilityVolume    bool     `json:"deniabilityVolume"`
	AutoUnzipEligible    bool     `json:"autoUnzipEligible"`
	StartLabel           string   `json:"startLabel"`
	Status               string   `json:"status"`
	StatusColor          string   `json:"statusColor"`
	Working              bool     `json:"working"`
	OutputFile           string   `json:"outputFile"`
	MultipleInputs       bool     `json:"multipleInputs"`
	ResetNonce           int      `json:"resetNonce"` // 变化时前端清空表单
}

// UIProgress 是推送给前端的进度状态。
type UIProgress struct {
	Working   bool    `json:"working"`
	Progress  float32 `json:"progress"`
	Speed     float64 `json:"speed"`
	ETA       string  `json:"eta"`
	Status    string  `json:"status"`
	CanCancel bool    `json:"canCancel"`
}

// emitState 是 core.OnState 回调：翻译并广播 "state" 事件。
func (svc *CryptoService) emitState(si core.StateInfo) {
	svc.app.Event.Emit("state", svc.buildState(si))
}

func (svc *CryptoService) pushState() {
	svc.app.Event.Emit("state", svc.buildState(svc.session.Snapshot()))
}

// emitProgress 是 core.OnProgress 回调：节流后广播 "progress" 事件。
func (svc *CryptoService) emitProgress(pi core.ProgressInfo) {
	svc.mu.Lock()
	now := time.Now()
	statusChanged := pi.Status != svc.lastProgStatus
	if !statusChanged && now.Sub(svc.lastEmit) < 100*time.Millisecond && pi.Progress < 1 {
		svc.mu.Unlock()
		return
	}
	svc.lastEmit = now
	svc.lastProgStatus = pi.Status
	svc.mu.Unlock()
	svc.app.Event.Emit("progress", svc.buildProgress(pi))
}

func (svc *CryptoService) buildState(si core.StateInfo) UIState {
	svc.mu.Lock()
	resetNonce := svc.resetNonce
	opts := svc.opts
	svc.mu.Unlock()
	lang := svc.lang()

	st := UIState{
		Mode:                 si.Mode,
		InputLabel:           translateInputLabel(lang, si.InputLabel),
		HasInput:             si.Mode != "",
		Comments:             translateComments(lang, si.Comments),
		CommentsDisabled:     si.CommentsDisabled,
		KeyfileRequired:      si.KeyfileRequired,
		KeyfileOrderedVolume: si.KeyfileOrderedVolume,
		Keyfiles:             svc.session.Keyfiles,
		DeniabilityVolume:    si.DeniabilityVolume,
		AutoUnzipEligible:    si.AutoUnzipEligible,
		StartLabel:           translateStartLabel(lang, si.StartLabel),
		StatusColor:          si.StatusColor,
		Working:              svc.session.Working(),
		OutputFile:           si.OutputFile,
		MultipleInputs:       si.MultipleInputs,
		ResetNonce:           resetNonce,
	}
	st.Status = svc.composeStatus(lang, si, opts)
	return st
}

func (svc *CryptoService) buildProgress(pi core.ProgressInfo) UIProgress {
	return UIProgress{
		Working:   svc.session.Working(),
		Progress:  pi.Progress,
		Speed:     pi.Speed,
		ETA:       pi.ETA,
		Status:    translateProgressStatus(svc.lang(), pi.Status, pi.Speed, pi.ETA),
		CanCancel: pi.CanCancel,
	}
}

// composeStatus 生成状态行：非 Ready 直接翻译；Ready 时按原版逻辑附加磁盘空间提示。
func (svc *CryptoService) composeStatus(lang string, si core.StateInfo, opts Options) string {
	if si.Status != "Ready" {
		return translateStatus(lang, si.Status)
	}
	if si.RequiredFreeSpace > 0 {
		multiplier := int64(1)
		if si.StartLabel == "Zip and Encrypt" { // 需要临时 zip
			multiplier++
		}
		if opts.Deniability || si.DeniabilityVolume { // 加密为勾选，解密为卷探测结果
			multiplier++
		}
		if opts.Split {
			multiplier++
		}
		if si.Recombine {
			multiplier++
		}
		if opts.AutoUnzip {
			multiplier++
		}
		if lang == "en" {
			return fmt.Sprintf("Ready (ensure >%s of disk space is free)", sizeify(si.RequiredFreeSpace*multiplier))
		}
		return fmt.Sprintf("就绪（请确保磁盘剩余空间大于 %s）", sizeify(si.RequiredFreeSpace*multiplier))
	}
	if lang == "en" {
		return "Ready"
	}
	return "就绪"
}

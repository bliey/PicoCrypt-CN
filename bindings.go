// bindings.go — 暴露给前端的绑定方法：选项与会话控制类
// （密码/注释/高级选项同步、密码工具、开始/覆盖确认、状态获取）。
package main

import (
	"picocrypt-wails/internal/core"
)

// SetPassword 同步密码（前端输入时调用）。
func (svc *CryptoService) SetPassword(password, cpassword string) {
	svc.session.Password = password
	svc.session.CPassword = cpassword
}

// SetComments 同步注释；开启「记住选项」时持久化。
func (svc *CryptoService) SetComments(comments string) {
	svc.session.Comments = comments
	svc.mu.Lock()
	if svc.settings.RememberOptions {
		svc.settings.SavedComments = comments
		s := svc.settings
		svc.mu.Unlock()
		saveSettings(s)
		return
	}
	svc.mu.Unlock()
}

// SetOptions 同步高级选项。解密模式下，弱化文件特征与密钥文件顺序由卷头 flags 决定，
// 忽略前端对应字段（原版 UI 中解密时这两项为只读）。开启「记住选项」时持久化。
func (svc *CryptoService) SetOptions(o Options) {
	svc.mu.Lock()
	svc.opts = o
	if svc.settings.RememberOptions {
		svc.settings.SavedOptions = o
		s := svc.settings
		svc.mu.Unlock()
		saveSettings(s)
	} else {
		svc.mu.Unlock()
	}
	s := svc.session
	if s.CurrentMode() != "decrypt" {
		s.Paranoid = o.Paranoid
		s.Reedsolo = o.Reedsolo
		s.Deniability = o.Deniability
		s.Recursively = o.Recursively
		s.Split = o.Split
		s.SplitSize = o.SplitSize
		s.SplitSelected = o.SplitSelected
		s.Compress = o.Compress
		s.Delete = o.Delete
		s.KeyfileOrdered = o.KeyfileOrdered
	} else {
		s.AutoUnzip = o.AutoUnzip
		s.SameLevel = o.SameLevel
		s.Keep = o.Keep
		s.Delete = o.Delete
	}
	svc.pushState()
}

// PasswordStrength 返回密码强度评分（0-4）。
func (svc *CryptoService) PasswordStrength(password string) int {
	return core.PasswordStrength(password)
}

// GeneratePassword 生成随机密码。
func (svc *CryptoService) GeneratePassword(length int, upper, lower, nums, symbols bool) string {
	return core.GenPassword(int32(length), upper, lower, nums, symbols)
}

// Start 开始加解密。返回 "" 表示已启动；返回 "confirm" 表示需要前端确认覆盖；
// 其余返回值为中文错误/提示文本。
func (svc *CryptoService) Start() string {
	s := svc.session
	if s.Working() {
		return "正在处理中，请稍候"
	}
	ok, needConfirm := s.PrepareStart()
	if !ok {
		svc.pushState()
		return ""
	}
	if needConfirm {
		svc.mu.Lock()
		svc.pendingRun = true
		svc.mu.Unlock()
		return "confirm"
	}
	svc.startRun()
	return ""
}

// ConfirmOverwrite 前端答复覆盖确认。
func (svc *CryptoService) ConfirmOverwrite(overwrite bool) {
	svc.mu.Lock()
	if !svc.pendingRun {
		svc.mu.Unlock()
		return
	}
	svc.pendingRun = false
	svc.mu.Unlock()
	if overwrite {
		svc.startRun()
	}
}

// GetState 返回当前完整状态（前端初始化时调用）。
func (svc *CryptoService) GetState() UIState {
	return svc.buildState(svc.session.Snapshot())
}

// PushState 向前端推送一次当前状态（窗口就绪后调用）。
func (svc *CryptoService) PushState() {
	svc.pushState()
}

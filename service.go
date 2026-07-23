// service.go — CryptoService 结构体定义、构造函数与任务生命周期管理。
// 绑定方法见 bindings.go（选项/会话）与 bindings_files.go（文件/输入）；
// 状态构建与事件推送见 state.go；设置见 settings.go；多语言见 i18n.go。
package main

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"picocrypt-wails/internal/core"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// CryptoService 是暴露给前端的 Wails 服务，负责状态机、对话框与事件推送。
type CryptoService struct {
	app     *application.App
	session *core.Session

	mu             sync.Mutex
	opts           Options
	settings       Settings
	keyfileDrops   bool // 密钥文件面板打开时，拖入的文件作为 keyfile
	pendingRun     bool // 已问过覆盖确认、等待前端答复
	resetNonce     int
	startDir       string
	lastEmit       time.Time
	lastProgStatus string
}

func NewCryptoService(app *application.App) *CryptoService {
	svc := &CryptoService{app: app}
	svc.settings = loadSettings()
	svc.newSession()
	svc.restoreSavedForm()
	return svc
}

// restoreSavedForm 在「记住上次的选项状态」开启时，把保存的选项与注释恢复到会话。
func (svc *CryptoService) restoreSavedForm() {
	if !svc.settings.RememberOptions {
		return
	}
	o := svc.settings.SavedOptions
	svc.opts = o
	s := svc.session
	s.Paranoid = o.Paranoid
	s.Reedsolo = o.Reedsolo
	s.Deniability = o.Deniability
	s.Recursively = o.Recursively
	s.Split = o.Split
	s.SplitSize = o.SplitSize
	s.SplitSelected = o.SplitSelected
	s.Compress = o.Compress
	s.Delete = o.Delete
	s.AutoUnzip = o.AutoUnzip
	s.SameLevel = o.SameLevel
	s.Keep = o.Keep
	s.KeyfileOrdered = o.KeyfileOrdered
	// 注释与弱化文件特征互斥：恢复弱化文件特征时清空注释
	if o.Deniability {
		svc.settings.SavedComments = ""
	}
	s.Comments = svc.settings.SavedComments
}

func (svc *CryptoService) newSession() {
	s := core.NewSession()
	s.OnState(func(si core.StateInfo) { svc.emitState(si) })
	s.OnProgress(func(pi core.ProgressInfo) { svc.emitProgress(pi) })
	svc.session = s
}

// Working 报告当前是否有任务在运行（供关窗拦截）。
func (svc *CryptoService) Working() bool {
	return svc.session.Working() || svc.pending()
}

func (svc *CryptoService) pending() bool {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	return svc.pendingRun
}

// ---------- 任务生命周期 ----------

func (svc *CryptoService) startRun() {
	svc.session.SetWorking()
	go func() {
		svc.session.Run()
		svc.finishRun()
	}()
	svc.pushState()
}

// finishRun 在任务结束（成功/失败/取消）后把界面恢复到初始干净状态：
// 清空输入与表单（resetNonce 递增驱动前端 resetForm），但保留最终状态文案。
func (svc *CryptoService) finishRun() {
	snap := svc.session.Snapshot()
	finalStatus, finalColor := snap.Status, snap.StatusColor

	svc.mu.Lock()
	svc.resetNonce++
	svc.opts = Options{}
	svc.lastProgStatus = ""
	svc.mu.Unlock()

	svc.session.ResetQuiet()

	st := svc.buildState(svc.session.Snapshot())
	if finalStatus != "" && finalStatus != "Ready" {
		st.Status = translateStatus(svc.lang(), finalStatus)
		st.StatusColor = finalColor
	}
	svc.app.Event.Emit("progress", UIProgress{Working: false})
	svc.app.Event.Emit("state", st)
}

// Cancel 取消当前任务。
func (svc *CryptoService) Cancel() {
	svc.session.Cancel()
}

func (svc *CryptoService) rememberStartDir(paths []string) {
	if len(paths) == 0 {
		return
	}
	p := paths[0]
	if stat, err := os.Stat(p); err == nil {
		if stat.IsDir() {
			svc.startDir = p
		} else {
			svc.startDir = filepath.Dir(p)
		}
	}
}

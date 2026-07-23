package main

import (
	"embed"
	"log"
	"os"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := application.New(application.Options{
		Name:        "PicoCrypt-CN",
		Description: "PicoCrypt-CN 文件加密工具",
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
	})

	svc := NewCryptoService(app)
	app.RegisterService(application.NewService(svc))
	app.OnShutdown(func() { svc.Save() })

	window := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "PicoCrypt-CN",
		Width:            420,
		Height:           780,
		MinWidth:         380,
		MinHeight:        600,
		EnableFileDrop:   true,
		BackgroundColour: application.NewRGB(255, 255, 255),
		URL:              "/",
	})

	// 原生拖放：文件路径经由事件上下文传入
	window.OnWindowEvent(events.Common.WindowFilesDropped, func(e *application.WindowEvent) {
		svc.HandleDrop(e.Context().DroppedFiles())
	})

	// 前端就绪后再推送初始状态，并把命令行参数当作拖放处理（原版行为）
	window.OnWindowEvent(events.Common.WindowRuntimeReady, func(e *application.WindowEvent) {
		if len(os.Args) > 1 {
			svc.HandleDrop(os.Args[1:])
		} else {
			svc.PushState()
		}
	})

	// 任务运行中禁止关闭窗口
	window.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		if svc.Working() {
			e.Cancel()
		}
	})

	err := app.Run()
	if err != nil {
		log.Fatal(err)
	}
}

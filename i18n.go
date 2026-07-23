// i18n.go — 多语言翻译：Go 端动态文案（状态/进度/输入提示/按钮名）的中英翻译。
// en 基本沿用 core 的原版英文文案；zh 为中文翻译表。
package main

import (
	"fmt"
	"regexp"
	"strings"

	"picocrypt-wails/internal/core"
)

var statusTranslations = map[string]string{
	"Ready":                                        "就绪",
	"Starting...":                                  "正在启动…",
	"Working...":                                   "处理中…",
	"Generating values...":                         "正在生成随机值…",
	"Reading values...":                            "正在读取卷头…",
	"Deriving key...":                              "正在派生密钥…",
	"Reading keyfiles...":                          "正在读取密钥文件…",
	"Calculating values...":                        "正在计算校验值…",
	"Comparing values...":                          "正在验证密钥…",
	"Removing deniability protection...":           "正在解除弱化文件特征保护…",
	"Adding plausible deniability...":              "正在添加弱化文件特征保护…",
	"Deleting files...":                            "正在删除文件…",
	"Unzipping...":                                 "正在解压…",
	"Completed":                                    "完成",
	"Operation cancelled by user":                  "操作已被用户取消",
	"The provided password is incorrect":           "密码不正确",
	"Incorrect keyfiles":                           "密钥文件不正确",
	"Incorrect keyfiles or ordering":               "密钥文件不正确或顺序错误",
	"Duplicate keyfiles detected":                  "检测到重复的密钥文件",
	"The volume header is damaged":                 "卷头已损坏",
	"The input file is damaged or modified":        "输入文件已损坏或被修改",
	"The input file is irrecoverably damaged":      "输入文件损坏，无法恢复",
	"The input file was modified. Please be careful": "警告：输入文件曾被修改，结果可能不正确，请务必小心",
	"Insufficient disk space":                      "磁盘空间不足",
	"Invalid chunk size":                           "分卷大小无效",
	"Please select your keyfiles":                  "请选择密钥文件",
	"Can't read header, assuming volume is deniable": "无法读取卷头，按弱化文件特征卷处理",
	"Failed to stat dropped item":                  "无法读取拖入的项目",
	"Failed to stat dropped items":                 "无法读取拖入的项目",
	"Failed to stat input files":                   "无法读取输入文件",
	"Failed to walk through dropped items":         "无法遍历拖入的项目",
	"Failed to read 15 bytes from file":            "读取文件失败",
	"Failed to read comments from file":            "读取注释失败",
	"Failed to create zip.FileInfoHeader":          "创建 ZIP 条目失败",
	"Failed to writer.CreateHeader":                "写入 ZIP 条目失败",
	"Auto unzipping failed!":                       "自动解压失败！",
	"Failed to create keyfile":                     "创建密钥文件失败",
	"Read access denied by operating system":       "读取被操作系统拒绝",
	"Write access denied by operating system":      "写入被操作系统拒绝",
	"Keyfile read access denied by operating system": "密钥文件读取被操作系统拒绝",
}

// translateStatus 翻译主状态；en 时原样返回（core 状态串本就是原版英文 UI 文案）。
func translateStatus(lang, s string) string {
	if lang == "en" {
		return s
	}
	if t, ok := statusTranslations[s]; ok {
		return t
	}
	if rest, ok := strings.CutPrefix(s, "Please remove "); ok {
		return "请先删除已存在的文件 " + rest
	}
	return s
}

var progressPrefixes = []struct {
	prefix string
	zh     string
	en     string
}{
	{"Encrypting at ", "加密中：%.2f MiB/s（预计剩余 %s）", "Encrypting at %.2f MiB/s (ETA: %s)"},
	{"Decrypting at ", "解密中：%.2f MiB/s（预计剩余 %s）", "Decrypting at %.2f MiB/s (ETA: %s)"},
	{"Repairing at ", "修复中：%.2f MiB/s（预计剩余 %s）", "Repairing at %.2f MiB/s (ETA: %s)"},
	{"Compressing at ", "压缩中：%.2f MiB/s（预计剩余 %s）", "Compressing at %.2f MiB/s (ETA: %s)"},
	{"Combining at ", "打包中：%.2f MiB/s（预计剩余 %s）", "Combining at %.2f MiB/s (ETA: %s)"},
	{"Recombining at ", "合并分卷中：%.2f MiB/s（预计剩余 %s）", "Recombining at %.2f MiB/s (ETA: %s)"},
	{"Splitting at ", "分卷中：%.2f MiB/s（预计剩余 %s）", "Splitting at %.2f MiB/s (ETA: %s)"},
	{"Unpacking at ", "解压中：%.2f MiB/s（预计剩余 %s）", "Unpacking at %.2f MiB/s (ETA: %s)"},
}

// translateProgressStatus 翻译进度状态；速度类文案用结构化数值重新拼装。
func translateProgressStatus(lang, s string, speed float64, eta string) string {
	for _, p := range progressPrefixes {
		if strings.HasPrefix(s, p.prefix) {
			if lang == "en" {
				return fmt.Sprintf(p.en, speed, eta)
			}
			return fmt.Sprintf(p.zh, speed, eta)
		}
	}
	return translateStatus(lang, s)
}

var inputLabelPatterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`^(\d+) files$`), "$1 个文件"},
	{regexp.MustCompile(`^(\d+) folders$`), "$1 个文件夹"},
	{regexp.MustCompile(`^(\d+) files and (\d+) folders$`), "$1 个文件和 $2 个文件夹"},
	{regexp.MustCompile(`^1 file and (\d+) folders$`), "1 个文件和 $1 个文件夹"},
	{regexp.MustCompile(`^(\d+) files and 1 folder$`), "$1 个文件和 1 个文件夹"},
	{regexp.MustCompile(`^1 file and 1 folder$`), "1 个文件和 1 个文件夹"},
}

// translateInputLabel 翻译输入描述（保留原版附加的 " (大小)" 后缀）；en 原样返回。
func translateInputLabel(lang, s string) string {
	if lang == "en" {
		return s
	}
	suffix := ""
	base := s
	if i := strings.LastIndex(s, " ("); i > 0 && strings.HasSuffix(s, ")") {
		base, suffix = s[:i], s[i:]
	}
	switch base {
	case "Drop files and folders into this window":
		return "将文件或文件夹拖入此窗口" + suffix
	case "1 file":
		return "1 个文件" + suffix
	case "1 folder":
		return "1 个文件夹" + suffix
	case "Volume for decryption":
		return "待解密的卷" + suffix
	}
	if rest, ok := strings.CutPrefix(base, "Scanning files... "); ok {
		return "正在扫描文件… " + rest
	}
	for _, p := range inputLabelPatterns {
		if p.re.MatchString(base) {
			return p.re.ReplaceAllString(base, p.repl) + suffix
		}
	}
	return s
}

func translateComments(lang, s string) string {
	if lang == "en" {
		return s
	}
	switch s {
	case "Comment length is corrupted":
		return "注释长度已损坏"
	case "Comments are corrupted":
		return "注释已损坏"
	}
	return s
}

func translateStartLabel(lang, s string) string {
	if lang == "en" {
		return s
	}
	switch s {
	case "Start":
		return "开始"
	case "Encrypt":
		return "加密"
	case "Zip and Encrypt":
		return "打包并加密"
	case "Decrypt":
		return "解密"
	case "Process":
		return "处理"
	}
	return s
}

// sizeify 与原版 sizeify 输出一致（用于磁盘空间提示）。
func sizeify(size int64) string {
	if size < core.MiB {
		return fmt.Sprintf("%.2f KiB", float64(size)/core.KiB)
	}
	if size < core.GiB {
		return fmt.Sprintf("%.2f MiB", float64(size)/core.MiB)
	}
	if size < core.TiB {
		return fmt.Sprintf("%.2f GiB", float64(size)/core.GiB)
	}
	return fmt.Sprintf("%.2f TiB", float64(size)/core.TiB)
}

func chooseFolderTitle(lang string) string {
	if lang == "en" {
		return "Choose a folder"
	}
	return "选择文件夹"
}

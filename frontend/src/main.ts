import { Events, Clipboard } from "@wailsio/runtime";
import * as svc from "../bindings/picocrypt-wails/cryptoservice";
import alipayUrl from "../assets/alipay.png";
import wechatUrl from "../assets/wechat.png";
import paypalUrl from "../assets/paypal.png";

// 赞助二维码：文字 key → 图片 URL
const QR_IMAGES: Record<string, string> = { alipay: alipayUrl, wechat: wechatUrl, paypal: paypalUrl };

// 点击文字显示对应二维码；点击其他任意位置隐藏；同时只显示一个
document.addEventListener("click", (e: MouseEvent) => {
    const qr = $("sponsorQr");
    if (!qr) return;
    const link = (e.target as HTMLElement).closest?.("[data-qr]") as HTMLElement | null;
    if (link && QR_IMAGES[link.dataset.qr!]) {
        (qr as HTMLImageElement).src = QR_IMAGES[link.dataset.qr!];
        qr.classList.remove("hidden");
    } else {
        qr.classList.add("hidden");
    }
});

// ---------- 工具 ----------
function $(id: string): any { return document.getElementById(id); }

interface UIState {
    mode: string;
    inputLabel: string;
    hasInput: boolean;
    comments: string;
    commentsDisabled: boolean;
    keyfileRequired: boolean;
    keyfileOrderedVolume: boolean;
    keyfiles: string[] | null;
    deniabilityVolume: boolean;
    autoUnzipEligible: boolean;
    startLabel: string;
    status: string;
    statusColor: string;
    working: boolean;
    outputFile: string;
    multipleInputs: boolean;
    resetNonce: number;
}

interface UIProgress {
    working: boolean;
    progress: number;
    speed: number;
    eta: string;
    status: string;
    canCancel: boolean;
}

let state: UIState | null = null;
let lastResetNonce = -1;
let pwTimer: any = null;
let lang = "zh";
let pwVisible = false;

// ---------- 界面语言 ----------
const I18N: Record<string, Record<string, string>> = {
    zh: {
        clear: "清除", pickFiles: "选择文件", pickFolder: "选择文件夹", password: "密码：",
        copy: "复制", paste: "粘贴", generate: "生成", confirmPassword: "确认密码：",
        keyfiles: "密钥文件：", manage: "管理", create: "创建", add: "添加", done: "完成",
        comments: "注释：", commentsNote: "（注释不会被加密）", advanced: "高级选项：",
        paranoid: "偏执模式", compress: "压缩文件", reedsolo: "Reed-Solomon", deleteFiles: "删除原文件",
        deniability: "弱化文件特征", recursively: "递归加密", split: "分卷：", totalAvg: "Total（均分）",
        keep: "强制解密", deleteVol: "删除卷", autoUnzip: "自动解压", sameLevel: "同级解压",
        requireOrder: "要求正确顺序", orderRequired: "此卷要求密钥文件按正确顺序提供",
        outputAs: "输出保存为：", change: "更改", overwriteQuestion: "输出文件已存在，是否覆盖？",
        no: "否", yes: "是", cancel: "取消", processing: "处理中…",
        length: "长度：", upper: "大写", lower: "小写", nums: "数字", symbols: "符号",
        copyToClipboard: "复制到剪贴板",
        keyfileHint: "将密钥文件拖入窗口，或点击按钮添加。解密时顺序需与加密时一致（如勾选）。",
        settings: "设置", rememberOptions: "记住上次的选项状态", defaultDir: "默认输出目录：",
        language: "界面语言：", close: "关闭",
        sponsor: "赞助", alipay: "支付宝", wechat: "微信",
        show: "显示", hide: "隐藏",
        strength0: "非常弱", strength1: "弱", strength2: "一般", strength3: "强", strength4: "非常强",
        matchOk: "✓ 一致", matchBad: "✗ 不一致",
        kfNone: "未选择", kfUsing: "已选择 N 个密钥文件", kfRequired: "此卷需要密钥文件",
        kfUsingRequired: "已选择 N 个密钥文件（此卷需要密钥文件）", kfNotApplicable: "不需要密钥文件",
    },
    en: {
        clear: "Clear", pickFiles: "Select files", pickFolder: "Select folder", password: "Password:",
        copy: "Copy", paste: "Paste", generate: "Create", confirmPassword: "Confirm password:",
        keyfiles: "Keyfiles:", manage: "Edit", create: "Create", add: "Add", done: "Done",
        comments: "Comments:", commentsNote: "(comments are not encrypted!)", advanced: "Advanced:",
        paranoid: "Paranoid mode", compress: "Compress files", reedsolo: "Reed-Solomon", deleteFiles: "Delete files",
        deniability: "Deniability", recursively: "Recursively", split: "Split into chunks:", totalAvg: "Total",
        keep: "Force decrypt", deleteVol: "Delete volume", autoUnzip: "Auto unzip", sameLevel: "Same level",
        requireOrder: "Require correct order", orderRequired: "Correct ordering is required",
        outputAs: "Save output as:", change: "Change", overwriteQuestion: "Output already exists. Overwrite?",
        no: "No", yes: "Yes", cancel: "Cancel", processing: "Working...",
        length: "Length:", upper: "Uppercase", lower: "Lowercase", nums: "Numbers", symbols: "Symbols",
        copyToClipboard: "Copy to clipboard",
        keyfileHint: "Drag and drop your keyfiles here, or click Add below. For decryption, ordering must match encryption (if checked).",
        settings: "Settings", rememberOptions: "Remember last used options", defaultDir: "Default output folder:",
        language: "Language:", close: "Close",
        sponsor: "Sponsor", alipay: "Alipay", wechat: "WeChat",
        show: "Show", hide: "Hide",
        strength0: "Very weak", strength1: "Weak", strength2: "Fair", strength3: "Strong", strength4: "Very strong",
        matchOk: "✓ Match", matchBad: "✗ Mismatch",
        kfNone: "None selected", kfUsing: "Using N keyfiles", kfRequired: "Keyfiles required",
        kfUsingRequired: "Using N keyfiles (keyfiles required)", kfNotApplicable: "Not applicable",
    },
};

function t(key: string): string {
    return (I18N[lang] && I18N[lang][key]) || I18N.zh[key] || key;
}

// 刷新所有静态文案与由 JS 生成的动态文案
function applyLanguage(l: string) {
    lang = l === "en" ? "en" : "zh";
    document.querySelectorAll("[data-i18n]").forEach((el: any) => {
        el.textContent = t(el.getAttribute("data-i18n"));
    });
    refreshDynamicTexts();
}

// JS 生成的动态文案（不来自 Go 状态事件的部分）
function refreshDynamicTexts() {
    $("btnTogglePw").textContent = pwVisible ? t("hide") : t("show");
    updateStrength();
    updateMatch();
    updateKeyfileLabel();
    if ($("progressPanel").classList.contains("hidden")) {
        $("progressText").textContent = t("processing");
    }
}

const ENCRYPT_OPTION_IDS = ["optParanoid", "optCompress", "optReedsolo", "optDelete", "optDeniability", "optRecursively", "optSplit", "splitSize", "splitUnit"];
const DECRYPT_OPTION_IDS = ["optKeep", "optDeleteVol", "optAutoUnzip", "optSameLevel"];

// ---------- 表单收集 ----------
function collectOptions() {
    const decrypt = state?.mode === "decrypt";
    return {
        paranoid: $("optParanoid").checked,
        reedsolo: $("optReedsolo").checked,
        deniability: $("optDeniability").checked,
        recursively: $("optRecursively").checked,
        split: $("optSplit").checked,
        splitSize: $("splitSize").value,
        splitSelected: parseInt($("splitUnit").value),
        compress: $("optCompress").checked,
        delete: decrypt ? $("optDeleteVol").checked : $("optDelete").checked,
        autoUnzip: $("optAutoUnzip").checked,
        sameLevel: $("optSameLevel").checked,
        keep: $("optKeep").checked,
        keyfileOrdered: decrypt ? (state?.keyfileOrderedVolume ?? false) : $("keyfileOrdered").checked,
    };
}

function syncOptions() { svc.SetOptions(collectOptions()); refreshDisabled(); }

function syncPassword() {
    svc.SetPassword($("password").value, $("cpassword").value);
    updateStrength();
    updateMatch();
    refreshDisabled();
}

function syncPasswordDebounced() {
    clearTimeout(pwTimer);
    pwTimer = setTimeout(syncPassword, 150);
    updateStrength();
    updateMatch();
    refreshDisabled();
}

// ---------- 启用/禁用矩阵（对齐原版 draw() 的 SetDisabled 规则） ----------
function refreshDisabled() {
    if (!state) return;
    const st = state;
    const decrypt = st.mode === "decrypt";
    const encrypt = st.mode === "encrypt";
    const working = st.working;
    const hasInput = st.hasInput;
    const multi = st.multipleInputs;

    const pw = $("password").value;
    const cpw = $("cpassword").value;
    const kfCount = st.keyfiles ? st.keyfiles.length : 0;
    const noCred = kfCount === 0 && pw === "";           // 原版: len(keyfiles)==0 && password==""
    const pwMismatch = pw !== cpw;
    const deniability = $("optDeniability").checked;
    const recursively = $("optRecursively").checked;
    const compress = $("optCompress").checked;
    const autoUnzip = $("optAutoUnzip").checked;
    const commentsVal = $("comments").value;

    const set = (id: string, disabled: boolean) => { $(id).disabled = disabled; };

    // 清除按钮与选择按钮（原版 L461：无输入时禁用）
    set("btnClear", working || !hasInput);
    set("btnPickFiles", working);
    set("btnPickFolder", working);

    // 密码区（原版 L469：无输入时整区禁用；L508：生成按钮解密时禁用）
    const pwSection = working || !hasInput;
    for (const id of ["password", "btnTogglePw", "btnClearPw", "btnCopyPw", "btnPastePw"]) set(id, pwSection);
    set("btnGenPw", pwSection || decrypt);

    // 确认密码（原版 L542：password=="" || 解密 时禁用；始终可见）
    set("cpassword", pwSection || pw === "" || decrypt);

    // 密钥文件（原版 L567 管理按钮 / L582 创建按钮；无输入时仍可用）
    set("btnKeyfile", working || (decrypt && !st.keyfileRequired && !st.deniabilityVolume));
    set("btnCreateKeyfile", working || decrypt);
    set("keyfileOrdered", working || decrypt);

    // 注释（原版 L631/633）
    if (decrypt) {
        $("comments").readOnly = st.commentsDisabled;
        set("comments", working || st.comments === "" || st.comments === "注释已损坏" || st.comments === "注释长度已损坏");
    } else {
        $("comments").readOnly = false;
        set("comments", working || noCred || pwMismatch || deniability);
    }

    // 高级选项整区（原版 L650）
    const adv = working || noCred || (encrypt && pwMismatch);

    // 加密侧
    set("optParanoid", adv);
    set("optReedsolo", adv);
    set("optDelete", adv);
    set("optCompress", adv || recursively || !multi);        // 原版 L658
    set("optRecursively", adv || !multi || compress);        // 原版 L676 + 互斥
    set("optDeniability", adv || commentsVal !== "");        // 与注释互斥
    set("optSplit", adv);
    set("splitSize", adv);
    set("splitUnit", adv);

    // 解密侧
    set("optKeep", adv || st.deniabilityVolume);             // 原版 L697
    set("optDeleteVol", adv);
    set("optAutoUnzip", adv || !st.autoUnzipEligible);       // 原版 L707
    set("optSameLevel", adv || !st.autoUnzipEligible || !autoUnzip); // 原版 L716

    // 输出（原版 L724：递归时禁用）
    set("outputFile", false); // 只读框，始终保持可选中复制
    set("btnOutput", working || !hasInput || recursively);

    // 开始按钮（原版不变灰，仅工作中禁用）
    set("btnStart", working);
}

// ---------- 界面更新 ----------
function updateStrength() {
    const pw = $("password").value;
    const bar = $("strengthBar"), text = $("strengthText");
    if (!pw) { bar.style.width = "0"; text.textContent = ""; return; }
    svc.PasswordStrength(pw).then((score: number) => {
        score = Math.max(0, Math.min(4, score));
        const r = 0xc8 - 31 * score, g = 0x4c + 31 * score, b = 0x4b;
        bar.style.width = ((score + 1) * 20) + "%";
        bar.style.background = `rgb(${r},${g},${b})`;
        text.textContent = t("strength" + score);
    });
}

function updateMatch() {
    const el = $("matchText");
    const pw = $("password").value, cpw = $("cpassword").value;
    if (!cpw || state?.mode === "decrypt") { el.textContent = ""; el.className = "match"; return; }
    if (pw === cpw) { el.textContent = t("matchOk"); el.className = "match ok"; }
    else { el.textContent = t("matchBad"); el.className = "match bad"; }
}

// 密钥文件状态行（解密/加密、数量、是否必需）
function updateKeyfileLabel() {
    if (!state) return;
    const st = state;
    const n = st.keyfiles ? st.keyfiles.length : 0;
    if (st.mode === "decrypt") {
        $("keyfileLabel").textContent = st.keyfileRequired
            ? (n > 0 ? t("kfUsingRequired").replace("N", String(n)) : t("kfRequired"))
            : (n > 0 ? t("kfUsing").replace("N", String(n)) : t("kfNotApplicable"));
    } else {
        $("keyfileLabel").textContent = n === 0 ? t("kfNone") : t("kfUsing").replace("N", String(n));
    }
}

function resetForm() {
    $("password").value = "";
    $("cpassword").value = "";
    $("comments").value = "";
    for (const id of [...ENCRYPT_OPTION_IDS, ...DECRYPT_OPTION_IDS, "keyfileOrdered"]) {
        const el = $(id);
        if (el.type === "checkbox") el.checked = false;
    }
    $("splitSize").value = "";
    $("splitUnit").value = "1";
    // 收起各面板，回到初始布局
    $("passgen").classList.add("hidden");
    $("keyfilePanel").classList.add("hidden");
    $("overwritePanel").classList.add("hidden");
    svc.SetKeyfileDropMode(false);
    // 进度条重置
    ($("progressBar") as HTMLElement).style.width = "0%";
    $("progressText").textContent = t("processing");
    $("progressPanel").classList.add("hidden");
    // 注意：不要在这里 syncOptions() —— Go 端 finishRun/Clear 已重置选项，
    // 这里的推送会触发 pushState 覆盖掉保留的最终状态文案。
    updateStrength();
    updateMatch();
}

// ---------- 拖放高亮兜底清理 ----------
// runtime 的 dragleave 处理器在 relatedTarget===null 时直接 return（为 Linux/macOS 的折衷），
// 导致 Windows 上文件拖出窗口后高亮残留；这里自行清理。
function clearDropHighlight() {
    document.querySelectorAll(".file-drop-target-active").forEach(el => el.classList.remove("file-drop-target-active"));
}
document.addEventListener("dragleave", (e: DragEvent) => {
    if (e.relatedTarget === null) clearDropHighlight();
});
document.addEventListener("drop", clearDropHighlight);

function applyState(st: UIState) {
    const prev = state;
    state = st;

    if (st.resetNonce !== lastResetNonce) {
        lastResetNonce = st.resetNonce;
        resetForm();
    }

    $("inputLabel").textContent = st.inputLabel;
    $("outputFile").value = st.outputFile;

    // 注释（解密时由卷头读入，只读）
    const comments = $("comments");
    if (comments.value !== st.comments) comments.value = st.comments;

    // 密钥文件
    updateKeyfileLabel();
    const list = $("keyfileList");
    list.innerHTML = "";
    for (const f of st.keyfiles ?? []) {
        const li = document.createElement("li");
        li.textContent = f;
        list.appendChild(li);
    }
    const decryptOrdered = st.mode === "decrypt" && st.keyfileOrderedVolume;
    $("keyfileOrderedRow").classList.toggle("hidden", st.mode === "decrypt");
    $("keyfileOrderedHint").classList.toggle("hidden", !decryptOrdered);

    // 模式相关区块（确认密码行始终可见，按条件禁用 —— 原版行为）
    $("advEncrypt").classList.toggle("hidden", st.mode === "decrypt");
    $("advDecrypt").classList.toggle("hidden", st.mode !== "decrypt");

    // 开始按钮与状态行
    $("btnStart").textContent = st.startLabel;
    const status = $("status");
    status.textContent = st.status;
    status.className = "status " + (st.statusColor || "white");

    // 任务结束后收起进度面板
    if (!st.working && prev?.working) {
        $("progressPanel").classList.add("hidden");
    }

    updateMatch();
    refreshDisabled();
}

// ---------- 事件 ----------
Events.On("state", (ev: any) => applyState(ev.data as UIState));

Events.On("progress", (ev: any) => {
    const p = ev.data as UIProgress;
    if (p.working) {
        $("progressPanel").classList.remove("hidden");
        ($("progressBar") as HTMLElement).style.width = Math.min(100, p.progress * 100) + "%";
        $("progressText").textContent = p.status || t("processing");
        ($("btnCancel") as HTMLButtonElement).disabled = !p.canCancel;
    } else if (!p.status) {
        $("progressPanel").classList.add("hidden");
    }
});

// ---------- 交互 ----------
$("btnPickFiles").onclick = () => svc.PickFiles();
$("btnPickFolder").onclick = () => svc.PickFolder();
$("btnClear").onclick = () => { svc.Clear(); $("overwritePanel").classList.add("hidden"); };

$("password").addEventListener("input", syncPasswordDebounced);
$("cpassword").addEventListener("input", syncPasswordDebounced);
$("password").addEventListener("keydown", (e: KeyboardEvent) => { if (e.key === "Enter") start(); });
$("cpassword").addEventListener("keydown", (e: KeyboardEvent) => { if (e.key === "Enter") start(); });

$("btnTogglePw").onclick = () => {
    const pw = $("password"), cpw = $("cpassword");
    pwVisible = pw.type === "password";
    pw.type = pwVisible ? "text" : "password";
    cpw.type = pwVisible ? "text" : "password";
    $("btnTogglePw").textContent = pwVisible ? t("hide") : t("show");
};
$("btnClearPw").onclick = () => { $("password").value = ""; $("cpassword").value = ""; syncPassword(); };
$("btnCopyPw").onclick = () => Clipboard.SetText($("password").value);
$("btnPastePw").onclick = async () => {
    $("password").value = await Clipboard.Text();
    syncPassword();
};

// 密码生成器
$("btnGenPw").onclick = () => $("passgen").classList.toggle("hidden");
$("pgCancel").onclick = () => $("passgen").classList.add("hidden");
$("pgLength").addEventListener("input", () => { $("pgLengthText").textContent = $("pgLength").value; });
$("pgGenerate").onclick = async () => {
    const pw = await svc.GeneratePassword(
        parseInt($("pgLength").value),
        $("pgUpper").checked, $("pgLower").checked, $("pgNums").checked, $("pgSymbols").checked,
    );
    $("password").value = pw;
    $("cpassword").value = pw;
    if ($("pgCopy").checked) Clipboard.SetText(pw);
    syncPassword();
    $("passgen").classList.add("hidden");
};

// 密钥文件
$("btnKeyfile").onclick = () => {
    const panel = $("keyfilePanel");
    const open = panel.classList.toggle("hidden") === false;
    svc.SetKeyfileDropMode(open);
};
$("btnKeyfileDone").onclick = () => {
    $("keyfilePanel").classList.add("hidden");
    svc.SetKeyfileDropMode(false);
};
$("btnAddKeyfile").onclick = () => svc.PickKeyfiles();
$("btnClearKeyfiles").onclick = () => svc.ClearKeyfiles();
$("btnCreateKeyfile").onclick = async () => {
    const err = await svc.CreateKeyfile();
    if (err) alert(err);
};

// 注释与高级选项（含原版副作用）
$("comments").addEventListener("input", () => {
    svc.SetComments($("comments").value);
    refreshDisabled(); // 注释非空时禁用否认性
});

$("keyfileOrdered").addEventListener("change", syncOptions);

// 勾递归 → 取消压缩（原版 OnChange 副作用）
$("optRecursively").addEventListener("change", () => {
    if ($("optRecursively").checked) $("optCompress").checked = false;
    syncOptions();
});
// 勾压缩 → 取消递归（互斥）
$("optCompress").addEventListener("change", () => {
    if ($("optCompress").checked) $("optRecursively").checked = false;
    syncOptions();
});
// 取消自动解压 → 取消同级解压（原版 OnChange 副作用）
$("optAutoUnzip").addEventListener("change", () => {
    if (!$("optAutoUnzip").checked) $("optSameLevel").checked = false;
    syncOptions();
});
// 输入分卷大小 → 自动勾选分卷（原版 OnChange 副作用）
$("splitSize").addEventListener("input", () => {
    $("optSplit").checked = $("splitSize").value !== "";
    syncOptions();
});
for (const id of ["optParanoid", "optReedsolo", "optDelete", "optDeniability", "optSplit", "splitUnit", "optKeep", "optDeleteVol", "optSameLevel"]) {
    $(id).addEventListener("change", syncOptions);
}

// 输出
$("btnOutput").onclick = () => svc.PickOutput();

// 开始 / 覆盖确认 / 取消
async function start() {
    syncPassword();
    svc.SetComments($("comments").value);
    await svc.SetOptions(collectOptions());
    const res = await svc.Start();
    if (res === "confirm") {
        $("overwritePanel").classList.remove("hidden");
    }
}
$("btnStart").onclick = start;
$("btnOverwriteNo").onclick = () => { svc.ConfirmOverwrite(false); $("overwritePanel").classList.add("hidden"); };
$("btnOverwriteYes").onclick = () => { svc.ConfirmOverwrite(true); $("overwritePanel").classList.add("hidden"); };
$("btnCancel").onclick = () => svc.Cancel();

// ---------- 设置面板 ----------
$("btnSettings").onclick = async () => {
    const panel = $("settingsPanel");
    if (panel.classList.contains("hidden")) {
        const s = await svc.GetSettings();
        $("setRemember").checked = s.rememberOptions;
        $("setDirPath").value = s.defaultOutputDir;
        $("setLang").value = s.language || "zh";
        panel.classList.remove("hidden");
    } else {
        panel.classList.add("hidden");
    }
};
$("setClose").onclick = () => {
    $("settingsPanel").classList.add("hidden");
    $("sponsorQr").classList.add("hidden");
};
$("setRemember").addEventListener("change", () => svc.SetRememberOptions($("setRemember").checked));
$("setDirBtn").onclick = async () => { $("setDirPath").value = await svc.PickDefaultOutputDir(); };
$("setDirClear").onclick = async () => { await svc.ClearDefaultOutputDir(); $("setDirPath").value = ""; };
$("setLang").addEventListener("change", async () => {
    const l = $("setLang").value;
    applyLanguage(l);          // 静态文案立即生效
    await svc.SetLanguage(l);  // Go 端动态文案随下次状态推送切换
});

// ---------- 启动：加载设置 → 应用语言 → 恢复上次的选项 ----------
(async () => {
    const settings = await svc.GetSettings();
    applyLanguage(settings.language || "zh");

    const st = await svc.GetState();
    applyState(st);

    const saved = await svc.GetSavedForm();
    if (saved.has) {
        const o = saved.options;
        $("optParanoid").checked = o.paranoid;
        $("optCompress").checked = o.compress;
        $("optReedsolo").checked = o.reedsolo;
        $("optDelete").checked = o.delete;
        $("optDeleteVol").checked = o.delete;
        $("optDeniability").checked = o.deniability;
        $("optRecursively").checked = o.recursively;
        $("optSplit").checked = o.split;
        $("splitSize").value = o.splitSize;
        $("splitUnit").value = String(o.splitSelected);
        $("optKeep").checked = o.keep;
        $("optAutoUnzip").checked = o.autoUnzip;
        $("optSameLevel").checked = o.sameLevel;
        $("keyfileOrdered").checked = o.keyfileOrdered;
        if (!o.deniability) $("comments").value = saved.comments;
        refreshDisabled();
    }
})();

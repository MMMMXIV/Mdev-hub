//! 未知デバイスのプロトコル解析 (汎用ドライバ `generic.rs` と example `hidanalyze` の共通部品)。
//!
//! やること (すべてデバイスへの**書き込みなし**):
//! 1. VID:PID の全 HID インターフェース / collection を列挙する
//! 2. 開ける collection のレポートディスクリプタを読み、report ID ごとの長さを出す
//! 3. vendor-defined collection の Feature report を GET_FEATURE で読む (読み取りのみ)
//! 4. `sniff`: 開ける collection の Input report を一定時間記録し、直前との差分バイトを出す
//!
//! Windows ではマウス・キーボード本体の collection は OS が排他で握るので開けない
//! (「open 失敗」と出るのは正常)。設定用の vendor collection は開ける。
//!
//! ホスト → デバイス方向 (公式ソフトが送る SET_REPORT / OUT) は HID API では見えない。
//! それは USBPcap + Wireshark で取る (docs/ADD_DEVICE.md §2.5)。

use crate::hiddesc::{self, Descriptor, ReportKind};
use std::collections::HashMap;
use std::ffi::CString;
use std::fmt::Write as _;
use std::time::{Duration, Instant};

/// 1 インターフェース (Windows では 1 collection = 1 パス)。
#[derive(Clone, Debug)]
pub struct Iface {
    pub path: CString,
    pub vid: u16,
    pub pid: u16,
    pub usage_page: u16,
    pub usage: u16,
    pub interface: i32,
    pub product: Option<String>,
    pub manufacturer: Option<String>,
    pub serial: Option<String>,
}

impl Iface {
    pub fn is_vendor(&self) -> bool {
        self.usage_page >= 0xFF00
    }
    pub fn label(&self) -> String {
        format!(
            "MI_{:02} {:04X}:{:04X} {}",
            self.interface.max(0),
            self.usage_page,
            self.usage,
            hiddesc::usage_name(self.usage_page, self.usage)
        )
    }
}

/// VID:PID の全インターフェース。並びは (interface 番号, パス) 順 = COL01, COL02, …。
pub fn interfaces(api: &hidapi::HidApi, vid: u16, pid: u16) -> Vec<Iface> {
    let mut v: Vec<Iface> = api
        .device_list()
        .filter(|d| d.vendor_id() == vid && d.product_id() == pid)
        .map(|d| Iface {
            path: d.path().to_owned(),
            vid,
            pid,
            usage_page: d.usage_page(),
            usage: d.usage(),
            interface: d.interface_number(),
            product: d.product_string().filter(|s| !s.is_empty()).map(Into::into),
            manufacturer: d
                .manufacturer_string()
                .filter(|s| !s.is_empty())
                .map(Into::into),
            serial: d.serial_number().filter(|s| !s.is_empty()).map(Into::into),
        })
        .collect();
    v.sort_by(|a, b| {
        (a.interface, a.path.as_bytes().to_ascii_lowercase())
            .cmp(&(b.interface, b.path.as_bytes().to_ascii_lowercase()))
    });
    v.dedup_by(|a, b| a.path == b.path);
    v
}

/// マウス / キーボードとして振る舞う VID:PID の一覧 (vid, pid) — 重複なし。
pub fn input_devices(api: &hidapi::HidApi) -> Vec<(u16, u16)> {
    let mut v: Vec<(u16, u16)> = Vec::new();
    for d in api.device_list() {
        if is_pointer_or_keyboard(d.usage_page(), d.usage()) {
            let k = (d.vendor_id(), d.product_id());
            if !v.contains(&k) {
                v.push(k);
            }
        }
    }
    v.sort();
    v
}

pub fn is_pointer_or_keyboard(page: u16, usage: u16) -> bool {
    page == 0x01 && (usage == 0x02 || usage == 0x06)
}

/// 主たる種別の推定: 最も若い interface の最初の collection が Mouse ならマウス。
/// (マウスはマクロ用に Keyboard collection も持つことが多く、キーボードは
/// マウスキー用に Mouse collection を持つことが多いので「先頭」で決める。)
pub fn primary_kind(ifaces: &[Iface]) -> Option<u16> {
    ifaces
        .iter()
        .find(|i| is_pointer_or_keyboard(i.usage_page, i.usage))
        .map(|i| i.usage)
}

/// 開いてレポートディスクリプタを取る。
fn descriptor(dev: &hidapi::HidDevice) -> Result<(Vec<u8>, Descriptor), String> {
    let mut buf = vec![0u8; 4096];
    let n = dev
        .get_report_descriptor(&mut buf)
        .map_err(|e| e.to_string())?;
    buf.truncate(n);
    let d = hiddesc::parse(&buf);
    Ok((buf, d))
}

/// 解析レポート (テキスト)。`probe_features` で vendor collection の GET_FEATURE を行う。
pub fn analyze(api: &hidapi::HidApi, vid: u16, pid: u16, probe_features: bool) -> String {
    let ifs = interfaces(api, vid, pid);
    let mut s = String::new();
    let _ = writeln!(s, "==== HID 解析 {vid:04X}:{pid:04X} ====");
    if let Some(i) = ifs.first() {
        let _ = writeln!(
            s,
            "製品: {}  メーカー: {}  シリアル: {}",
            i.product.as_deref().unwrap_or("-"),
            i.manufacturer.as_deref().unwrap_or("-"),
            if i.serial.is_some() {
                "あり"
            } else {
                "なし"
            },
        );
    } else {
        let _ = writeln!(s, "(このVID:PIDのインターフェースが見つかりません)");
        return s;
    }
    let _ = writeln!(s, "インターフェース数: {}", ifs.len());
    for (n, i) in ifs.iter().enumerate() {
        let _ = writeln!(s, "\n--- [{n}] {}", i.label());
        match api.open_path(&i.path) {
            Err(e) => {
                let _ = writeln!(
                    s,
                    "  open 失敗 ({e}) — OS が排他で握る Mouse/Keyboard collection なら正常"
                );
            }
            Ok(dev) => match descriptor(&dev) {
                Ok((raw, d)) => {
                    let _ = writeln!(s, "  descriptor {} bytes", raw.len());
                    s.push_str(&d.summary());
                    let _ = writeln!(s, "  raw: {}", hiddesc::hex(&raw));
                    if probe_features && i.is_vendor() {
                        for r in d.reports.iter().filter(|r| r.kind == ReportKind::Feature) {
                            let mut buf = vec![0u8; r.wire_len().max(2)];
                            buf[0] = r.id;
                            match dev.get_feature_report(&mut buf) {
                                Ok(n) => {
                                    let _ = writeln!(
                                        s,
                                        "  GET_FEATURE id=0x{:02X} → {n}B: {}",
                                        r.id,
                                        hiddesc::hex(&buf[..n.min(buf.len())])
                                    );
                                }
                                Err(e) => {
                                    let _ =
                                        writeln!(s, "  GET_FEATURE id=0x{:02X} 失敗: {e}", r.id);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = writeln!(s, "  descriptor 取得失敗: {e}");
                }
            },
        }
    }
    let vendor: Vec<_> = ifs.iter().filter(|i| i.is_vendor()).collect();
    let _ = writeln!(s, "\n---- まとめ");
    if vendor.is_empty() {
        let _ = writeln!(
            s,
            "vendor-defined collection なし — 設定は Output/Feature を持つ標準 collection か、\
             USB コントロール転送 (HID 外) で行われている可能性。USBPcap で確認してください。"
        );
    } else {
        for i in vendor {
            let _ = writeln!(s, "設定用の候補: {}", i.label());
        }
    }
    s
}

/// `sniff_run` 用に開いた collection。
pub struct Opened {
    pub index: usize,
    pub label: String,
    pub dev: hidapi::HidDevice,
}

/// 開ける collection をすべて開く (HidApi のロックはこの間だけ必要)。
/// 戻り値: (開けたもの, ログ行)。
pub fn sniff_open(api: &hidapi::HidApi, vid: u16, pid: u16) -> (Vec<Opened>, Vec<String>) {
    let mut lines = Vec::new();
    let mut devs = Vec::new();
    for (n, i) in interfaces(api, vid, pid).iter().enumerate() {
        match api.open_path(&i.path) {
            Ok(d) => {
                d.set_blocking_mode(false).ok();
                lines.push(format!("listen [{n}] {}", i.label()));
                devs.push(Opened {
                    index: n,
                    label: i.label(),
                    dev: d,
                });
            }
            Err(_) => lines.push(format!("skip   [{n}] {} (OS 排他)", i.label())),
        }
    }
    (devs, lines)
}

/// 開ける collection の Input report を `dur` だけ記録する (CLI 用の一括版)。
pub fn sniff(
    api: &hidapi::HidApi,
    vid: u16,
    pid: u16,
    dur: Duration,
    mut line: impl FnMut(&str),
) -> String {
    let (devs, pre) = sniff_open(api, vid, pid);
    let mut log = String::new();
    for l in pre {
        line(&l);
        log.push_str(&l);
        log.push('\n');
    }
    log.push_str(&sniff_run(&devs, dur, line));
    log
}

/// 開いた collection の Input report を `dur` だけ記録し、直前との差分バイトを出す。
/// 同じ内容の繰り返しは数えるだけで行に出さない。`line` は 1 行ごとに呼ばれる。
pub fn sniff_run(devs: &[Opened], dur: Duration, mut line: impl FnMut(&str)) -> String {
    let mut log = String::new();
    let mut emit = |l: String, log: &mut String| {
        line(&l);
        log.push_str(&l);
        log.push('\n');
    };
    if devs.is_empty() {
        emit("開ける collection がありません".into(), &mut log);
        return log;
    }
    emit(
        format!(
            "{} 秒間記録します — 公式ソフトで設定を変える / キーやボタンを押す / DPI ボタンを押す",
            dur.as_secs()
        ),
        &mut log,
    );
    let start = Instant::now();
    let mut last: HashMap<(usize, u8), Vec<u8>> = HashMap::new();
    let mut counts: HashMap<(usize, u8), u32> = HashMap::new();
    let mut buf = [0u8; 1024];
    while start.elapsed() < dur {
        let mut any = false;
        for o in devs {
            let n = o.index;
            if let Ok(len) = o.dev.read(&mut buf) {
                if len == 0 {
                    continue;
                }
                any = true;
                let r = &buf[..len];
                let key = (n, r[0]);
                *counts.entry(key).or_default() += 1;
                let diff = match last.get(&key) {
                    Some(p) if p.len() == r.len() => {
                        let idx: Vec<String> = (0..r.len())
                            .filter(|&k| p[k] != r[k])
                            .map(|k| k.to_string())
                            .collect();
                        if idx.is_empty() {
                            None
                        } else {
                            Some(format!("変化@[{}]", idx.join(",")))
                        }
                    }
                    _ => Some("初回".to_string()),
                };
                if let Some(diff) = diff {
                    emit(
                        format!(
                            "+{:>6}ms [{n}] {len:>3}B {}  {diff}",
                            start.elapsed().as_millis(),
                            hiddesc::hex(r)
                        ),
                        &mut log,
                    );
                }
                last.insert(key, r.to_vec());
            }
        }
        if !any {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let mut keys: Vec<_> = counts.into_iter().collect();
    keys.sort();
    emit(
        "---- 受信数 (collection, 先頭バイト=report ID)".into(),
        &mut log,
    );
    for ((n, id), c) in keys {
        let label = devs
            .iter()
            .find(|o| o.index == n)
            .map(|o| o.label.as_str())
            .unwrap_or("");
        emit(format!("  [{n}] 0x{id:02X}: {c} 件  {label}"), &mut log);
    }
    log
}

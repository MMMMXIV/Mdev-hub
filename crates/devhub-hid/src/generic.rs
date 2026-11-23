//! 汎用ドライバ — registry に無い**任意の HID マウス / キーボード**用。
//!
//! メーカー独自の設定プロトコル (DPI・RT・キーマップ等) は機種ごとに非公開なので、
//! ここでは設定を書かない。代わりに:
//! - サイドバーに「検出済み・汎用」として出す (製品名・メーカー名・VID:PID)
//! - 「一般」タブの操作から、そのデバイスのプロトコル解析ログを保存できる
//!   (HID 構成 + ディスクリプタ + vendor Feature の読み出し / Input report の記録)
//!
//! 解析ログから専用ドライバを書く手順は docs/ADD_DEVICE.md §2.5。
//! **デバイスへは一切書き込まない** (GET_FEATURE と Input の受信だけ)。

use crate::analyze;
use devhub_core::backend::*;
use devhub_core::model::*;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SNIFF_SECS: u64 = 20;

pub struct GenericDriver {
    api: Arc<Mutex<hidapi::HidApi>>,
    info: DeviceInfo,
    events: Option<Arc<dyn Fn(HubEvent) + Send + Sync>>,
}

pub fn open(
    api: Arc<Mutex<hidapi::HidApi>>,
    info: DeviceInfo,
    events: Option<Arc<dyn Fn(HubEvent) + Send + Sync>>,
) -> GenericDriver {
    GenericDriver { api, info, events }
}

fn caps() -> Capabilities {
    let mut c = Capabilities::empty();
    c.actions =
        vec![
        ActionSpec::new("generic_analyze", section::SYSTEM, "プロトコル解析: HID 構成を保存")
            .help(
                "全インターフェース・レポートディスクリプタ・設定用 (vendor) collection の \
                 Feature report を読み取り専用で取得してテキストに保存します。",
            )
            .save_file(&["txt"]),
        ActionSpec::new(
            "generic_sniff",
            section::SYSTEM,
            "プロトコル解析: 受信レポートを 20 秒記録",
        )
        .help(
            "開ける collection の Input report を記録します。記録中に公式ソフトで設定を変える・\
             DPI ボタンやキーを押すと、どのバイトが変わるかが分かります。",
        )
        .save_file(&["txt"]),
    ];
    c
}

impl GenericDriver {
    fn progress(&self, label: &str, fraction: Option<f32>, done: bool) {
        if let Some(ev) = &self.events {
            ev(HubEvent::Progress {
                id: self.info.id.clone(),
                label: label.into(),
                fraction,
                done,
            });
        }
    }

    fn header(&self) -> String {
        format!(
            "Device HUB 汎用ドライバ 解析ログ\n表示名: {}\nVID:PID: {:04X}:{:04X}\n\n",
            self.info.name, self.info.vid, self.info.pid
        )
    }
}

fn write_out(path: &Path, text: &str) -> HubResult<()> {
    std::fs::write(path, text).map_err(|e| HubError::Io(format!("{}: {e}", path.display())))
}

impl DeviceDriver for GenericDriver {
    fn info(&self) -> DeviceInfo {
        self.info.clone()
    }

    fn caps(&self) -> Capabilities {
        caps()
    }

    fn read(&self) -> HubResult<DeviceState> {
        Ok(DeviceState {
            profile: ProfileState::default(),
            settings: BTreeMap::new(),
            mouse: None,
            keyboard: None,
            lighting: BTreeMap::new(),
            peq: None,
        })
    }

    fn apply(&self, _change: &Change) -> HubResult<()> {
        Err(HubError::Unsupported(
            "汎用ドライバでは設定を書き込めません (専用ドライバが必要)",
        ))
    }

    fn run_action(&self, id: &str, file: Option<&Path>) -> HubResult<ActionOutcome> {
        let path = file.ok_or_else(|| HubError::Invalid("保存先が選ばれていません".into()))?;
        let (vid, pid) = (self.info.vid, self.info.pid);
        match id {
            "generic_analyze" => {
                let text = {
                    let mut api = self.api.lock().unwrap_or_else(|p| p.into_inner());
                    api.refresh_devices().ok();
                    analyze::analyze(&api, vid, pid, true)
                };
                write_out(path, &(self.header() + &text))?;
                Ok(ActionOutcome {
                    message: Some(format!("解析ログを保存しました: {}", path.display())),
                    reload: false,
                })
            }
            "generic_sniff" => {
                // 開く間だけ HidApi を握る (scan を 20 秒止めないため)。
                let (devs, pre) = {
                    let api = self.api.lock().unwrap_or_else(|p| p.into_inner());
                    analyze::sniff_open(&api, vid, pid)
                };
                let start = Instant::now();
                let mut last_tick = 0u64;
                let mut log = pre.join("\n") + "\n";
                let dur = Duration::from_secs(SNIFF_SECS);
                // 進捗は sniff_run の行コールバックでは粗いので、別スレッドで刻む。
                let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let ticker = {
                    let stop = stop.clone();
                    let events = self.events.clone();
                    let id = self.info.id.clone();
                    std::thread::spawn(move || {
                        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                            let t = start.elapsed().as_secs_f32() / SNIFF_SECS as f32;
                            if let Some(ev) = &events {
                                ev(HubEvent::Progress {
                                    id: id.clone(),
                                    label: "受信レポートを記録中…".into(),
                                    fraction: Some(t.min(1.0)),
                                    done: false,
                                });
                            }
                            std::thread::sleep(Duration::from_millis(250));
                        }
                    })
                };
                log += &analyze::sniff_run(&devs, dur, |_| {
                    last_tick += 1;
                });
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
                ticker.join().ok();
                self.progress("記録完了", Some(1.0), true);
                write_out(path, &(self.header() + &log))?;
                Ok(ActionOutcome {
                    message: Some(format!("{last_tick} 行を記録しました: {}", path.display())),
                    reload: false,
                })
            }
            _ => Err(HubError::Unsupported("action")),
        }
    }
}

//! devhub-hid: 実機との会話層。
//!
//! - `connect()` … hidapi を開いて `RealHub` を返す
//! - `RealHub::scan` … `devhub_core::registry::KNOWN` に一致したインターフェースを
//!   `DeviceInfo` として報告し、ID → HID path を `paths` に記録する
//!   (HID で開けないドライバ種別は `supported: false`)。
//! - `RealHub::driver` … ID から記録済み path を開き、ドライバを作ってキャッシュする。
//!   同じ ID には同じ `Arc` を返す (UI はデバイスごとのワーカー 1 本で呼ぶ)。

use devhub_core::backend::*;
use devhub_core::model::*;
use devhub_core::registry;
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::{Arc, Mutex};

// mousefit 新プロトコル (64B feature report) ドライバ — 観測した全機種 (5219 有線・
// 3854 ドングル) は Windows で feature report を持たないため現状どの機種にも振らない。
// JS バンドル解析に基づく実装として残し、feature report を持つ機種が出たらここを使う。
/// 未知デバイスのプロトコル解析 (汎用ドライバ・example `hidanalyze` 共通)。
pub mod analyze;
/// ATK 系ドライバ。診断 example (atkread) からも使うので公開。
#[doc(hidden)]
pub mod atk;
mod generic;
/// HID レポートディスクリプタの最小パーサ。
pub mod hiddesc;
#[doc(hidden)]
pub mod lamzu;
#[allow(dead_code)]
mod mousefit;
mod mousefit8;
/// 生 HID チャネル。診断 example (axraw 等) が直接フレームを投げるために公開。
#[doc(hidden)]
pub mod transport;
mod walkplay;
mod xsyd;

/// 実機バックエンドの入口。HID が開けなければ Err (UI はデモへ落ちる)。
pub fn connect() -> HubResult<Arc<dyn HubBackend>> {
    let api = transport::open()?;
    Ok(Arc::new(RealHub {
        api: Arc::new(Mutex::new(api)),
        generic: Mutex::new(HashMap::new()),
        paths: Mutex::new(HashMap::new()),
        drivers: Mutex::new(HashMap::new()),
        creating: Mutex::new(HashMap::new()),
        names: Mutex::new(HashMap::new()),
        watcher: Mutex::new(None),
        detected: Arc::new(Mutex::new(HashMap::new())),
    }))
}

/// ドライバ種別ごとの実装が済んでいるか。
fn driver_ready(kind: DriverKind) -> bool {
    match kind {
        DriverKind::Xsyd => true,
        DriverKind::Mousefit => true,
        DriverKind::Walkplay => true,
        DriverKind::Atk => true,
        DriverKind::Lamzu => true,
        DriverKind::Generic => true,
        DriverKind::Unsupported => false,
    }
}

pub struct RealHub {
    /// 汎用ドライバが解析時に開き直すので共有する (hidapi は 1 プロセス 1 インスタンス)。
    api: Arc<Mutex<hidapi::HidApi>>,
    /// 汎用ドライバで扱う ID → scan 時点の DeviceInfo (registry に無いマウス/キーボード)。
    generic: Mutex<HashMap<String, DeviceInfo>>,
    /// `DeviceId.0` → HID path (最後の scan 時点)。
    paths: Mutex<HashMap<String, CString>>,
    /// `DeviceId.0` → ドライバ (オープン済みは使い回す)。
    drivers: Mutex<HashMap<String, Arc<dyn DeviceDriver>>>,
    /// `DeviceId.0` → 生成ロック。同じ ID のドライバ生成を直列化する
    /// (キャッシュ確認と登録が別区間だと並行呼び出しが同じ HID を二重に開く)。
    creating: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// `DeviceId.0` → HID が報告する製品名 (scan 時点で記録)。
    names: Mutex<HashMap<String, String>>,
    /// `DeviceId.0` → ドングル内側機種の確定値 (model, 表示名)。
    /// ドライバが EID で確定した結果を保持し、ドライバ再生成
    /// (切断/invalidate) でも registry 既定へ戻らないようにする。
    detected: Arc<Mutex<HashMap<String, (String, String)>>>,
    /// `watch` で登録された通知窓口 (ドライバへ渡す)。
    watcher: Mutex<Option<Watcher>>,
}

/// ドライバへ渡すイベント窓口。
type Watcher = Arc<dyn Fn(HubEvent) + Send + Sync>;

impl HubBackend for RealHub {
    fn scan(&self) -> HubResult<Vec<DeviceInfo>> {
        let mut api = self.api.lock().unwrap_or_else(|p| p.into_inner());
        api.refresh_devices()
            .map_err(|e| HubError::Io(e.to_string()))?;
        let mut out: Vec<DeviceInfo> = Vec::new();
        let mut paths = self.paths.lock().unwrap_or_else(|p| p.into_inner());
        let mut names = self.names.lock().unwrap_or_else(|p| p.into_inner());
        let prev_paths = std::mem::take(&mut *paths);
        names.clear();
        // registry に一致した VID:PID (汎用ドライバの対象から外す)。
        let mut matched: Vec<(u16, u16)> = Vec::new();
        for d in api.device_list() {
            let Some(spec) =
                registry::match_device(d.vendor_id(), d.product_id(), d.usage_page(), d.usage())
            else {
                continue;
            };
            if !matched.contains(&(spec.vid, spec.pid)) {
                matched.push((spec.vid, spec.pid));
            }
            let serial = d
                .serial_number()
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            let id = DeviceId(format!(
                "hid:{:04x}:{:04x}:{}",
                d.vendor_id(),
                d.product_id(),
                serial
                    .clone()
                    .unwrap_or_else(|| format!("{:08x}", fxhash(d.path().to_bytes())))
            ));
            if out.iter().any(|o| o.id == id) {
                continue;
            }
            paths.insert(id.0.clone(), d.path().to_owned());
            // 表示名は HID の製品文字列を優先 (無ければ registry の名前)。
            // ただしドングルは受信機自身の名前を名乗るので、registry (ペア機種名) を優先する。
            let name = match spec.transport {
                Transport::Wireless24G | Transport::Bluetooth => spec.name.into(),
                _ => d
                    .product_string()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .unwrap_or_else(|| spec.name.into()),
            };
            names.insert(id.0.clone(), name.clone());
            out.push(DeviceInfo {
                id,
                kind: spec.kind,
                name,
                vendor: spec.vendor.into(),
                model: spec.model.into(),
                vid: spec.vid,
                pid: spec.pid,
                transport: spec.transport,
                firmware: None,
                dongle_firmware: None,
                serial,
                driver: spec.driver,
                battery: None,
                supported: driver_ready(spec.driver),
                asleep: false,
                board_id: None,
            });
        }
        // registry に無いマウス/キーボード → 汎用ドライバ (検出 + プロトコル解析)。
        let mut generic = self.generic.lock().unwrap_or_else(|p| p.into_inner());
        generic.clear();
        for (vid, pid) in analyze::input_devices(&api) {
            if matched.contains(&(vid, pid)) {
                continue;
            }
            let ifs = analyze::interfaces(&api, vid, pid);
            let Some(first) = ifs.first() else { continue };
            let id = DeviceId(format!(
                "hid:{vid:04x}:{pid:04x}:{}",
                first
                    .serial
                    .clone()
                    .unwrap_or_else(|| format!("{:08x}", fxhash(first.path.as_bytes())))
            ));
            // 汎用ドライバは開いたハンドルを持たないので、パスは先頭 collection を記録する
            // (抜き差し検出 = キャッシュ破棄の判定に使う)。
            paths.insert(id.0.clone(), first.path.clone());
            let kind = match analyze::primary_kind(&ifs) {
                Some(0x06) => DeviceKind::Keyboard,
                Some(_) => DeviceKind::Mouse,
                None => DeviceKind::Other,
            };
            let name = ifs
                .iter()
                .find_map(|i| i.product.clone())
                .unwrap_or_else(|| format!("HID {vid:04X}:{pid:04X}"));
            let lower = name.to_ascii_lowercase();
            let transport = if ["dongle", "receiver", "wireless", "2.4g"]
                .iter()
                .any(|w| lower.contains(w))
            {
                Transport::Wireless24G
            } else {
                Transport::Unknown
            };
            let info = DeviceInfo {
                id: id.clone(),
                kind,
                name: name.clone(),
                vendor: first.manufacturer.clone().unwrap_or_else(|| "不明".into()),
                model: "generic".into(),
                vid,
                pid,
                transport,
                firmware: None,
                dongle_firmware: None,
                serial: first.serial.clone(),
                driver: DriverKind::Generic,
                battery: None,
                supported: true,
                asleep: false,
                board_id: None,
            };
            names.insert(id.0.clone(), name);
            generic.insert(id.0.clone(), info.clone());
            out.push(info);
        }
        drop(generic);
        // 抜かれた/差し直されたデバイスのキャッシュは死んだハンドル — パスが
        // 前回と一致するものだけ残し、他は捨てて次回 driver() で開き直す。
        self.drivers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|id, _| paths.get(id).is_some() && prev_paths.get(id) == paths.get(id));
        Ok(out)
    }

    fn watch(&self, cb: Box<dyn Fn(HubEvent) + Send + Sync>) {
        *self.watcher.lock().unwrap_or_else(|p| p.into_inner()) = Some(Arc::from(cb));
    }

    fn driver(&self, id: &DeviceId) -> HubResult<Arc<dyn DeviceDriver>> {
        if let Some(d) = self
            .drivers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&id.0)
        {
            return Ok(d.clone());
        }
        // 同じ ID の生成を直列化する。別 ID の通信はこのロックを待たない。
        let guard = self
            .creating
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(id.0.clone())
            .or_default()
            .clone();
        let _guard = guard.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(d) = self
            .drivers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&id.0)
        {
            return Ok(d.clone());
        }
        let generic_info = self
            .generic
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&id.0)
            .cloned();
        if let Some(info) = generic_info {
            let events = self
                .watcher
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            let drv: Arc<dyn DeviceDriver> =
                Arc::new(generic::open(self.api.clone(), info, events));
            self.drivers
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(id.0.clone(), drv.clone());
            return Ok(drv);
        }
        let (vid, pid) = parse_id(id).ok_or_else(|| HubError::NotFound(id.clone()))?;
        let spec = known_spec(vid, pid).ok_or_else(|| HubError::NotFound(id.clone()))?;
        // 列挙の更新と生成が重なると、切れた古いパスで開いたドライバを
        // 登録してしまう — 登録前にパス世代を再確認し、変わっていればやり直す。
        for _ in 0..3 {
            let path = self
                .paths
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&id.0)
                .cloned()
                .ok_or_else(|| HubError::NotFound(id.clone()))?;
            let api = self.api.lock().unwrap_or_else(|p| p.into_inner());
            let dev = match api.open_path(&path) {
                Ok(d) => d,
                Err(e) => return Err(HubError::Io(format!("open {}: {e}", spec.name))),
            };
            drop(api);
            let drv = self.make_driver(spec, dev, id)?;
            let same = self
                .paths
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&id.0)
                == Some(&path);
            if same {
                self.drivers
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(id.0.clone(), drv.clone());
                return Ok(drv);
            }
            // パスが更新された — 古い接続先で開いたハンドルは捨てて取り直す。
        }
        Err(HubError::Io(
            "デバイスの接続先が変化しています — 再試行してください".into(),
        ))
    }

    fn invalidate(&self, id: &DeviceId) {
        self.drivers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&id.0);
    }
}

impl RealHub {
    /// ドライバ 1 回分の生成 (info/detected/events 解決 + registry 分岐)。
    /// 登録は呼び出し側がパス世代の再確認後に行う。
    fn make_driver(
        &self,
        spec: &registry::KnownDevice,
        dev: hidapi::HidDevice,
        id: &DeviceId,
    ) -> HubResult<Arc<dyn DeviceDriver>> {
        let name = self
            .names
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&id.0)
            .cloned()
            .unwrap_or_else(|| spec.name.into());
        let mut info = DeviceInfo {
            id: id.clone(),
            kind: spec.kind,
            name,
            vendor: spec.vendor.into(),
            model: spec.model.into(),
            vid: spec.vid,
            pid: spec.pid,
            transport: spec.transport,
            firmware: None,
            dongle_firmware: None,
            serial: None,
            driver: spec.driver,
            battery: None,
            supported: true,
            asleep: false,
            board_id: None,
        };
        // ドングルの内側機種が確定済みなら復元 (再生成でも正しい caps で開く)。
        if let Some((m, n)) = self
            .detected
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&id.0)
        {
            info.model = m.clone();
            info.name = n.clone();
        }
        let events = self
            .watcher
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let drv: Arc<dyn DeviceDriver> = match spec.driver {
            // mouse.fit 機種はドングル経由だけでなく有線 (5219 実機) でも
            // feature report を持たない → 全機種 report-8/EEPROM 経路。
            // 新プロトコル (64B feature report) のドライバは mousefit.rs に残してある。
            DriverKind::Mousefit => {
                Arc::new(mousefit8::open(dev, info, events, self.detected.clone())?)
            }
            DriverKind::Xsyd => Arc::new(xsyd::open(dev, info)?),
            DriverKind::Walkplay => Arc::new(walkplay::open(dev, info)?),
            DriverKind::Atk => Arc::new(atk::open(dev, info, events)?),
            DriverKind::Lamzu => Arc::new(lamzu::open(dev, info, events)?),
            // 汎用ドライバは driver() 側で registry を経由せずに作る。
            DriverKind::Generic | DriverKind::Unsupported => {
                return Err(HubError::NotImplemented("このデバイスのドライバ"))
            }
        };
        Ok(drv)
    }
}

/// `hid:<vid>:<pid>:<serial>` → (vid, pid)。
fn parse_id(id: &DeviceId) -> Option<(u16, u16)> {
    let mut it = id.0.split(':');
    if it.next()? != "hid" {
        return None;
    }
    let vid = u16::from_str_radix(it.next()?, 16).ok()?;
    let pid = u16::from_str_radix(it.next()?, 16).ok()?;
    Some((vid, pid))
}

/// VID/PID → registry エントリ (usage 条件は scan 時点で満たした前提)。
fn known_spec(vid: u16, pid: u16) -> Option<&'static registry::KnownDevice> {
    registry::KNOWN
        .iter()
        .find(|k| k.vid == vid && k.pid == pid && k.vid != 0xFFFF)
}

/// パス文字列の安定ハッシュ (シリアルが無いデバイスの ID 用)。
fn fxhash(b: &[u8]) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for x in b {
        h ^= *x as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

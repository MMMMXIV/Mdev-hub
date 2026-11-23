//! ATK 系 (373b:*) の**読み取り専用**チェック — 書き込みは一切しない。
//! `cargo run -p devhub-hid --example atkcheck`
//!
//! 1. ff02/u2 collection を探す (有線 / ドングル問わず)
//! 2. cmd16 (CID/MID 問い合わせ) の生応答を出す — 新機種を atk.rs の機種表に足す材料
//! 3. ドライバ経路 (atk::open → info → caps → read) で全設定を読み、表示する
//!
//! `--dpi-test` を付けたときだけ DPI の書き込み往復を行う:
//! 1 段目を +10 して書く → 読み戻して一致を確認 → 元の値に戻す → 読み戻して確認。

use devhub_core::backend::DeviceDriver;
use devhub_core::model::*;
use devhub_hid::{atk, hiddesc, transport};
use std::time::{Duration, Instant};

fn main() {
    let api = transport::open().expect("hidapi");
    let Some(info_raw) = api
        .device_list()
        .find(|d| d.vendor_id() == 0x373b && d.usage_page() == 0xff02 && d.usage() == 2)
    else {
        println!("ATK (373b) の ff02/u2 collection が見つかりません。");
        return;
    };
    let pid = info_raw.product_id();
    let product = info_raw.product_string().unwrap_or("").to_string();
    let dongle = product.to_ascii_lowercase().contains("dongle");
    println!("== device 373b:{pid:04x} \"{product}\" dongle={dongle}");

    // ---- cmd16 生応答 (読み取り系コマンド)
    let dev = info_raw.open_device(&api).expect("open");
    dev.set_blocking_mode(false).ok();
    let mut f = [0u8; 17];
    f[0] = 8;
    f[1] = 16;
    let s: u32 = f[..16].iter().map(|&b| b as u32).sum();
    f[16] = 85u32.wrapping_sub(s) as u8;
    let mut got = None;
    for _ in 0..5 {
        dev.write(&f).expect("write cmd16");
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            let mut buf = [0u8; 64];
            if let Ok(n) = dev.read_timeout(&mut buf, 100) {
                if n >= 17 && buf[1] == 16 {
                    got = Some(buf[..17].to_vec());
                    break;
                }
            }
        }
        if got.is_some() {
            break;
        }
    }
    match &got {
        Some(r) => println!(
            "== cmd16 応答: {}\n   CID={} MID={}",
            hiddesc::hex(r),
            r[6],
            r[7]
        ),
        None => println!("== cmd16 応答なし (マウスが休眠中? マウスを動かしてから再実行)"),
    }
    drop(dev);

    // ---- ドライバ経路で読む
    let dev = info_raw.open_device(&api).expect("open");
    let info = DeviceInfo {
        id: DeviceId(format!("hid:373b:{pid:04x}:check")),
        kind: DeviceKind::Mouse,
        name: product.clone(),
        vendor: "ATK".into(),
        model: "atk-check".into(),
        vid: 0x373b,
        pid,
        transport: if dongle {
            Transport::Wireless24G
        } else {
            Transport::Wired
        },
        firmware: None,
        dongle_firmware: None,
        serial: None,
        driver: DriverKind::Atk,
        supported: true,
        asleep: false,
        battery: None,
        board_id: None,
    };
    let d = atk::open(dev, info, None).expect("driver");
    let i = d.info();
    println!(
        "== info: name={} fw={:?} dongle_fw={:?} bat={:?} asleep={}",
        i.name, i.firmware, i.dongle_firmware, i.battery, i.asleep
    );
    match d.battery() {
        Ok(b) => println!("== battery: {b:?}"),
        Err(e) => println!("== battery: {e}"),
    }
    let s = match d.read() {
        Ok(s) => s,
        Err(e) => {
            println!("== read 失敗: {e}");
            return;
        }
    };
    if let Some(ms) = &s.mouse {
        println!("== DPI stages: active={}", ms.active_stage);
        for (k, st) in ms.stages.iter().enumerate() {
            println!(
                "   {k}: {}x{:?} enabled={} rgb={:?}",
                st.x, st.y, st.enabled, st.color
            );
        }
        println!("== buttons:");
        for (k, b) in ms.buttons.iter().enumerate() {
            println!("   {k}: {b:?}");
        }
    }
    println!("== settings:");
    for (k, v) in &s.settings {
        println!("   {k} = {v:?}");
    }
    // ---- EEPROM 生ダンプ (DPI 方式の確定用)
    for (addr, len, what) in [
        (0u16, 100u16, "@0 rate/stage/LOD/旧式DPI/色"),
        (96, 64, "@96 ボタン割当"),
        (160, 80, "@160 各種設定"),
        (6912, 60, "@6912 PAW3955 DPI"),
    ] {
        match d.ee_dump(addr, len) {
            Ok(b) => {
                println!("== EEPROM {what}");
                for (k, ch) in b.chunks(10).enumerate() {
                    println!("   {:>5}: {}", addr as usize + k * 10, hiddesc::hex(ch));
                }
            }
            Err(e) => println!("== EEPROM {what}: {e}"),
        }
    }
    if std::env::args().any(|a| a == "--dpi-test") {
        dpi_test(&d, &s);
        return;
    }
    println!("== 完了 (書き込みはしていません)");
}

/// DPI 書き込み往復 (`--dpi-test` のときだけ)。最後に必ず元の値へ戻す。
fn dpi_test(d: &atk::AtkDriver, before: &DeviceState) {
    let Some(ms) = &before.mouse else {
        println!("== dpi-test: mouse state なし");
        return;
    };
    let orig = ms.stages.clone();
    let mut test = orig.clone();
    let step = d.caps().mouse.map(|m| m.dpi_step).unwrap_or(10);
    test[0].x += step;
    test[0].y = test[0].y.map(|y| y + step);
    println!("== dpi-test: 1 段目 {} → {} を書き込みます", orig[0].x, test[0].x);
    let write = |stages: &Vec<DpiStage>| {
        d.apply(&Change::DpiStages {
            stages: stages.clone(),
            active: ms.active_stage,
        })
    };
    if let Err(e) = write(&test) {
        println!("== dpi-test: 書き込み失敗: {e} (何も変わっていません)");
        return;
    }
    let got = d.read().ok().and_then(|s| s.mouse).map(|m| m.stages[0].x);
    println!(
        "== dpi-test: 読み戻し = {got:?} → {}",
        if got == Some(test[0].x) { "一致 OK" } else { "不一致 NG" }
    );
    match write(&orig) {
        Ok(()) => {
            let back = d.read().ok().and_then(|s| s.mouse).map(|m| m.stages[0].x);
            println!(
                "== dpi-test: 元に戻しました = {back:?} → {}",
                if back == Some(orig[0].x) { "OK" } else { "NG (公式ソフトで確認してください)" }
            );
        }
        Err(e) => println!("== dpi-test: 復元失敗: {e} — 公式ソフトで DPI を {} に戻してください", orig[0].x),
    }
}

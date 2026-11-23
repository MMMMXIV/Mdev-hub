//! ATK 系 (373b:*) の**読み取り専用**チェック — 書き込みは一切しない。
//! `cargo run -p devhub-hid --example atkcheck`
//!
//! 1. ff02/u2 collection を探す (有線 / ドングル問わず)
//! 2. cmd16 (CID/MID 問い合わせ) の生応答を出す — 新機種を atk.rs の機種表に足す材料
//! 3. ドライバ経路 (atk::open → info → caps → read) で全設定を読み、表示する

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
    println!("== 完了 (書き込みはしていません)");
}

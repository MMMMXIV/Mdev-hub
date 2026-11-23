//! 任意の HID マウス / キーボードのプロトコル解析 (書き込みなし)。
//!
//! ```text
//! cargo run -p devhub-hid --example hidanalyze                 # マウス/キーボードの一覧
//! cargo run -p devhub-hid --example hidanalyze -- 04d9:fc4d    # 構成 + ディスクリプタ + vendor Feature
//! cargo run -p devhub-hid --example hidanalyze -- 04d9:fc4d --sniff 30   # Input report を 30 秒記録
//! cargo run -p devhub-hid --example hidanalyze -- all          # 全マウス/キーボードを一括解析
//! ```
//!
//! 出力をファイルに残すときは `> log.txt` でリダイレクトする。

use devhub_hid::analyze;
use std::time::Duration;

fn parse_vidpid(s: &str) -> Option<(u16, u16)> {
    let (v, p) = s.split_once(':')?;
    Some((
        u16::from_str_radix(v.trim_start_matches("0x"), 16).ok()?,
        u16::from_str_radix(p.trim_start_matches("0x"), 16).ok()?,
    ))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let api = hidapi::HidApi::new().expect("hidapi init");
    let list = analyze::input_devices(&api);
    let sniff = args.iter().position(|a| a == "--sniff").map(|i| {
        args.get(i + 1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(20u64)
    });
    let target = args.first().filter(|a| !a.starts_with("--"));
    match target.map(String::as_str) {
        None => {
            println!("マウス / キーボードとして見える HID デバイス:");
            for (v, p) in &list {
                let ifs = analyze::interfaces(&api, *v, *p);
                let name = ifs
                    .iter()
                    .find_map(|i| i.product.clone())
                    .unwrap_or_default();
                let maker = ifs
                    .iter()
                    .find_map(|i| i.manufacturer.clone())
                    .unwrap_or_default();
                let vendor = ifs.iter().filter(|i| i.is_vendor()).count();
                let known = devhub_core::registry::KNOWN
                    .iter()
                    .any(|k| k.vid == *v && k.pid == *p);
                println!(
                    "  {v:04x}:{p:04x}  {name} / {maker}  collections={} vendor={vendor}{}",
                    ifs.len(),
                    if known {
                        "  [registry 登録済み]"
                    } else {
                        ""
                    }
                );
            }
            println!("\n詳細: hidanalyze <vid:pid>   記録: hidanalyze <vid:pid> --sniff 20");
        }
        Some("all") => {
            for (v, p) in &list {
                println!("{}", analyze::analyze(&api, *v, *p, true));
            }
        }
        Some(t) => {
            let Some((v, p)) = parse_vidpid(t) else {
                eprintln!("VID:PID の形式で指定してください (例 04d9:fc4d)");
                std::process::exit(2);
            };
            match sniff {
                Some(secs) => {
                    analyze::sniff(&api, v, p, Duration::from_secs(secs), |l| println!("{l}"));
                }
                None => println!("{}", analyze::analyze(&api, v, p, true)),
            }
        }
    }
}

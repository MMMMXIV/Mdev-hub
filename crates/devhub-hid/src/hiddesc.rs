//! HID レポートディスクリプタの最小パーサ (プロトコル解析用)。
//!
//! 未知のデバイスで「どの collection がどの report ID で何バイトを送受信するか」を
//! 機械的に知るためのもの。値の意味づけ (ボタン/軸の論理範囲等) までは追わず、
//! report ID ごとの Input / Output / Feature のビット長と、その上位 collection の
//! usage page / usage だけを集計する。
//!
//! 仕様: USB HID 1.11 §6.2.2 (short item のみ。long item は読み飛ばす)。

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// レポートの向き。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReportKind {
    Input,
    Output,
    Feature,
}

impl ReportKind {
    pub fn label(self) -> &'static str {
        match self {
            ReportKind::Input => "Input",
            ReportKind::Output => "Output",
            ReportKind::Feature => "Feature",
        }
    }
}

/// report ID 1 件 (向きごと) の集計。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportInfo {
    pub kind: ReportKind,
    /// 0 = report ID を使わないデバイス。
    pub id: u8,
    /// データ部のビット数 (report ID バイトは含まない)。
    pub bits: u32,
    /// 最上位 (application) collection の usage page / usage。
    pub usage_page: u16,
    pub usage: u16,
    /// 中で使われた usage page (重複なし、出現順)。
    pub usage_pages: Vec<u16>,
}

impl ReportInfo {
    /// report ID を含む転送バイト数 (hidapi の read/write/feature の長さ)。
    pub fn wire_len(&self) -> usize {
        self.bits.div_ceil(8) as usize + usize::from(self.id != 0)
    }
}

/// ディスクリプタ全体の解析結果。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Descriptor {
    pub reports: Vec<ReportInfo>,
    /// application collection の (usage page, usage) 一覧。
    pub applications: Vec<(u16, u16)>,
}

impl Descriptor {
    pub fn feature_ids(&self) -> Vec<u8> {
        self.reports
            .iter()
            .filter(|r| r.kind == ReportKind::Feature)
            .map(|r| r.id)
            .collect()
    }

    /// vendor-defined (usage page >= 0xFF00) の application を持つか。
    pub fn has_vendor(&self) -> bool {
        self.applications.iter().any(|&(p, _)| p >= 0xFF00)
    }

    /// 人間向けの 1 行/レポートの要約。
    pub fn summary(&self) -> String {
        let mut s = String::new();
        for (p, u) in &self.applications {
            let _ = writeln!(
                s,
                "  application {:04X}:{:04X} {}",
                p,
                u,
                usage_name(*p, *u)
            );
        }
        for r in &self.reports {
            let _ = writeln!(
                s,
                "  {:<7} id=0x{:02X} bits={:<4} wire={:>3}B  in {:04X}:{:04X}",
                r.kind.label(),
                r.id,
                r.bits,
                r.wire_len(),
                r.usage_page,
                r.usage
            );
        }
        s
    }
}

#[derive(Clone, Copy, Default)]
struct Globals {
    usage_page: u16,
    report_size: u32,
    report_count: u32,
    report_id: u8,
}

/// 生ディスクリプタを解析する。壊れた末尾は無視する (分かった所までを返す)。
pub fn parse(desc: &[u8]) -> Descriptor {
    let mut out = Descriptor::default();
    let mut g = Globals::default();
    let mut stack: Vec<Globals> = Vec::new();
    // Local: 直近の usage (usage page 付き 32bit 指定にも対応)。
    let mut local_usages: Vec<(u16, u16)> = Vec::new();
    // collection スタック: (usage page, usage)。
    let mut coll: Vec<(u16, u16)> = Vec::new();
    // (kind, id) → index in out.reports
    let mut idx: BTreeMap<(ReportKind, u8), usize> = BTreeMap::new();

    let mut i = 0usize;
    while i < desc.len() {
        let b = desc[i];
        if b == 0xFE {
            // long item: [FE][size][tag][data..]
            let size = desc.get(i + 1).copied().unwrap_or(0) as usize;
            i += 3 + size;
            continue;
        }
        let size = match b & 0x03 {
            0 => 0,
            1 => 1,
            2 => 2,
            _ => 4,
        };
        if i + 1 + size > desc.len() {
            break;
        }
        let data = &desc[i + 1..i + 1 + size];
        let mut v: u32 = 0;
        for (k, x) in data.iter().enumerate() {
            v |= (*x as u32) << (8 * k);
        }
        let typ = (b >> 2) & 0x03;
        let tag = b >> 4;
        i += 1 + size;
        match (typ, tag) {
            // ---- main
            (0, 0x8) | (0, 0x9) | (0, 0xB) => {
                let kind = match tag {
                    0x8 => ReportKind::Input,
                    0x9 => ReportKind::Output,
                    _ => ReportKind::Feature,
                };
                let app = coll.first().copied().unwrap_or((g.usage_page, 0));
                let k = (kind, g.report_id);
                let n = *idx.entry(k).or_insert_with(|| {
                    out.reports.push(ReportInfo {
                        kind,
                        id: g.report_id,
                        bits: 0,
                        usage_page: app.0,
                        usage: app.1,
                        usage_pages: vec![],
                    });
                    out.reports.len() - 1
                });
                let r = &mut out.reports[n];
                r.bits += g.report_size.saturating_mul(g.report_count);
                let mut pages: Vec<u16> = local_usages.iter().map(|u| u.0).collect();
                if pages.is_empty() {
                    pages.push(g.usage_page);
                }
                for p in pages {
                    if !r.usage_pages.contains(&p) {
                        r.usage_pages.push(p);
                    }
                }
                local_usages.clear();
            }
            (0, 0xA) => {
                // Collection
                let u = local_usages.first().copied().unwrap_or((g.usage_page, 0));
                if coll.is_empty() && !out.applications.contains(&u) {
                    out.applications.push(u);
                }
                coll.push(u);
                local_usages.clear();
            }
            (0, 0xC) => {
                coll.pop();
                local_usages.clear();
            }
            // ---- global
            (1, 0x0) => g.usage_page = v as u16,
            (1, 0x7) => g.report_size = v,
            (1, 0x8) => g.report_id = v as u8,
            (1, 0x9) => g.report_count = v,
            (1, 0xA) => stack.push(g),
            (1, 0xB) => {
                if let Some(p) = stack.pop() {
                    g = p;
                }
            }
            // ---- local
            (2, 0x0) | (2, 0x1) => {
                // Usage / Usage Minimum (4 バイトなら上位 16bit が usage page)
                let u = if size == 4 {
                    ((v >> 16) as u16, v as u16)
                } else {
                    (g.usage_page, v as u16)
                };
                local_usages.push(u);
            }
            _ => {}
        }
    }
    out
}

/// よく出る usage の名前 (解析ログを読みやすくするだけ)。
pub fn usage_name(page: u16, usage: u16) -> &'static str {
    match (page, usage) {
        (0x01, 0x02) => "Mouse",
        (0x01, 0x06) => "Keyboard",
        (0x01, 0x05) => "Gamepad",
        (0x01, 0x04) => "Joystick",
        (0x01, 0x80) => "System Control",
        (0x0C, 0x01) => "Consumer Control",
        (0x0B, _) => "Telephony",
        (p, _) if p >= 0xFF00 => "Vendor-defined (設定用の候補)",
        _ => "",
    }
}

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 3);
    for (i, x) in b.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一般的なブートマウス + vendor feature の合成ディスクリプタ。
    const MOUSE: &[u8] = &[
        0x05, 0x01, 0x09, 0x02, 0xA1,
        0x01, // UP Generic Desktop, Usage Mouse, Collection(App)
        0x85, 0x01, // Report ID 1
        0x09, 0x01, 0xA1, 0x00, // Usage Pointer, Collection(Physical)
        0x05, 0x09, 0x19, 0x01, 0x29, 0x05, // Buttons 1..5
        0x15, 0x00, 0x25, 0x01, 0x95, 0x05, 0x75, 0x01, 0x81, 0x02, // 5x1 bit Input
        0x95, 0x01, 0x75, 0x03, 0x81, 0x03, // padding 3 bit
        0x05, 0x01, 0x09, 0x30, 0x09, 0x31, // X, Y
        0x16, 0x01, 0x80, 0x26, 0xFF, 0x7F, 0x75, 0x10, 0x95, 0x02, 0x81, 0x06, // 2x16
        0xC0, 0xC0, //
        0x06, 0x00, 0xFF, 0x09, 0x01, 0xA1, 0x01, // UP Vendor FF00, Usage 1, Collection(App)
        0x85, 0x05, 0x09, 0x02, 0x75, 0x08, 0x95, 0x10, 0xB1, 0x02, // Feature id5 16B
        0x85, 0x06, 0x09, 0x03, 0x95, 0x3F, 0x81, 0x02, // Input id6 63B
        0xC0,
    ];

    #[test]
    fn parses_mouse_and_vendor() {
        let d = parse(MOUSE);
        assert_eq!(d.applications, vec![(0x01, 0x02), (0xFF00, 0x01)]);
        let inp = d
            .reports
            .iter()
            .find(|r| r.kind == ReportKind::Input && r.id == 1)
            .unwrap();
        assert_eq!(inp.bits, 5 + 3 + 32);
        assert_eq!(inp.wire_len(), 6);
        assert_eq!((inp.usage_page, inp.usage), (0x01, 0x02));
        let f = d
            .reports
            .iter()
            .find(|r| r.kind == ReportKind::Feature)
            .unwrap();
        assert_eq!((f.id, f.bits, f.wire_len()), (5, 128, 17));
        assert_eq!(f.usage_page, 0xFF00);
        assert_eq!(d.feature_ids(), vec![5]);
        assert!(d.has_vendor());
        let v = d
            .reports
            .iter()
            .find(|r| r.kind == ReportKind::Input && r.id == 6)
            .unwrap();
        assert_eq!(v.wire_len(), 64);
    }

    #[test]
    fn truncated_does_not_panic() {
        let d = parse(&MOUSE[..MOUSE.len() - 7]);
        assert!(!d.reports.is_empty());
        let _ = parse(&[0x06, 0x00]);
        let _ = parse(&[0xFE, 0x10]);
    }
}

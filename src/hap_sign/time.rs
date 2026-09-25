//! UTC 时间处理。
//!
//! 不引入 `time` / `chrono`：只需要「Unix 秒 → 日历时间」这一件事，
//! 手写 30 行比拖一个依赖更划算。

/// 把 Unix 秒拆成 UTC 日历时间 `(年, 月, 日, 时, 分, 秒)`。
pub fn utc_from_unix(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    (
        y,
        m,
        d,
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    )
}

/// 把 Unix 秒格式化为 DER UTCTime 内容 `YYMMDDHHMMSSZ`。
pub fn utc_time_content(secs: i64) -> String {
    let (y, m, d, h, mi, s) = utc_from_unix(secs);
    format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        y.rem_euclid(100),
        m,
        d,
        h,
        mi,
        s
    )
}

/// Howard Hinnant `civil_from_days`：以 1970-01-01 为第 0 天的日序号 → 公历年月日。
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    ((if m <= 2 { y + 1 } else { y }) as i32, m, d)
}

/// 当前 Unix 秒。
pub fn now_unix() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch() {
        assert_eq!(utc_from_unix(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(utc_time_content(0), "700101000000Z");
    }

    #[test]
    fn known_timestamps() {
        // 2024-02-29T12:34:56Z
        assert_eq!(utc_from_unix(1_709_210_096i64), (2024, 2, 29, 12, 34, 56));
        assert_eq!(utc_time_content(1_709_210_096), "240229123456Z");
        // 闰年边界：2100 不是闰年
        assert_eq!(utc_from_unix(4_107_542_400i64), (2100, 3, 1, 0, 0, 0));
        assert_eq!(utc_from_unix(951_868_800i64), (2000, 3, 1, 0, 0, 0));
    }

    #[test]
    fn civil_roundtrip() {
        for (ts, expect) in [
            (0i64, (1970, 1, 1, 0, 0, 0)),
            (951_868_800i64, (2000, 3, 1, 0, 0, 0)),
            (1_709_210_096i64, (2024, 2, 29, 12, 34, 56)),
            (4_107_542_400i64, (2100, 3, 1, 0, 0, 0)),
        ] {
            assert_eq!(utc_from_unix(ts), expect);
        }
    }
}

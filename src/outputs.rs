// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! Output coarsening. A verdict carries numbers rounded to what a customer needs to act on,
//! never the full precision the method computes. Full-precision answers to many chosen
//! inputs are what someone would need to rebuild the method from the outside; rounding
//! removes most of that signal while leaving the decision unchanged.
//!
//! Rules: integers, strings, booleans and hashes are untouched. A number under a key ending
//! in `_deg` (a latitude or longitude) is rounded to [`DEG_DECIMALS`] decimal places (about
//! 10 m), every other non-integer number to `sigfigs` significant figures.

use serde_json::{Number, Value};

/// Decimal places kept on angles in degrees (1e-4 deg ≈ 11 m).
pub const DEG_DECIMALS: i32 = 4;

/// Round `x` to `sig` significant figures.
pub fn round_sig(x: f64, sig: u32) -> f64 {
    if x == 0.0 || !x.is_finite() || sig == 0 {
        return x;
    }
    let mag = x.abs().log10().floor() as i32;
    let p = sig as i32 - 1 - mag;
    let f = 10f64.powi(p);
    let r = (x * f).round() / f;
    // Clean binary noise from the division (0.30000000000000004 -> 0.3).
    format!("{r:.*e}", (sig as usize).saturating_sub(1))
        .parse()
        .unwrap_or(r)
}

fn round_dec(x: f64, d: i32) -> f64 {
    let f = 10f64.powi(d);
    let r = (x * f).round() / f;
    format!("{r:.*}", d.max(0) as usize).parse().unwrap_or(r)
}

fn coarse_num(n: &Number, key: Option<&str>, sigfigs: u32) -> Value {
    if n.is_i64() || n.is_u64() {
        return Value::Number(n.clone());
    }
    let x = n.as_f64().unwrap_or(0.0);
    let y = match key {
        Some(k) if k.ends_with("_deg") => round_dec(x, DEG_DECIMALS),
        _ => round_sig(x, sigfigs),
    };
    Number::from_f64(y)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

fn walk(v: &mut Value, key: Option<&str>, sigfigs: u32) {
    match v {
        Value::Number(n) => *v = coarse_num(n, key, sigfigs),
        Value::Array(a) => a.iter_mut().for_each(|x| walk(x, key, sigfigs)),
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                let k = k.clone();
                walk(x, Some(&k), sigfigs);
            }
        }
        _ => {}
    }
}

/// Coarsen every number in a verdict outcome in place (see the module rules).
pub fn coarsen(v: &mut Value, sigfigs: u32) {
    walk(v, None, sigfigs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rounds_floats_keeps_integers_strings_and_angles_to_four_places() {
        let mut v = json!({
            "coverage_after": 0.912345678,
            "mean_pl_after_m": 123.456789,
            "passes": 7,
            "head": "abc123",
            "converged": true,
            "picks": [{"lat_deg": 55.123456789, "lon_deg": 12.98765, "mean_pl_m": 0.000123456}],
            "posterior": [{"value": -0.0098765, "std_err": 0.00123456}]
        });
        coarsen(&mut v, 3);
        assert_eq!(v["coverage_after"], json!(0.912));
        assert_eq!(v["mean_pl_after_m"], json!(123.0));
        assert_eq!(v["passes"], json!(7));
        assert_eq!(v["head"], json!("abc123"));
        assert_eq!(v["picks"][0]["lat_deg"], json!(55.1235));
        assert_eq!(v["picks"][0]["lon_deg"], json!(12.9877));
        assert_eq!(v["picks"][0]["mean_pl_m"], json!(0.000123));
        assert_eq!(v["posterior"][0]["value"], json!(-0.00988));
        assert_eq!(v["posterior"][0]["std_err"], json!(0.00123));
    }

    #[test]
    fn round_sig_edges() {
        assert_eq!(round_sig(0.0, 3), 0.0);
        assert_eq!(round_sig(0.1 + 0.2, 3), 0.3);
        assert_eq!(round_sig(98765.0, 2), 99000.0);
    }
}

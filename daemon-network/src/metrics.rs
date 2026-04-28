//! Prometheus-style metrics for daemon-network.
//!
//! All metrics are `opensesame_network_*` prefixed. Counters and gauges are
//! atomic for lock-free updates from the transport receive loop.

use std::sync::atomic::{AtomicU64, Ordering};

/// Daemon-network metrics.
#[derive(Debug)]
pub struct Metrics {
    /// Active sessions gauge.
    pub sessions_active: AtomicU64,
    /// Total sessions established.
    pub sessions_established_total: AtomicU64,
    /// Sessions rejected because the table was full.
    pub sessions_rejected_full: AtomicU64,
    /// Frames sent (UDP + TCP).
    pub frames_sent_total: AtomicU64,
    /// Frames received (UDP + TCP).
    pub frames_received_total: AtomicU64,
    /// Frames dropped (parse error, short, unknown version).
    pub frames_dropped_total: AtomicU64,
    /// AEAD decryption failures.
    pub aead_failures_total: AtomicU64,
    /// Replay-detected frames.
    pub replay_detected_total: AtomicU64,
    /// TOFU key mismatch events.
    pub tofu_mismatches_total: AtomicU64,
    /// Cookie challenges issued.
    pub cookie_challenges_total: AtomicU64,
    /// Rate-limited frames.
    pub rate_limited_total: AtomicU64,
    /// Handshake failures.
    pub handshake_failures_total: AtomicU64,
    /// Sessions closed (by peer or by idle timeout).
    pub sessions_closed_total: AtomicU64,
}

impl Metrics {
    /// Create zeroed metrics.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions_active: AtomicU64::new(0),
            sessions_established_total: AtomicU64::new(0),
            sessions_rejected_full: AtomicU64::new(0),
            frames_sent_total: AtomicU64::new(0),
            frames_received_total: AtomicU64::new(0),
            frames_dropped_total: AtomicU64::new(0),
            aead_failures_total: AtomicU64::new(0),
            replay_detected_total: AtomicU64::new(0),
            tofu_mismatches_total: AtomicU64::new(0),
            cookie_challenges_total: AtomicU64::new(0),
            rate_limited_total: AtomicU64::new(0),
            handshake_failures_total: AtomicU64::new(0),
            sessions_closed_total: AtomicU64::new(0),
        }
    }

    /// Increment a counter by 1.
    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

fn prom_gauge(out: &mut String, name: &str, help: &str, val: u64) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {val}");
}

fn prom_counter(out: &mut String, name: &str, help: &str, val: u64) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} counter\n{name} {val}");
}

/// Render all metrics in Prometheus text exposition format.
#[must_use]
pub fn render_prometheus(m: &Metrics) -> String {
    let mut out = String::with_capacity(2048);

    prom_gauge(&mut out, "opensesame_network_sessions_active",
        "Active peer sessions", m.sessions_active.load(Ordering::Relaxed));
    prom_counter(&mut out, "opensesame_network_sessions_established_total",
        "Total sessions established", m.sessions_established_total.load(Ordering::Relaxed));
    prom_counter(&mut out, "opensesame_network_sessions_rejected_full_total",
        "Sessions rejected (table full)", m.sessions_rejected_full.load(Ordering::Relaxed));
    prom_counter(&mut out, "opensesame_network_frames_sent_total",
        "Frames sent", m.frames_sent_total.load(Ordering::Relaxed));
    prom_counter(&mut out, "opensesame_network_frames_received_total",
        "Frames received", m.frames_received_total.load(Ordering::Relaxed));
    prom_counter(&mut out, "opensesame_network_frames_dropped_total",
        "Frames dropped", m.frames_dropped_total.load(Ordering::Relaxed));
    prom_counter(&mut out, "opensesame_network_aead_failures_total",
        "AEAD decryption failures", m.aead_failures_total.load(Ordering::Relaxed));
    prom_counter(&mut out, "opensesame_network_replay_detected_total",
        "Replay-detected frames", m.replay_detected_total.load(Ordering::Relaxed));
    prom_counter(&mut out, "opensesame_network_tofu_mismatches_total",
        "TOFU key mismatch events", m.tofu_mismatches_total.load(Ordering::Relaxed));
    prom_counter(&mut out, "opensesame_network_cookie_challenges_total",
        "Cookie challenges issued", m.cookie_challenges_total.load(Ordering::Relaxed));
    prom_counter(&mut out, "opensesame_network_rate_limited_total",
        "Rate-limited frames", m.rate_limited_total.load(Ordering::Relaxed));
    prom_counter(&mut out, "opensesame_network_handshake_failures_total",
        "Handshake failures", m.handshake_failures_total.load(Ordering::Relaxed));
    prom_counter(&mut out, "opensesame_network_sessions_closed_total",
        "Sessions closed", m.sessions_closed_total.load(Ordering::Relaxed));

    out
}

/// Spawn a Prometheus metrics HTTP server on `127.0.0.1:port`.
///
/// Serves `/metrics` in text exposition format. Binds only to localhost
/// to prevent external scraping without explicit proxy configuration.
pub async fn serve_prometheus(metrics: std::sync::Arc<Metrics>, port: u16) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let addr = format!("127.0.0.1:{port}");
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => {
            tracing::info!(addr = %addr, "Prometheus metrics endpoint listening");
            l
        }
        Err(e) => {
            tracing::warn!(addr = %addr, error = %e, "failed to bind Prometheus endpoint");
            return;
        }
    };

    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::debug!(error = %e, "metrics accept error");
                continue;
            }
        };

        let mut reader = tokio::io::BufReader::new(&mut stream);
        let mut request_line = String::new();
        let _ = reader.read_line(&mut request_line).await;

        let response = if request_line.starts_with("GET /metrics") {
            let body = render_prometheus(&metrics);
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
        } else {
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
        };

        let _ = stream.write_all(response.as_bytes()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_prometheus_format() {
        let m = Metrics::new();
        Metrics::inc(&m.sessions_established_total);
        Metrics::inc(&m.sessions_established_total);
        Metrics::inc(&m.aead_failures_total);

        let output = render_prometheus(&m);

        // Must contain TYPE declarations.
        assert!(output.contains("# TYPE opensesame_network_sessions_active gauge"));
        assert!(output.contains("# TYPE opensesame_network_sessions_established_total counter"));

        // Must contain actual values.
        assert!(output.contains("opensesame_network_sessions_established_total 2"));
        assert!(output.contains("opensesame_network_aead_failures_total 1"));
        assert!(output.contains("opensesame_network_sessions_active 0"));

        // Must contain HELP strings.
        assert!(output.contains("# HELP opensesame_network_frames_sent_total"));
    }

    #[test]
    fn render_prometheus_all_zeroes() {
        let m = Metrics::new();
        let output = render_prometheus(&m);

        // All counters should be 0.
        assert!(output.contains("opensesame_network_sessions_established_total 0"));
        assert!(output.contains("opensesame_network_frames_received_total 0"));
        assert!(output.contains("opensesame_network_aead_failures_total 0"));
    }
}

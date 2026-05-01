use mangle_common::Value;

/// A single policy violation: the predicate that fired and its bound arguments.
pub struct Violation {
    pub policy: String,
    pub args: Vec<Value>,
}

impl Violation {
    pub fn arg_strings(&self) -> Vec<String> {
        self.args.iter().map(|v| v.to_string()).collect()
    }
}

pub trait Handler {
    fn handle(&mut self, v: &Violation);
}

/// Emits a line to stderr for each violation.
pub struct LogHandler;

impl Handler for LogHandler {
    fn handle(&mut self, v: &Violation) {
        eprintln!("[{}] {}", v.policy, v.arg_strings().join(", "));
    }
}

/// Collects violations in memory.
pub struct DryRunCollector {
    pub violations: Vec<Violation>,
}

impl DryRunCollector {
    pub fn new() -> Self {
        Self { violations: Vec::new() }
    }

    pub fn print_summary(&self) {
        if self.violations.is_empty() {
            println!("No policy violations found.");
            return;
        }
        println!("Policy violations ({}):", self.violations.len());
        for v in &self.violations {
            println!("  [{}] {}", v.policy, v.arg_strings().join(", "));
        }
    }
}

impl Handler for DryRunCollector {
    fn handle(&mut self, v: &Violation) {
        self.violations.push(Violation {
            policy: v.policy.clone(),
            args: v.args.clone(),
        });
    }
}

/// Webhook handler stub — not wired in the POC (requires reqwest + TLS).
#[allow(dead_code)]
pub struct WebhookHandler {
    pub url: String,
}

#[allow(dead_code)]
impl WebhookHandler {
    pub fn new(url: String) -> Self {
        Self { url }
    }
}

impl Handler for WebhookHandler {
    fn handle(&mut self, v: &Violation) {
        eprintln!("[webhook-stub] {} {} — {}", v.policy, v.arg_strings().join(", "), self.url);
    }
}

use crate::{CodeLocation, Finding, Severity};
use serde::Serialize;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub struct RuleContext<'a> {
    pub path: &'a str,
    pub source: &'a str,
    pub syntax: Option<&'a syn::File>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct RuleMetadata {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub confidence: f32,
    pub cvss: f32,
    pub cwe: &'static str,
    pub category: &'static str,
}

pub trait Rule: Send + Sync {
    fn metadata(&self) -> RuleMetadata;
    fn analyze(&self, context: &RuleContext<'_>) -> Vec<Finding>;
}

pub struct RuleRegistry {
    rules: Vec<Box<dyn Rule>>,
}

impl Default for RuleRegistry {
    fn default() -> Self {
        let mut registry = Self { rules: Vec::new() };
        registry.register(LineRule::missing_signer());
        registry.register(LineRule::unchecked_account());
        registry.register(LineRule::panic_path());
        registry.register(LineRule::unsafe_block());
        registry.register(FileRule::arbitrary_cpi());
        registry.register(FileRule::pda_without_bump());
        registry.register(LineRule::timestamp_dependence());
        registry.register(LineRule::direct_lamport_mutation());
        registry.register(LineRule::lossy_numeric_cast());
        registry.register(FileRule::unvalidated_token_account());
        registry.register(FileRule::untyped_program_account());
        registry
    }
}

impl RuleRegistry {
    pub fn register<R: Rule + 'static>(&mut self, rule: R) {
        self.rules.push(Box::new(rule));
    }
    pub fn analyze(&self, context: &RuleContext<'_>) -> Vec<Finding> {
        self.rules
            .iter()
            .flat_map(|rule| rule.analyze(context))
            .collect()
    }
    pub fn len(&self) -> usize {
        self.rules.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn metadata(&self) -> Vec<RuleMetadata> {
        self.rules.iter().map(|rule| rule.metadata()).collect()
    }
}

struct LineRule {
    metadata: RuleMetadata,
    predicate: fn(&str) -> bool,
    summary: &'static str,
    root_cause: &'static str,
    attack: &'static str,
    remediation: &'static str,
    secure_example: &'static str,
}

impl LineRule {
    fn missing_signer() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RBX001",
                title: "Authority is not typed as a signer",
                severity: Severity::Critical,
                confidence: 0.93,
                cvss: 9.1,
                cwe: "CWE-862",
                category: "Access control",
            },
            predicate: |line| line.contains("authority") && line.contains("AccountInfo<'info>"),
            summary: "An authority account uses unchecked AccountInfo instead of Anchor's Signer type.",
            root_cause: "The account model does not require a transaction signature for the authority.",
            attack: "An attacker can substitute an arbitrary public key and invoke privileged state changes.",
            remediation: "Use Signer<'info> and bind it to the stored authority with a has_one or address constraint.",
            secure_example: "pub authority: Signer<'info>,",
        }
    }

    fn unchecked_account() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RBX002",
                title: "Unchecked account accepts substitution",
                severity: Severity::High,
                confidence: 0.84,
                cvss: 8.1,
                cwe: "CWE-284",
                category: "Account validation",
            },
            predicate: |line| {
                line.trim_start().starts_with("pub ") && line.contains("UncheckedAccount<'info>")
            },
            summary: "An UncheckedAccount is accepted without an evident declarative validation boundary.",
            root_cause: "Unchecked accounts bypass Anchor's ownership and discriminator checks.",
            attack: "A crafted account can be substituted where a program-owned or token account was expected.",
            remediation: "Prefer a typed Account<'info, T>, or document and enforce owner, key, and data invariants.",
            secure_example: "#[account(owner = expected_program.key())]\npub external: UncheckedAccount<'info>,",
        }
    }

    fn panic_path() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RBX004",
                title: "Panic-prone execution path",
                severity: Severity::Medium,
                confidence: 0.96,
                cvss: 5.3,
                cwe: "CWE-248",
                category: "Reliability",
            },
            predicate: |line| line.contains(".unwrap()") || line.contains(".expect("),
            summary: "A reachable unwrap/expect can abort instruction execution instead of returning a program error.",
            root_cause: "Fallible data is converted with a panic rather than propagated as a typed error.",
            attack: "A caller can supply edge-case input that repeatedly fails transactions and wastes compute.",
            remediation: "Map the error into an Anchor error and propagate it with ?.",
            secure_example: "let value = checked_operation().ok_or(ErrorCode::ArithmeticOverflow)?;",
        }
    }

    fn unsafe_block() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RBX006",
                title: "Unsafe Rust in on-chain path",
                severity: Severity::High,
                confidence: 0.99,
                cvss: 7.8,
                cwe: "CWE-119",
                category: "Memory safety",
            },
            predicate: |line| line.contains("unsafe {") || line.contains("unsafe{"),
            summary: "Unsafe Rust weakens the compiler's memory-safety guarantees in security-critical code.",
            root_cause: "The implementation relies on an unchecked memory operation.",
            attack: "Malformed input may reach undefined behavior if the unsafe invariant is incomplete.",
            remediation: "Replace with safe APIs or isolate the operation behind a reviewed, tested abstraction.",
            secure_example: "let bytes = account.try_borrow_data()?;",
        }
    }

    fn timestamp_dependence() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RBX007",
                title: "Security decision depends on validator time",
                severity: Severity::Medium,
                confidence: 0.88,
                cvss: 5.9,
                cwe: "CWE-367",
                category: "Solana sysvars",
            },
            predicate: |line| line.contains("unix_timestamp") || line.contains("Clock::get()"),
            summary: "The instruction reads validator-controlled clock data in an execution path.",
            root_cause: "Cluster time is approximate and can drift within the bounds allowed to validators.",
            attack: "A boundary-sensitive check may be executed earlier or later than the business rule expects.",
            remediation: "Use explicit tolerance windows and avoid exact-time equality or narrow expiry boundaries.",
            secure_example: "require!(clock.unix_timestamp >= opens_at.saturating_sub(TOLERANCE), ErrorCode::NotOpen);",
        }
    }

    fn direct_lamport_mutation() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RBX008",
                title: "Direct lamport mutation requires balance invariants",
                severity: Severity::High,
                confidence: 0.86,
                cvss: 8.0,
                cwe: "CWE-682",
                category: "Lamport accounting",
            },
            predicate: |line| {
                line.contains("lamports.borrow_mut") || line.contains("try_borrow_mut_lamports")
            },
            summary: "The program directly mutates account lamports outside a System Program transfer.",
            root_cause: "Manual balance changes rely on the program preserving ownership, rent, and conservation invariants.",
            attack: "An incorrect debit/credit pair can drain a program-owned account or create transaction failures.",
            remediation: "Check ownership and rent constraints, use checked arithmetic, and assert conserved lamports.",
            secure_example: "let next = source.lamports().checked_sub(amount).ok_or(ErrorCode::InsufficientFunds)?;",
        }
    }

    fn lossy_numeric_cast() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RBX009",
                title: "Lossy numeric cast in on-chain arithmetic",
                severity: Severity::Medium,
                confidence: 0.74,
                cvss: 5.5,
                cwe: "CWE-681",
                category: "Arithmetic",
            },
            predicate: |line| {
                [" as u8", " as u16", " as u32", " as u64", " as usize"]
                    .iter()
                    .any(|cast| line.contains(cast))
            },
            summary: "A numeric value is converted with `as`, which may truncate or wrap without an error.",
            root_cause: "Rust's primitive casts do not enforce the financial range invariant expected by the program.",
            attack: "A large user-controlled amount can be narrowed into an unintended value used for accounting.",
            remediation: "Use TryFrom/TryInto and return a typed program error when the value is out of range.",
            secure_example: "let amount = u64::try_from(raw_amount).map_err(|_| ErrorCode::InvalidAmount)?;",
        }
    }
}

impl Rule for LineRule {
    fn metadata(&self) -> RuleMetadata {
        self.metadata
    }
    fn analyze(&self, context: &RuleContext<'_>) -> Vec<Finding> {
        context
            .source
            .lines()
            .enumerate()
            .filter_map(|(index, line)| {
                (self.predicate)(line).then(|| {
                    make_finding(
                        self.metadata,
                        context.path,
                        index + 1,
                        line,
                        self.summary,
                        self.root_cause,
                        self.attack,
                        self.remediation,
                        self.secure_example,
                    )
                })
            })
            .collect()
    }
}

struct FileRule {
    metadata: RuleMetadata,
    predicate: fn(&str) -> Option<(usize, &str)>,
    summary: &'static str,
    root_cause: &'static str,
    attack: &'static str,
    remediation: &'static str,
    secure_example: &'static str,
}

impl FileRule {
    fn arbitrary_cpi() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RBX003",
                title: "CPI target may be attacker-controlled",
                severity: Severity::Critical,
                confidence: 0.82,
                cvss: 9.0,
                cwe: "CWE-829",
                category: "Cross-program invocation",
            },
            predicate: |source| {
                if source.contains("remaining_accounts")
                    && (source.contains("invoke(") || source.contains("invoke_signed("))
                {
                    source
                        .lines()
                        .enumerate()
                        .find(|(_, line)| {
                            line.contains("invoke(") || line.contains("invoke_signed(")
                        })
                        .map(|(i, line)| (i + 1, line))
                } else {
                    None
                }
            },
            summary: "A raw CPI is assembled in a context that consumes remaining_accounts.",
            root_cause: "The invoked program identity is not evidently pinned to a trusted program ID.",
            attack: "A malicious program can receive the caller's forwarded signer privileges.",
            remediation: "Use Program<'info, T> or compare the target key with the expected program ID before invoking.",
            secure_example: "require_keys_eq!(target.key(), trusted_program::ID, ErrorCode::InvalidProgram);",
        }
    }

    fn pda_without_bump() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RBX005",
                title: "PDA constraint omits canonical bump",
                severity: Severity::Medium,
                confidence: 0.78,
                cvss: 6.0,
                cwe: "CWE-347",
                category: "PDA validation",
            },
            predicate: |source| {
                if source.contains("seeds =") && !source.contains("bump") {
                    source
                        .lines()
                        .enumerate()
                        .find(|(_, line)| line.contains("seeds ="))
                        .map(|(i, line)| (i + 1, line))
                } else {
                    None
                }
            },
            summary: "A PDA seed constraint does not visibly require Anchor's canonical bump.",
            root_cause: "Seed verification is incomplete without a canonical bump constraint.",
            attack: "A non-canonical derived address may bypass assumptions made by downstream instructions.",
            remediation: "Add bump and, when appropriate, seeds::program to the account constraint.",
            secure_example: "#[account(seeds = [b\"vault\", authority.key().as_ref()], bump)]",
        }
    }

    fn unvalidated_token_account() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RBX010",
                title: "SPL token account lacks mint or authority constraint",
                severity: Severity::High,
                confidence: 0.72,
                cvss: 7.7,
                cwe: "CWE-20",
                category: "SPL Token validation",
            },
            predicate: |source| {
                if source.contains("TokenAccount")
                    && !source.contains("token::mint")
                    && !source.contains("token::authority")
                    && !source.contains("associated_token::")
                {
                    source
                        .lines()
                        .enumerate()
                        .find(|(_, line)| line.contains("TokenAccount"))
                        .map(|(index, line)| (index + 1, line))
                } else {
                    None
                }
            },
            summary: "A typed token account is present without an evident mint or authority relationship constraint.",
            root_cause: "Type checking alone proves SPL ownership, not that the account belongs to the expected mint or user.",
            attack: "An attacker can substitute a valid token account for a different mint or authority.",
            remediation: "Bind token accounts with token::mint/token::authority or associated_token constraints.",
            secure_example: "#[account(token::mint = mint, token::authority = authority)]",
        }
    }

    fn untyped_program_account() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RBX011",
                title: "External program is accepted as AccountInfo",
                severity: Severity::High,
                confidence: 0.83,
                cvss: 8.2,
                cwe: "CWE-829",
                category: "Cross-program invocation",
            },
            predicate: |source| {
                source
                    .lines()
                    .enumerate()
                    .find(|(_, line)| {
                        line.contains("program") && line.contains("AccountInfo<'info>")
                    })
                    .map(|(index, line)| (index + 1, line))
            },
            summary: "A CPI program account is untyped, so its executable identity is not declaratively pinned.",
            root_cause: "AccountInfo does not prove that the supplied account is the intended external program.",
            attack: "A caller can substitute another executable program and redirect a CPI.",
            remediation: "Use Program<'info, T> or an address constraint against the trusted program ID.",
            secure_example: "pub token_program: Program<'info, Token>,",
        }
    }
}

impl Rule for FileRule {
    fn metadata(&self) -> RuleMetadata {
        self.metadata
    }
    fn analyze(&self, context: &RuleContext<'_>) -> Vec<Finding> {
        (self.predicate)(context.source)
            .map(|(line_number, line)| {
                vec![make_finding(
                    self.metadata,
                    context.path,
                    line_number,
                    line,
                    self.summary,
                    self.root_cause,
                    self.attack,
                    self.remediation,
                    self.secure_example,
                )]
            })
            .unwrap_or_default()
    }
}

#[allow(clippy::too_many_arguments)]
fn make_finding(
    metadata: RuleMetadata,
    path: &str,
    line: usize,
    snippet: &str,
    summary: &str,
    root_cause: &str,
    attack: &str,
    remediation: &str,
    secure_example: &str,
) -> Finding {
    let mut hasher = DefaultHasher::new();
    (metadata.id, path, line).hash(&mut hasher);
    Finding {
        id: format!("{}-{:x}", metadata.id, hasher.finish()),
        rule_id: metadata.id.into(),
        title: metadata.title.into(),
        severity: metadata.severity,
        confidence: metadata.confidence,
        cvss: metadata.cvss,
        cwe: metadata.cwe.into(),
        category: metadata.category.into(),
        location: CodeLocation {
            file: path.into(),
            line_start: line,
            line_end: line,
            snippet: snippet.trim().into(),
        },
        summary: summary.into(),
        root_cause: root_cause.into(),
        attack_scenario: attack.into(),
        remediation: remediation.into(),
        secure_example: secure_example.into(),
        references: vec![
            "https://www.anchor-lang.com/docs/account-constraints".into(),
            "https://solana.com/docs/core/cpi".into(),
        ],
    }
}

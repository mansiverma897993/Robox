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
        registry.register(LineRule::wrapping_arithmetic());
        registry.register(LineRule::unchecked_deserialization());
        registry.register(FileRule::raw_token_authority());
        registry.register(FileRule::raw_token_owner());
        registry.register(FileRule::untyped_sysvar());
        registry.register(FileRule::noncanonical_pda());
        registry.register(FileRule::duplicate_mutable_accounts());
        registry.register(FileRule::missing_discriminator());
        registry.register(FileRule::reinitialization());
        registry.register(FileRule::manual_close());
        registry.register(FileRule::shared_pda_signer());
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
                severity: Severity::High,
                confidence: 0.78,
                cvss: 8.1,
                cwe: "CWE-862",
                category: "Access control",
            },
            predicate: |line| line.contains("authority") && line.contains("AccountInfo<'info>"),
            summary: "An authority account uses AccountInfo without a declarative signer constraint. Check the handler for equivalent validation.",
            root_cause: "AccountInfo alone does not require a transaction signature or bind the account to stored authority state.",
            attack: "If the handler trusts this account as an authority without checking its signature and key, a caller may authorize privileged state changes.",
            remediation: "Use Signer<'info> and bind its key to the stored authority with has_one, address, or an explicit require_keys_eq! check.",
            secure_example: "pub authority: Signer<'info>,",
        }
    }

    fn unchecked_account() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RBX002",
                title: "Unchecked account accepts substitution",
                severity: Severity::High,
                confidence: 0.75,
                cvss: 8.1,
                cwe: "CWE-284",
                category: "Account validation",
            },
            predicate: |line| {
                line.trim_start().starts_with("pub ") && line.contains("UncheckedAccount<'info>")
            },
            summary: "An UncheckedAccount has no field-level ownership, address, seeds, or custom constraint. Check for equivalent handler validation.",
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
                severity: Severity::Medium,
                confidence: 0.99,
                cvss: 7.8,
                cwe: "CWE-119",
                category: "Memory safety",
            },
            predicate: |line| line.contains("unsafe {") || line.contains("unsafe{"),
            summary: "Unsafe Rust is present in code selected for audit; its safety invariants need manual review.",
            root_cause: "The implementation relies on an unchecked memory operation.",
            attack: "Malformed input may reach undefined behavior if the documented safety invariant is incomplete.",
            remediation: "Replace with safe APIs or isolate the operation behind a reviewed, tested abstraction.",
            secure_example: "let bytes = account.try_borrow_data()?;",
        }
    }

    fn timestamp_dependence() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RBX007",
                title: "Security decision depends on validator time",
                severity: Severity::Low,
                confidence: 0.66,
                cvss: 3.7,
                cwe: "CWE-367",
                category: "Solana sysvars",
            },
            predicate: |line| {
                line.contains("unix_timestamp")
                    && [">", "<", "==", "!="]
                        .iter()
                        .any(|operator| line.contains(operator))
            },
            summary: "A time comparison may depend on approximate cluster time; review narrow boundary assumptions.",
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
                severity: Severity::Medium,
                confidence: 0.74,
                cvss: 6.0,
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

    fn wrapping_arithmetic() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RBX012",
                title: "Wrapping arithmetic needs an explicit invariant",
                severity: Severity::Medium,
                confidence: 0.77,
                cvss: 5.9,
                cwe: "CWE-190",
                category: "Arithmetic",
            },
            predicate: |line| {
                [".wrapping_add(", ".wrapping_sub(", ".wrapping_mul("]
                    .iter()
                    .any(|method| line.contains(method))
            },
            summary: "Wrapping arithmetic discards overflow or underflow. Review whether the value controls balances, supply, limits, or authorization.",
            root_cause: "The arithmetic deliberately wraps instead of failing when its result exceeds the integer range.",
            attack: "If the operand is caller controlled and the result affects value or permissions, a boundary input may bypass an invariant.",
            remediation: "Use checked_add, checked_sub, or checked_mul and return a typed error unless modular arithmetic is a documented protocol requirement.",
            secure_example: "let next = balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;",
        }
    }

    fn unchecked_deserialization() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RBX013",
                title: "Unchecked account data deserialization",
                severity: Severity::High,
                confidence: 0.83,
                cvss: 8.0,
                cwe: "CWE-20",
                category: "Account validation",
            },
            predicate: |line| {
                line.contains("try_from_slice_unchecked(")
                    || line.contains("deserialize_unchecked(")
            },
            summary: "Account data is decoded without the normal shape or discriminator validation. Review the account owner and expected type checks.",
            root_cause: "Unchecked deserialization accepts bytes that may not represent the intended account type.",
            attack: "If caller supplied data reaches this path without owner, discriminator, and length checks, crafted bytes may be trusted as program state.",
            remediation: "Prefer checked account deserialization; if unchecked decoding is required, validate owner, discriminator, exact length, and state invariants first.",
            secure_example: "require_keys_eq!(*account.owner, expected_program::ID, ErrorCode::InvalidOwner);",
        }
    }
}

impl Rule for LineRule {
    fn metadata(&self) -> RuleMetadata {
        self.metadata
    }
    fn analyze(&self, context: &RuleContext<'_>) -> Vec<Finding> {
        let code = code_lines(context.source);
        let account_fields = account_fields(&code);
        code.iter()
            .enumerate()
            .filter_map(|(index, line)| {
                let matches = match self.metadata.id {
                    "RBX001" => account_fields.iter().any(|field| {
                        field.line == index + 1
                            && field.name.contains("authority")
                            && field.ty.contains("AccountInfo")
                            && !field.constraints.contains("signer")
                            && !code.iter().any(|candidate| {
                                candidate.contains(&format!("{}.is_signer", field.name))
                            })
                    }),
                    "RBX002" => account_fields.iter().any(|field| {
                        field.line == index + 1
                            && field.ty.contains("UncheckedAccount")
                            && !has_account_validation(&field.constraints)
                    }),
                    _ => (self.predicate)(line),
                };
                matches.then(|| {
                    make_finding(
                        self.metadata,
                        context.path,
                        index + 1,
                        context.source.lines().nth(index).unwrap_or(line),
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
    #[allow(clippy::too_many_arguments)]
    fn heuristic(
        metadata: RuleMetadata,
        summary: &'static str,
        root_cause: &'static str,
        attack: &'static str,
        remediation: &'static str,
        secure_example: &'static str,
    ) -> Self {
        Self {
            metadata,
            predicate: |_| None,
            summary,
            root_cause,
            attack,
            remediation,
            secure_example,
        }
    }

    fn raw_token_authority() -> Self {
        Self::heuristic(
            RuleMetadata {
                id: "RBX014",
                title: "Raw token data lacks an authority relationship check",
                severity: Severity::High,
                confidence: 0.78,
                cvss: 7.6,
                cwe: "CWE-284",
                category: "SPL Token validation",
            },
            "SPL token bytes are decoded from an account without an evident comparison between token authority and the expected signer.",
            "Raw decoding does not bind the token account's authority to the instruction's authority.",
            "A caller may substitute another token account whose balance or privileges are incorrectly trusted.",
            "Use Account<'info, TokenAccount> with token::authority or compare the decoded owner to the signer and verify the account's program owner.",
            "#[account(token::authority = authority)]\ntoken: Account<'info, TokenAccount>,",
        )
    }

    fn raw_token_owner() -> Self {
        Self::heuristic(
            RuleMetadata {
                id: "RBX015",
                title: "Raw token account lacks a Token Program owner check",
                severity: Severity::High,
                confidence: 0.82,
                cvss: 8.0,
                cwe: "CWE-284",
                category: "SPL Token validation",
            },
            "SPL token data is decoded from AccountInfo without an evident account owner check against the Token Program.",
            "Deserializing bytes does not establish which program owns the source account.",
            "An attacker-controlled account with token-shaped bytes may pass data checks unless its program owner is verified.",
            "Prefer Account<'info, TokenAccount>; otherwise verify *account.owner equals the trusted Token Program ID before decoding.",
            "require_keys_eq!(*token.owner, spl_token::ID, ErrorCode::InvalidOwner);",
        )
    }

    fn untyped_sysvar() -> Self {
        Self::heuristic(
            RuleMetadata {
                id: "RBX016",
                title: "Sysvar account identity is not pinned",
                severity: Severity::Medium,
                confidence: 0.82,
                cvss: 6.4,
                cwe: "CWE-20",
                category: "Sysvar validation",
            },
            "A sysvar-named AccountInfo has no field-level address constraint or visible key comparison.",
            "AccountInfo alone does not prove that a caller supplied account is the expected sysvar.",
            "A substituted account can supply an unexpected key or data to logic that trusts the sysvar identity.",
            "Use Sysvar<'info, Rent/Clock> or require the account key to equal the expected sysvar ID.",
            "rent: Sysvar<'info, Rent>,",
        )
    }

    fn noncanonical_pda() -> Self {
        Self::heuristic(
            RuleMetadata {
                id: "RBX017",
                title: "PDA address may accept a noncanonical bump",
                severity: Severity::Medium,
                confidence: 0.75,
                cvss: 6.0,
                cwe: "CWE-347",
                category: "PDA validation",
            },
            "A PDA is checked with create_program_address and an apparent bump input without an evident canonical bump comparison.",
            "create_program_address validates a candidate address but does not select the canonical bump.",
            "Multiple valid bump values can create addresses that bypass one-address-per-seed assumptions.",
            "Derive with find_program_address and compare the returned bump, or use Anchor seeds and bump constraints.",
            "let (expected, canonical_bump) = Pubkey::find_program_address(&seeds, program_id);",
        )
    }

    fn duplicate_mutable_accounts() -> Self {
        Self::heuristic(
            RuleMetadata {
                id: "RBX018",
                title: "Distinct mutable accounts may alias",
                severity: Severity::Medium,
                confidence: 0.72,
                cvss: 6.4,
                cwe: "CWE-841",
                category: "Account validation",
            },
            "An instruction mutates two account roles without a visible key inequality check.",
            "The caller may supply the same account for both roles unless the program enforces distinct keys.",
            "State updates intended for independent accounts can overwrite each other when both roles alias.",
            "Require different public keys with an Anchor constraint or explicit comparison before mutating either account.",
            "#[account(constraint = user_a.key() != user_b.key())]",
        )
    }

    fn missing_discriminator() -> Self {
        Self::heuristic(
            RuleMetadata {
                id: "RBX019",
                title: "Raw state decoding lacks a type discriminator",
                severity: Severity::High,
                confidence: 0.78,
                cvss: 7.7,
                cwe: "CWE-20",
                category: "Account validation",
            },
            "Program state is decoded from raw account bytes without a visible discriminator or typed Anchor account check.",
            "Struct-shaped bytes can be accepted as the wrong account type when no discriminator is enforced.",
            "A differently typed program-owned account may be interpreted as privileged state.",
            "Use Account<'info, T> or verify owner, exact account type discriminator, and length before raw decoding.",
            "user: Account<'info, User>,",
        )
    }

    fn reinitialization() -> Self {
        Self::heuristic(
            RuleMetadata {
                id: "RBX020",
                title: "Initialization may overwrite existing authority",
                severity: Severity::High,
                confidence: 0.76,
                cvss: 8.1,
                cwe: "CWE-841",
                category: "Initialization",
            },
            "An initialize path rewrites authority in raw account data without an evident already-initialized guard.",
            "Reusing an initialized account can reset its security-sensitive authority state.",
            "A caller may invoke initialization again to replace a prior authority or configuration.",
            "Use Anchor init with a typed account, or check a discriminator/initialized flag before writing authority.",
            "#[account(init, payer = authority, space = 8 + User::INIT_SPACE)]",
        )
    }

    fn manual_close() -> Self {
        Self::heuristic(
            RuleMetadata {
                id: "RBX021",
                title: "Manual account close may permit account revival",
                severity: Severity::High,
                confidence: 0.77,
                cvss: 7.7,
                cwe: "CWE-672",
                category: "Account lifecycle",
            },
            "An account's lamports are set to zero without a visible closed-account discriminator or Anchor close constraint.",
            "Draining lamports alone does not mark account data as closed within the transaction.",
            "Another instruction may replenish the account and reuse stale data before cleanup.",
            "Use #[account(close = destination)] or clear data and write a closed-account discriminator before allowing reuse.",
            "#[account(mut, close = destination)] account: Account<'info, Data>,",
        )
    }

    fn shared_pda_signer() -> Self {
        Self::heuristic(
            RuleMetadata {
                id: "RBX022",
                title: "Token withdrawal uses a shared mint-derived PDA signer",
                severity: Severity::Medium,
                confidence: 0.68,
                cvss: 6.5,
                cwe: "CWE-284",
                category: "PDA authorization",
            },
            "A token withdrawal signs with seeds derived from the pool mint while a distinct withdrawal destination is present.",
            "A mint-wide PDA can be shared across different withdrawal destinations or vault contexts.",
            "If destination-specific authority is expected, a caller may reuse the shared signer for a different withdrawal path.",
            "Include the vault or withdrawal destination in PDA seeds and constrain the derived account against the same seeds and bump.",
            "#[account(seeds = [withdraw_destination.key().as_ref()], bump = pool.bump)]",
        )
    }

    fn arbitrary_cpi() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RBX003",
                title: "CPI target may be attacker-controlled",
                severity: Severity::High,
                confidence: 0.73,
                cvss: 8.0,
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
            summary: "A raw CPI appears in a function that consumes caller supplied remaining_accounts; verify the instruction's program ID.",
            root_cause: "The invoked program identity is not visibly pinned to a trusted program ID near the call.",
            attack: "If the CPI instruction targets a caller supplied program, that program can receive forwarded signer or writable privileges.",
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
            summary: "This PDA field's seed constraint does not visibly require Anchor's canonical bump.",
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
            summary: "This typed token account lacks a field-level mint or authority relationship constraint. Check for equivalent handler validation.",
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
            summary: "This CPI program account is untyped and has no field-level address constraint. Check for equivalent handler validation.",
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
        let code = code_lines(context.source);
        let fields = account_fields(&code);
        let matches: Vec<usize> = match self.metadata.id {
            "RBX003" => code
                .iter()
                .enumerate()
                .filter_map(|(index, line)| {
                    if !(line.contains("invoke(") || line.contains("invoke_signed(")) {
                        return None;
                    }
                    let start = code[..=index].iter().rposition(|candidate| {
                        candidate.contains("fn ") && candidate.contains('{')
                    })?;
                    let body = &code[start..=index];
                    let uses_remaining = body
                        .iter()
                        .any(|candidate| candidate.contains("remaining_accounts"));
                    let checks_target = body.iter().any(|candidate| {
                        candidate.contains("require_keys_eq!")
                            || candidate.contains("require_eq!")
                            || candidate.contains("check_program_account")
                    });
                    (uses_remaining && !checks_target).then_some(index + 1)
                })
                .collect(),
            "RBX005" => fields
                .iter()
                .filter(|field| {
                    field.constraints.contains("seeds") && !field.constraints.contains("bump")
                })
                .map(|field| field.constraint_line.unwrap_or(field.line))
                .collect(),
            "RBX010" => fields
                .iter()
                .filter(|field| {
                    field.ty.contains("TokenAccount")
                        && fields.iter().any(|other| {
                            other.struct_name == field.struct_name
                                && other.name == "mint"
                                && other.ty.contains("Mint")
                        })
                        && !field.constraints.contains("token::mint")
                        && !field.constraints.contains("token::authority")
                        && !field.constraints.contains("associated_token::")
                        && !field.constraints.contains("constraint")
                })
                .map(|field| field.line)
                .collect(),
            "RBX011" => fields
                .iter()
                .filter(|field| {
                    field.name.contains("program")
                        && field.ty.contains("AccountInfo")
                        && !field.constraints.contains("address")
                        && !field.constraints.contains("constraint")
                        && !code.iter().any(|line| {
                            line.contains(&field.name)
                                && (line.contains("::ID") || line.contains("::id()"))
                                && (line.contains("!=")
                                    || line.contains("==")
                                    || line.contains("require_keys_eq!"))
                        })
                })
                .map(|field| field.line)
                .collect(),
            "RBX014" => {
                let has_raw_token = fields
                    .iter()
                    .any(|field| field.name == "token" && field.ty.contains("AccountInfo"));
                let authority_bound = code.iter().any(|line| {
                    line.contains("token.owner")
                        && line.contains("authority")
                        && (line.contains("!=")
                            || line.contains("==")
                            || line.contains("require_keys_eq!"))
                });
                if has_raw_token && !authority_bound {
                    first_line(&code, "SplTokenAccount::unpack(")
                        .into_iter()
                        .collect()
                } else {
                    Vec::new()
                }
            }
            "RBX015" => {
                let has_raw_token = fields
                    .iter()
                    .any(|field| field.name == "token" && field.ty.contains("AccountInfo"));
                let owner_pinned = code.iter().any(|line| {
                    line.contains("ctx.accounts.token.owner") && line.contains("spl_token::ID")
                });
                if has_raw_token && !owner_pinned {
                    first_line(&code, "SplTokenAccount::unpack(")
                        .into_iter()
                        .collect()
                } else {
                    Vec::new()
                }
            }
            "RBX016" => fields
                .iter()
                .filter(|field| {
                    ["rent", "clock", "instructions"].contains(&field.name.as_str())
                        && field.ty.contains("AccountInfo")
                        && !field.constraints.contains("address")
                        && !code.iter().any(|line| {
                            line.contains(&field.name)
                                && line.contains("::ID")
                                && (line.contains("require_eq!")
                                    || line.contains("require_keys_eq!")
                                    || line.contains("==")
                                    || line.contains("!="))
                        })
                })
                .map(|field| field.line)
                .collect(),
            "RBX017" => {
                if code
                    .iter()
                    .any(|line| line.contains("find_program_address("))
                {
                    Vec::new()
                } else {
                    first_line(&code, "create_program_address(")
                        .into_iter()
                        .collect()
                }
            }
            "RBX018" => duplicate_mutable_location(&code).into_iter().collect(),
            "RBX019" => {
                let has_discriminator = code
                    .iter()
                    .any(|line| line.contains("discriminant") || line.contains("discriminator"));
                if has_discriminator {
                    Vec::new()
                } else {
                    first_line(&code, "::try_from_slice(&ctx.accounts.")
                        .into_iter()
                        .collect()
                }
            }
            "RBX020" => {
                let initializes = code
                    .iter()
                    .any(|line| line.contains("fn initialize(") || line.contains("fn init("));
                let writes_authority = code.iter().any(|line| line.contains(".authority ="));
                let has_guard = code.iter().any(|line| {
                    line.contains("if ")
                        && (line.contains("discriminator") || line.contains("initialized"))
                });
                if initializes
                    && writes_authority
                    && !has_guard
                    && code
                        .iter()
                        .any(|line| line.contains("::try_from_slice(&ctx.accounts."))
                {
                    code.iter()
                        .enumerate()
                        .find(|(_, line)| line.contains(".authority ="))
                        .map(|(index, _)| index + 1)
                        .into_iter()
                        .collect()
                } else {
                    Vec::new()
                }
            }
            "RBX021" => {
                if code.iter().any(|line| {
                    line.contains("CLOSED_ACCOUNT_DISCRIMINATOR") || line.contains("close =")
                }) {
                    Vec::new()
                } else {
                    code.iter()
                        .enumerate()
                        .filter(|(_, line)| {
                            line.contains("lamports.borrow_mut()") && line.contains("= 0")
                        })
                        .map(|(index, _)| index + 1)
                        .collect()
                }
            }
            "RBX022" => {
                if code.iter().any(|line| line.contains("with_signer("))
                    && code.iter().any(|line| line.contains("token::transfer("))
                    && code
                        .iter()
                        .any(|line| line.contains("withdraw_destination"))
                    && !code.iter().any(|line| {
                        line.contains("withdraw_destination.as_ref()")
                            || line.contains("withdraw_destination.key().as_ref()")
                    })
                {
                    code.iter()
                        .enumerate()
                        .find(|(_, line)| line.contains(".mint.as_ref()"))
                        .map(|(index, _)| index + 1)
                        .into_iter()
                        .collect()
                } else {
                    Vec::new()
                }
            }
            _ => (self.predicate)(&code.join("\n"))
                .map(|(line, _)| vec![line])
                .unwrap_or_default(),
        };
        matches
            .into_iter()
            .filter_map(|line_number| {
                let line = context.source.lines().nth(line_number - 1)?;
                Some(make_finding(
                    self.metadata,
                    context.path,
                    line_number,
                    line,
                    self.summary,
                    self.root_cause,
                    self.attack,
                    self.remediation,
                    self.secure_example,
                ))
            })
            .collect()
    }
}

fn first_line(lines: &[String], pattern: &str) -> Option<usize> {
    lines
        .iter()
        .position(|line| line.contains(pattern))
        .map(|index| index + 1)
}

fn duplicate_mutable_location(lines: &[String]) -> Option<usize> {
    let mut prior: Option<(String, usize)> = None;
    for (index, line) in lines.iter().enumerate() {
        let Some((_, rest)) = line.split_once("&mut ctx.accounts.") else {
            continue;
        };
        let name = rest
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .collect::<String>();
        if name.is_empty() {
            continue;
        }
        if let Some((first, _)) = &prior {
            if first == &name {
                continue;
            }
            let distinct = lines.iter().any(|candidate| {
                candidate.contains(&format!("{first}.key()"))
                    && candidate.contains(&format!("{name}.key()"))
                    && (candidate.contains("!=") || candidate.contains("=="))
            });
            if !distinct {
                return Some(index + 1);
            }
        } else {
            prior = Some((name, index + 1));
        }
    }
    None
}

struct AccountField {
    line: usize,
    constraint_line: Option<usize>,
    struct_name: String,
    name: String,
    ty: String,
    constraints: String,
}

fn has_account_validation(constraints: &str) -> bool {
    ["owner", "address", "constraint", "seeds", "has_one"]
        .iter()
        .any(|marker| constraints.contains(marker))
}

fn account_fields(lines: &[String]) -> Vec<AccountField> {
    let mut fields = Vec::new();
    let mut pending_derive = false;
    let mut in_accounts = false;
    let mut struct_name = String::new();
    let mut constraints = String::new();
    let mut constraint_line = None;
    let mut in_attribute = false;

    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("derive(") && trimmed.contains("Accounts") {
            pending_derive = true;
        }
        if trimmed.contains("pub struct ") {
            in_accounts = pending_derive;
            struct_name = trimmed
                .split_once("pub struct ")
                .map(|(_, rest)| {
                    rest.chars()
                        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
                        .collect()
                })
                .unwrap_or_default();
            pending_derive = false;
            constraints.clear();
        }
        if !in_accounts {
            continue;
        }
        if trimmed == "}" {
            in_accounts = false;
            continue;
        }
        if trimmed.starts_with("#[account(") {
            constraints.clear();
            constraint_line = Some(index + 1);
            in_attribute = true;
        }
        if in_attribute {
            constraints.push_str(trimmed);
            constraints.push(' ');
            if trimmed.ends_with(")]") {
                in_attribute = false;
            }
            continue;
        }
        let field = trimmed.strip_prefix("pub ").unwrap_or(trimmed);
        if field.ends_with(',')
            && let Some((name, ty)) = field.split_once(':')
        {
            fields.push(AccountField {
                line: index + 1,
                constraint_line,
                struct_name: struct_name.clone(),
                name: name.trim().to_owned(),
                ty: ty.trim().to_owned(),
                constraints: constraints.clone(),
            });
            constraints.clear();
            constraint_line = None;
        }
    }
    fields
}

fn code_lines(source: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut block_comment = false;
    for source_line in source.lines() {
        let mut output = String::new();
        let mut chars = source_line.chars().peekable();
        let mut quoted = false;
        let mut escaped = false;
        while let Some(character) = chars.next() {
            let next = chars.peek().copied();
            if block_comment {
                if character == '*' && next == Some('/') {
                    chars.next();
                    block_comment = false;
                }
                continue;
            }
            if !quoted && character == '/' && next == Some('/') {
                break;
            }
            if !quoted && character == '/' && next == Some('*') {
                chars.next();
                block_comment = true;
                continue;
            }
            output.push(character);
            if character == '"' && !escaped {
                quoted = !quoted;
            }
            escaped = character == '\\' && !escaped;
        }
        lines.push(output);
    }
    lines
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
        sensitive_asset: match metadata.id {
            "RBX001" => "Privileged authority and protected vault state",
            "RBX002" | "RBX013" | "RBX019" => "Account ownership, identity, and decoded state",
            "RBX003" | "RBX011" => "CPI target and forwarded signer privileges",
            "RBX005" | "RBX017" | "RBX022" => {
                "Program-derived account address and signer authority"
            }
            "RBX008" => "Lamport balances and rent reserve",
            "RBX010" | "RBX014" | "RBX015" => "Token mint, account owner, and spending authority",
            "RBX016" => "Trusted sysvar identity",
            "RBX018" => "Distinct writable accounts and state updates",
            "RBX020" => "Initialization state and privileged authority",
            "RBX021" => "Closed account data and lamport balances",
            "RBX009" | "RBX012" => "Amounts, limits, and accounting values",
            "RBX007" => "Time-gated protocol actions",
            _ => "Instruction execution and account state",
        }
        .into(),
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
        references: match metadata.id {
            "RBX003" | "RBX011" => vec!["https://solana.com/docs/core/cpi"],
            "RBX010" | "RBX014" | "RBX015" => {
                vec!["https://www.anchor-lang.com/docs/tokens/basics/create-token-account"]
            }
            "RBX005" | "RBX017" | "RBX022" => vec![
                "https://www.anchor-lang.com/docs/references/account-constraints",
                "https://solana.com/docs/core/pda",
            ],
            "RBX001" | "RBX002" | "RBX013" | "RBX016" | "RBX018" | "RBX019" | "RBX020"
            | "RBX021" => {
                vec!["https://www.anchor-lang.com/docs/references/account-constraints"]
            }
            _ => Vec::new(),
        }
        .into_iter()
        .map(str::to_owned)
        .collect(),
    }
}

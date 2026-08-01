use anchor_lang::prelude::*;
use solana_program::program::invoke;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod sentinel_vault {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance.checked_sub(amount).unwrap();

        // Deliberately vulnerable fixture: the scanner should flag this raw CPI.
        let target = &ctx.remaining_accounts[0];
        invoke(&build_instruction(target.key()), ctx.remaining_accounts)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, seeds = [b"vault", authority.key.as_ref()])]
    pub vault: Account<'info, Vault>,
    pub authority: AccountInfo<'info>,
    pub external_state: UncheckedAccount<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

fn build_instruction(_key: Pubkey) -> solana_program::instruction::Instruction { unimplemented!() }


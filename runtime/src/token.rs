use super::Aura;
use codec::{Codec, Decode, Encode};
use primitives::{
    sr25519::{Public as SRPublic, Signature as SRSignature},
    H256, H512,
};
use rstd::collections::btree_set::BTreeSet;
use rstd::convert::From;
use runtime_io::sr25519_verify;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sr_primitives::{
    traits::{
        BlakeTwo256, CheckedAdd, CheckedSub, Hash, Member, One, SaturatedConversion,
        SimpleArithmetic,
    },
    RuntimeDebug,
};
use support::{
    decl_event, decl_module, decl_storage,
    dispatch::{Result, Vec},
    ensure, Parameter,
};
use system::{ensure_none, ensure_signed};

pub trait Trait: system::Trait {
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    type TokenBalance: Member + Parameter + SimpleArithmetic + Default + Copy;
    type TokenId: Parameter + SimpleArithmetic + Default + Copy;
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, RuntimeDebug, Encode, Decode, Hash)]
pub struct Erc20Token<U> {
    name: Vec<u8>,
    ticker: Vec<u8>,
    total_supply: U,
}

decl_storage! {
    trait Store for Module<T: Trait> as Erc20 {
        TokenId get(token_id): T::TokenId;

        Tokens get(token_details): map T::TokenId => Erc20Token<T::TokenBalance>;

        BalanceOf get(balance_of): map (T::TokenId, T::AccountId) => T::TokenBalance;

        Allowance get(allowance): map (T::TokenId, T::AccountId, T::AccountId) => T::TokenBalance;
    }

    add_extra_genesis {
        config(tokens): Vec<T::TokenId>;
        config(initial_balance): T::TokenBalance;
        config(accounts): Vec<T::AccountId>;

        build(|config: &GenesisConfig<T>| {
            config.tokens.iter().for_each(|token_id| {
                config.accounts.iter().for_each(|account_id| {
                    <BalanceOf<T>>::insert((token_id, account_id), &config.initial_balance);
                });
            });
        });
    }
}

decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as system::Trait>::AccountId,
        Balance = <T as self::Trait>::TokenBalance,
        TokenId = <T as self::Trait>::TokenId,
    {
        Transfer(TokenId, AccountId, AccountId, Balance),
        Approval(TokenId, AccountId, AccountId, Balance),
    }
);

impl<T: Trait> Module<T> {
    // internal
    fn _transfer(
        token_id: T::TokenId,
        from: T::AccountId,
        to: T::AccountId,
        value: T::TokenBalance,
    ) -> Result {
        ensure!(
            <BalanceOf<T>>::exists((token_id, from.clone())),
            "Account does not own this token"
        );
        let sender_balance = Self::balance_of((token_id, from.clone()));
        ensure!(sender_balance >= value, "Not enough balance.");

        let updated_from_balance = sender_balance
            .checked_sub(&value)
            .ok_or("overflow in calculating balance")?;

        let receiver_balance = Self::balance_of((token_id, to.clone()));
        let updated_to_balance = receiver_balance
            .checked_add(&value)
            .ok_or("overflow in calculating balance")?;

        // reduce sender's balance
        <BalanceOf<T>>::insert((token_id, from.clone()), updated_from_balance);

        // increase receiver's balance
        <BalanceOf<T>>::insert((token_id, to.clone()), updated_to_balance);

        Self::deposit_event(RawEvent::Transfer(token_id, from, to, value));
        Ok(())
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        fn init(origin, name: Vec<u8>, ticker: Vec<u8>, total_supply: T::TokenBalance) -> Result {
            let sender = ensure_signed(origin)?;

            // checking max size for name and ticker
            // byte arrays (vecs) with no max size should be avoided
            ensure!(name.len() <= 64, "token name cannot exceed 64 bytes");
            ensure!(ticker.len() <= 32, "token ticker cannot exceed 32 bytes");

            let token_id = Self::token_id();
            let next_token_id = token_id.checked_add(&One::one()).ok_or("overflow in calculating next token id")?;
            <TokenId<T>>::put(next_token_id);

            let token = Erc20Token {
                name,
                ticker,
                total_supply,
            };

            <Tokens<T>>::insert(token_id, token);
            <BalanceOf<T>>::insert((token_id, sender), total_supply);

            Ok(())
        }

        fn transfer(_origin, token_id: T::TokenId, to: T::AccountId, value: T::TokenBalance) -> Result {
            let sender = ensure_signed(_origin)?;
            Self::_transfer(token_id, sender, to, value)
        }

        fn approve(_origin, token_id: T::TokenId, spender: T::AccountId, value: T::TokenBalance) -> Result {
            let sender = ensure_signed(_origin)?;
            ensure!(<BalanceOf<T>>::exists((token_id, sender.clone())), "Account does not own this token");

            let allowance = Self::allowance((token_id, sender.clone(), spender.clone()));
            let updated_allowance = allowance.checked_add(&value).ok_or("overflow in calculating allowance")?;
            <Allowance<T>>::insert((token_id, sender.clone(), spender.clone()), updated_allowance);

            Self::deposit_event(RawEvent::Approval(token_id, sender.clone(), spender.clone(), value));

            Ok(())
        }


        pub fn transfer_from(_origin, token_id: T::TokenId, from: T::AccountId, to: T::AccountId, value: T::TokenBalance) -> Result {
            ensure!(<Allowance<T>>::exists((token_id, from.clone(), to.clone())), "Allowance does not exist.");
            let allowance = Self::allowance((token_id, from.clone(), to.clone()));
            ensure!(allowance >= value, "Not enough allowance.");

            // using checked_sub (safe math) to avoid overflow
            let updated_allowance = allowance.checked_sub(&value).ok_or("overflow in calculating allowance")?;
            <Allowance<T>>::insert((token_id, from.clone(), to.clone()), updated_allowance);

            Self::deposit_event(RawEvent::Approval(token_id, from.clone(), to.clone(), value));
            Self::_transfer(token_id, from, to, value)
        }
    }
}

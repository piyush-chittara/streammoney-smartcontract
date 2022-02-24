use std::convert::TryInto;
use std::str::FromStr;

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    native_token::lamports_to_sol,
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
    system_instruction,
    sysvar::{clock::Clock, fees::Fees, rent::Rent, Sysvar},
};

pub struct StreamMoney{
    /// Timestamp when the funds start unlocking
    pub start_time: u64,
    /// Timestamp when all funds should be unlocked
    pub end_time: u64,
    /// Amount of funds locked
    pub amount: u64,
    /// Amount of funds withdrawn
    pub withdrawn: u64,
    /// Pubkey of the program initializer
    pub sender: [u8; 32],
    /// Pubkey of the funds' recipient
    pub recipient: [u8; 32],
    /// Number of total event triggers
    pub total_events: u32,
    /// Number of events triggered
    pub triggered_events: u32,
    /// Timestamp to count withdraw amount
    pub stream_resume_time: u64,
    /// Amount of funds unlocked
    pub unlocked_amount: u64,
    /// State of stream
    pub state: u8,

}


/// Deserialize instruction_data into StreamMoney struct.
/// This is used to read instructions given to us by the program's initializer.
pub fn deserialize_init_instruction(data: &[u8], sender: &Pubkey, receiver: &Pubkey) -> StreamMoney {
    StreamMoney{
        sender: sender.to_bytes(),
        recipient: receiver.to_bytes(),
        start_time: u64::from(u32::from_le_bytes(data[1..5].try_into().unwrap())),
        end_time: u64::from(u32::from_le_bytes(data[5..9].try_into().unwrap())),
        amount: u64::from_le_bytes(data[9..17].try_into().unwrap()),
        total_events: u32::from_le_bytes(data[17..21].try_into().unwrap()),
        triggered_events: u32::from_le_bytes(data[21..25].try_into().unwrap()),
        withdrawn: 0,
        stream_resume_time: u64::from(u32::from_le_bytes(data[25..29].try_into().unwrap())),
        unlocked_amount: 0,
        state: 1,
    }
}

/// Deserialize account data into StreamMoney struct
/// This is used for reading the metadata from the account holding the locked funds.
pub fn deserialize_account_data(data: &[u8]) -> StreamMoney {
    StreamMoney {
        start_time: u64::from_le_bytes(data[0..8].try_into().unwrap()),
        end_time: u64::from_le_bytes(data[8..16].try_into().unwrap()),
        amount: u64::from_le_bytes(data[16..24].try_into().unwrap()),
        withdrawn: u64::from_le_bytes(data[24..32].try_into().unwrap()),
        sender: data[32..64].try_into().unwrap(),
        recipient: data[64..96].try_into().unwrap(),
        total_events: u32::from_le_bytes(data[96..100].try_into().unwrap()),
        triggered_events: u32::from_le_bytes(data[100..104].try_into().unwrap()),
        stream_resume_time: u64::from_le_bytes(data[104..108].try_into().unwrap()),
        unlocked_amount: u64::from_le_bytes(data[108..112].try_into().unwrap()),
        state: data[112],
    }
}


fn calculate_streamed_time(now: u64, start: u64, resume: u64, end: u64, amount: u64) -> u64 {
    // This is valid float division, but we lose precision when going u64.
    // The loss however should not matter, as in the end we will simply
    // send everything that is remaining.
    (((now - resume) as f64) / ((end - start) as f64) * amount as f64) as u64
}

fn calculate_streamed_events(total_events: u32, triggered_events: u32, amount: u64) -> u64 {
    // This is valid float division, but we lose precision when going u64.
    // The loss however should not matter, as in the end we will simply
    // send everything that is remaining.
    ((triggered_events as f64) / (total_events as f64) * amount as f64) as u64
}

fn initialize_stream(pid: &Pubkey, accounts: &[AccountInfo], ix: &[u8]) -> ProgramResult {
    msg!("starting stream initialization");
    let account_info_iter = &mut accounts.iter();
    let sender = next_account_info(account_info_iter)?;
    let receiver = next_account_info(account_info_iter)?;
    let pda = next_account_info(account_info_iter)?;
    let system_program = next_account_info(account_info_iter)?;

    if ix.len() != 25 {
        return Err(ProgramError::InvalidInstructionData);
    }

    if !pda.data_is_empty() {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    if !sender.is_writable || !receiver.is_writable || !pda.is_writable || !sender.is_signer ||
        !pda.is_signer{
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut stream_money = deserialize_init_instruction(ix, sender.key, receiver.key);
    let struct_size = std::mem::size_of::<StreamMoney>();

    // We also transfer enough to be rent-exempt (about 0.00156 SOL) to the
    // new account. After all funds are withdrawn and unlocked, this might
    // be returned to the initializer or put in another pool for future reuse.
    let cluster_rent = Rent::get()?;
    if sender.lamports() < stream_money.amount + cluster_rent.minimum_balance(struct_size) {
        msg!("Not enough funds in sender's account to initialize stream");
        return Err(ProgramError::InsufficientFunds);
    }
    let now = Clock::get()?.unix_timestamp as u64;
    if stream_money.start_time < now || stream_money.start_time >= stream_money.end_time {
        msg!("Timestamps are invalid!");
        msg!("Solana cluster time: {}", now);
        msg!("Stream start time:   {}", stream_money.start_time);
        msg!("Stream end time:     {}", stream_money.end_time);
        msg!("Stream duration:     {}", stream_money.end_time - stream_money.start_time);
        return Err(ProgramError::InvalidArgument);
    }

    // Create the account holding locked funds and data
    invoke(
        &system_instruction::create_account(
            &sender.key,
            &pda.key,
            stream_money.amount + cluster_rent.minimum_balance(struct_size),
            struct_size as u64,
            &pid,
        ),
        &[sender.clone(), pda.clone(), system_program.clone()],
    )?;

    // Send enough for one transaction to receiver, so receiver can do an initial
    // withdraw without having previous funds on their account.
    let fees = Fees::get()?;
    **pda.try_borrow_mut_lamports()? -= fees.fee_calculator.lamports_per_signature * 2;
    **receiver.try_borrow_mut_lamports()? += fees.fee_calculator.lamports_per_signature * 2;
    stream_money.withdrawn += fees.fee_calculator.lamports_per_signature * 2;

    // Write our metadata to pda's data.
    let mut data = pda.try_borrow_mut_data()?;
    let bytes: &[u8] = unsafe { any_as_u8_slice(&stream_money) };
    data[0..bytes.len()].clone_from_slice(bytes);

    msg!(
        "Successfully initialized {} SOL ({} lamports) stream for: {}",
        lamports_to_sol(stream_money.amount),
        stream_money.amount,
        receiver.key
    );
    msg!("Called by account: {}", sender.key);
    msg!("Funds locked in account: {}", pda.key);
    msg!("Stream duration: {} seconds", stream_money.end_time - stream_money.start_time);
    Ok(())
}

fn trigger_event(pid: &Pubkey, accounts: &[AccountInfo], _ix: &[u8]) -> ProgramResult{
    msg!("Event triggered");
    let account_info_iter = &mut accounts.iter();
    let sender = next_account_info(account_info_iter)?;
    let receiver = next_account_info(account_info_iter)?;
    let pda = next_account_info(account_info_iter)?;

    if !sender.is_signer || !sender.is_writable || !receiver.is_writable || !receiver.is_writable {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if pda.data_is_empty() || pda.owner != pid {
        return Err(ProgramError::UninitializedAccount);
    }

    let mut data = pda.try_borrow_mut_data()?;
    let mut stream_money = deserialize_account_data(&data);

    if sender.key.to_bytes() != stream_money.sender {
        msg!("Unauthorized to trigger event for {}", sender.key);
        return Err(ProgramError::MissingRequiredSignature);
    }
    if stream_money.triggered_events>=stream_money.total_events {
        msg!("All events are already triggered");
        return Err(ProgramError::InvalidArgument);
    }
    stream_money.triggered_events+=1;
    let bytes: &[u8] = unsafe { any_as_u8_slice(&stream_money) };
    data[0..bytes.len()].clone_from_slice(bytes);
    Ok(())
}

fn withdraw_unlocked(pid: &Pubkey, accounts: &[AccountInfo], ix: &[u8]) -> ProgramResult {
    msg!("Requested withdraw of unlocked funds");
    let account_info_iter = &mut accounts.iter();
    let receiver = next_account_info(account_info_iter)?;
    let pda = next_account_info(account_info_iter)?;
    let lld = next_account_info(account_info_iter)?;

    if ix.len() != 9 {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Hardcoded rent collector
    let rent_reaper = Pubkey::from_str("DrFtxPb9F6SxpHHHFiEtSNXE3SZCUNLXMaHS6r8pkoz2").unwrap();
    if lld.key != &rent_reaper {
        msg!("Got unexpected rent collection account");
        return Err(ProgramError::InvalidAccountData);
    }

    if !receiver.is_signer || !receiver.is_writable || !pda.is_writable || !lld.is_writable {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if pda.data_is_empty() || pda.owner != pid {
        return Err(ProgramError::UninitializedAccount);
    }

    let mut data = pda.try_borrow_mut_data()?;
    let mut stream_money = deserialize_account_data(&data);

    if receiver.key.to_bytes() != stream_money.recipient {
        msg!("This stream isn't indented for {}", receiver.key);
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Current cluster time used to calculate unlocked amount.
    let now = Clock::get()?.unix_timestamp as u64;

    let amount_unlocked;
    ///check if stream is time based or event based
    if stream_money.total_events == 0{
        /// check if stream is playing
        if stream_money.state ==1{
            amount_unlocked = stream_money.unlocked_amount +
                calculate_streamed_time(now, stream_money.start_time, stream_money.stream_resume_time, stream_money.end_time, stream_money.amount);
        } else {
            amount_unlocked = stream_money.unlocked_amount;
        }
        stream_money.unlocked_amount=0;
    } else{
        amount_unlocked = calculate_streamed_events(stream_money.total_events, stream_money.triggered_events, stream_money.amount);
    }
    let mut available = amount_unlocked - stream_money.withdrawn;

    // In case we're past the set time, everything is available.
    if now >= stream_money.end_time {
        available = stream_money.amount - stream_money.withdrawn;
    }

    let mut requested = u64::from_le_bytes(ix[1..9].try_into().unwrap());
    if requested == 0 {
        requested = available;
    }

    if requested > available {
        msg!("Amount requested for withdraw is larger than what is available.");
        msg!(
            "Requested: {} SOL ({} lamports)",
            lamports_to_sol(requested),
            requested
        );
        msg!(
            "Available: {} SOL ({} lamports)",
            lamports_to_sol(available),
            available
        );
        return Err(ProgramError::InvalidArgument);
    }

    **pda.try_borrow_mut_lamports()? -= requested;
    **receiver.try_borrow_mut_lamports()? += requested;

    // Update account data
    stream_money.withdrawn += available as u64;
    let bytes: &[u8] = unsafe { any_as_u8_slice(&stream_money) };
    data[0..bytes.len()].clone_from_slice(bytes);

    msg!(
        "Successfully withdrawn: {} SOL ({} lamports)",
        lamports_to_sol(available),
        available
    );
    msg!(
        "Remaining: {} SOL ({} lamports)",
        lamports_to_sol(stream_money.amount - stream_money.withdrawn),
        stream_money.amount - stream_money.withdrawn
    );

    /*
    if sf.withdrawn == sf.amount {
        // Collect rent after stream is finished.
        let rent = pda.lamports();
        **pda.try_borrow_mut_lamports()? -= rent;
        **lld.try_borrow_mut_lamports()? += rent;
    }
    */

    Ok(())
}

fn edit_time_amount_events(pid: &Pubkey, accounts: &[AccountInfo], _ix: &[u8]) -> ProgramResult {
    msg!("Requested stream edit");

    let account_info_iter = &mut accounts.iter();
    let receiver = next_account_info(account_info_iter)?;
    let pda = next_account_info(account_info_iter)?;
    let lld = next_account_info(account_info_iter)?;
    let sender = next_account_info(account_info_iter)?;

    if !sender.is_signer || !sender.is_writable ||  !receiver.is_signer || !receiver.is_writable || !pda.is_writable || !lld.is_writable {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut data = pda.try_borrow_mut_data()?;
    let mut stream_money = deserialize_account_data(&data);
    let now = Clock::get()?.unix_timestamp as u64;
    ///check if edits are doable
    if stream_money.end_time<=now || stream_money.total_events<=stream_money.triggered_events{
        return Err(ProgramError::InvalidArgument);
    }

    if let Err(_err) = withdraw_unlocked(pid,accounts,_ix) {
        return Err(ProgramError::Custom(500));
    }
    if pda.data_is_empty() || pda.owner != pid {
        return Err(ProgramError::UninitializedAccount);
    }
    stream_money.amount=u64::from_le_bytes(_ix[9..17].try_into().unwrap());
    stream_money.end_time=u64::from_le_bytes(_ix[17..25].try_into().unwrap());
    stream_money.total_events=u32::from_le_bytes(_ix[25..33].try_into().unwrap());
    let bytes: &[u8] = unsafe { any_as_u8_slice(&stream_money) };
    data[0..bytes.len()].clone_from_slice(bytes);
    Ok(())
}

fn pause_or_resume(pid: &Pubkey, accounts: &[AccountInfo], _ix: &[u8]) -> ProgramResult {
    msg!("Requested stream pause or resume");

    let account_info_iter = &mut accounts.iter();
    let sender = next_account_info(account_info_iter)?;
    let pda = next_account_info(account_info_iter)?;

    if !sender.is_signer || !sender.is_writable {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let now = Clock::get()?.unix_timestamp as u64;
    let mut data = pda.try_borrow_mut_data()?;
    let mut stream_money = deserialize_account_data(&data);

    if stream_money.state==1{
        stream_money.unlocked_amount = calculate_streamed_time(now, stream_money.start_time, stream_money.stream_resume_time, stream_money.end_time, stream_money.amount);
        stream_money.state=0;
    } else{
        stream_money.state=1;
        stream_money.stream_resume_time=now;
    }
    let bytes: &[u8] = unsafe { any_as_u8_slice(&stream_money) };
    data[0..bytes.len()].clone_from_slice(bytes);
    Ok(())
}

fn cancel_stream(pid: &Pubkey, accounts: &[AccountInfo], _ix: &[u8]) -> ProgramResult {
    msg!("Requested stream cancellation");
    let account_info_iter = &mut accounts.iter();
    let sender = next_account_info(account_info_iter)?;
    let receiver = next_account_info(account_info_iter)?;
    let pda = next_account_info(account_info_iter)?;

    if !sender.is_signer || !sender.is_writable || !receiver.is_writable || !pda.is_writable {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if pda.data_is_empty() || pda.owner != pid {
        return Err(ProgramError::UninitializedAccount);
    }

    let data = pda.try_borrow_data()?;
    let stream_money = deserialize_account_data(&data);

    if sender.key.to_bytes() != stream_money.sender {
        msg!("Unauthorized to withdraw for {}", sender.key);
        return Err(ProgramError::MissingRequiredSignature);
    }

    if receiver.key.to_bytes() != stream_money.recipient {
        msg!("This stream isn't intended for {}", receiver.key);
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Current cluster time used to calculate unlocked amount.
    let now = Clock::get()?.unix_timestamp as u64;

    // Transfer what was unlocked but not withdrawn to receiver.
    let amount_unlocked;
    if stream_money.total_events == 0{
        if stream_money.state ==1{
            amount_unlocked = stream_money.unlocked_amount +
                calculate_streamed_time(now, stream_money.start_time, stream_money.stream_resume_time, stream_money.end_time, stream_money.amount);

        } else {
            amount_unlocked = stream_money.unlocked_amount;
        }
    } else{
        amount_unlocked = calculate_streamed_events(stream_money.total_events, stream_money.triggered_events, stream_money.amount);
    }

    let available = amount_unlocked - stream_money.withdrawn;
    **pda.try_borrow_mut_lamports()? -= available;
    **receiver.try_borrow_mut_lamports()? += available;

    // sender decides to cancel, and withdraws from the derived account,
    // resulting in its purge.
    let remains = pda.lamports();
    **pda.try_borrow_mut_lamports()? -= remains;
    **sender.try_borrow_mut_lamports()? += remains;

    msg!("Successfully cancelled stream on {} ", pda.key);
    msg!(
        "Transferred unlocked {} SOL ({} lamports to {}",
        lamports_to_sol(available),
        available,
        receiver.key
    );
    msg!(
        "Returned {} SOL ({} lamports) to {}",
        lamports_to_sol(remains),
        remains,
        sender.key
    );

    Ok(())
}

/// Serialize any to u8 slice.
/// # Safety
pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
}

entrypoint!(process_instruction);
/// The program entrypoint
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!(
        "StreamMoney v{}.{}.{}",
        env!("CARGO_PKG_VERSION_MAJOR"),
        env!("CARGO_PKG_VERSION_MINOR"),
        env!("CARGO_PKG_VERSION_PATCH")
    );

    match instruction_data[0] {
        0 => initialize_stream(program_id, accounts, instruction_data),
        1 => withdraw_unlocked(program_id, accounts, instruction_data),
        2 => cancel_stream(program_id, accounts, instruction_data),
        3 => trigger_event(program_id, accounts, instruction_data),
        4 => edit_time_amount_events(program_id, accounts, instruction_data),
        5 => pause_or_resume(program_id, accounts, instruction_data),
        _ => Err(ProgramError::InvalidArgument),
    }
}

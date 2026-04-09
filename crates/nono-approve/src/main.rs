//! nono-approve: native macOS biometric/password approval dialog.
//!
//! Usage: nono-approve <command> [arg1 arg2 ...]
//!
//! Exits 0 if the user authenticates successfully (allow).
//! Exits 1 if the user denies, cancels, or an error occurs (deny).
//!
//! This binary is invoked by the nono mediation server when a command with
//! `admin: true` is intercepted. It presents a native macOS TouchID/password
//! dialog via LocalAuthentication and reports the outcome via exit code.

#[cfg(target_os = "macos")]
mod macos {
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::sync::{Arc, Condvar, Mutex};

    pub fn run(command: &str, args: &[String]) -> bool {
        // Build a human-readable reason string for the dialog.
        let invocation = if args.is_empty() {
            command.to_string()
        } else {
            format!("{} {}", command, args.join(" "))
        };
        let reason = format!("nono: approve '{}'", invocation);

        // Create LAContext and check policy availability.
        // SAFETY: LAContext is a valid ObjC class; new() calls alloc+init.
        let context = unsafe { LAContext::new() };
        let policy = LAPolicy::DeviceOwnerAuthentication;

        // canEvaluatePolicy_error returns Result<(), Retained<NSError>>.
        // SAFETY: valid selector on LAContext.
        let available = unsafe { context.canEvaluatePolicy_error(policy) };
        if available.is_err() {
            eprintln!("nono-approve: authentication not available on this device");
            return false;
        }

        // Use Mutex + Condvar to block the main thread until the async
        // completion handler signals the result.
        let result: Arc<(Mutex<Option<bool>>, Condvar)> =
            Arc::new((Mutex::new(None), Condvar::new()));
        let result_clone = Arc::clone(&result);

        let reason_ns = NSString::from_str(&reason);

        // Build the completion block. The block captures `result_clone` and
        // signals the condvar when authentication completes.
        //
        // The reply signature matches `&block2::Block<dyn Fn(Bool, *mut NSError)>`
        // as required by evaluatePolicy_localizedReason_reply.
        let reply = RcBlock::new(move |success: Bool, _error: *mut NSError| {
            let (lock, cvar) = &*result_clone;
            if let Ok(mut guard) = lock.lock() {
                *guard = Some(success.as_bool());
                cvar.notify_one();
            }
        });

        // SAFETY: valid selector; reason_ns and reply outlive the call.
        unsafe {
            context.evaluatePolicy_localizedReason_reply(policy, &reason_ns, &reply);
        }

        // Block until the completion handler fires.
        let (lock, cvar) = &*result;
        if let Ok(mut guard) = lock.lock() {
            loop {
                if let Some(approved) = *guard {
                    return approved;
                }
                match cvar.wait(guard) {
                    Ok(g) => guard = g,
                    Err(_) => return false,
                }
            }
        }
        false
    }
}

fn main() {
    let mut args_iter = std::env::args().skip(1);
    let command = match args_iter.next() {
        Some(c) => c,
        None => {
            eprintln!("nono-approve: usage: nono-approve <command> [args...]");
            std::process::exit(2);
        }
    };
    let args: Vec<String> = args_iter.collect();

    #[cfg(target_os = "macos")]
    {
        if macos::run(&command, &args) {
            std::process::exit(0);
        } else {
            std::process::exit(1);
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (command, args);
        eprintln!("nono-approve: only supported on macOS");
        std::process::exit(1);
    }
}

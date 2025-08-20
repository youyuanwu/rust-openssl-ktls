use std::ffi::CString;

/// Custom async engine implementation for OpenSSL
///
/// This engine demonstrates how to create a custom async engine that can:
/// 1. Register async capabilities
/// 2. Handle RSA operations asynchronously
/// 3. Integrate with OpenSSL's async job system
//
// Engine constants
const ENGINE_ID: &str = "rust_async";
const ENGINE_NAME: &str = "Rust Async Engine";

// Engine callback functions
extern "C" fn engine_init(_engine: *mut crate::exp::ffi::ENGINE) -> std::os::raw::c_int {
    println!("🔧 Initializing Rust async engine");
    1 // Success
}

extern "C" fn engine_finish(_engine: *mut crate::exp::ffi::ENGINE) -> std::os::raw::c_int {
    println!("🏁 Finishing Rust async engine");
    1 // Success
}

extern "C" fn engine_destroy(_engine: *mut crate::exp::ffi::ENGINE) -> std::os::raw::c_int {
    println!("💥 Destroying Rust async engine");
    1 // Success
}

// Async RSA operations - let's override multiple operations to see which are used

extern "C" fn async_rsa_pub_enc(
    flen: std::os::raw::c_int,
    from: *const std::os::raw::c_uchar,
    to: *mut std::os::raw::c_uchar,
    rsa: *mut crate::exp::ffi::RSA,
    padding: std::os::raw::c_int,
) -> std::os::raw::c_int {
    println!("🔧 Async RSA PUBLIC ENCRYPT called with flen={flen}");

    unsafe {
        // Check if we have an active async job
        let job = crate::exp::ffi::ASYNC_get_current_job();
        if job.is_null() {
            println!("⚠️  No async job context - falling back to sync operation");
            // Fall back to default RSA implementation
            return crate::exp::ffi::RSA_meth_get_pub_enc(crate::exp::ffi::RSA_PKCS1_OpenSSL())
                .map(|f| f(flen, from, to, rsa, padding))
                .unwrap_or(-1);
        }

        println!("🚀 Starting async RSA PUBLIC ENCRYPT operation with job: {job:p}");

        // For this demo, let's simulate an operation that takes multiple calls
        static mut CALL_COUNT: u32 = 0;
        let count = {
            CALL_COUNT += 1;
            CALL_COUNT
        };

        println!("📞 Async RSA PUBLIC ENCRYPT call #{count}");

        if count < 2 {
            // Reduce to just 1 pause, complete on 2nd call
            // First call - simulate work in progress
            println!("⏸️  PUBLIC ENCRYPT operation in progress - pausing job (call #{count})");
            // Return ASYNC_PAUSE to indicate we need to be called again
            return crate::exp::ffi::ASYNC_PAUSE;
        }

        // Second call - operation is "complete", do the actual work
        println!(
            "✅ PUBLIC ENCRYPT operation ready - performing actual RSA encryption (call #{count})"
        );
        CALL_COUNT = 0; // Reset for next operation

        // Do the actual RSA operation
        let result = crate::exp::ffi::RSA_meth_get_pub_enc(crate::exp::ffi::RSA_PKCS1_OpenSSL())
            .map(|f| f(flen, from, to, rsa, padding))
            .unwrap_or(-1);

        println!("🎉 Async RSA PUBLIC ENCRYPT operation completed with result: {result}");
        result
    }
}

// Simplified async RSA private encrypt demonstrating the pause mechanism
extern "C" fn async_rsa_priv_enc(
    flen: std::os::raw::c_int,
    from: *const std::os::raw::c_uchar,
    to: *mut std::os::raw::c_uchar,
    rsa: *mut crate::exp::ffi::RSA,
    padding: std::os::raw::c_int,
) -> std::os::raw::c_int {
    println!("🔧 Async RSA PRIVATE ENCRYPT (signing) called with flen={flen}");

    unsafe {
        // Inside your ENGINE's RSA method - check if we have an async job
        let job = crate::exp::ffi::ASYNC_get_current_job();
        if !job.is_null() {
            println!("🚀 Found async job context: {job:p}");

            // Only demonstrate async behavior for SSL handshake operations (larger flen)
            if flen > 100 {
                // Get the wait context from the current job
                let wait_ctx = crate::exp::ffi::ASYNC_get_wait_ctx(job);
                if !wait_ctx.is_null() {
                    println!("✅ Got wait context: {wait_ctx:p}");

                    static mut CALL_COUNT: u32 = 0;
                    CALL_COUNT += 1;

                    if CALL_COUNT == 1 {
                        // First call - demonstrate the pause mechanism
                        println!("🔄 First call - pausing job to demonstrate async mechanism");

                        // Create a job identifier
                        let _job_id = CString::new("rsa_async_job").unwrap();

                        // Cast wait_ctx to raw pointer to pass to another thread
                        let wait_ctx_raw = wait_ctx as usize;

                        println!("🚀 Starting background thread to signal completion");
                        std::thread::spawn(move || {
                            // Simulate some async work
                            std::thread::sleep(std::time::Duration::from_millis(10));

                            println!(
                                "✅ Background work completed, getting wait context callback..."
                            );

                            // Cast back to wait_ctx pointer
                            let wait_ctx = wait_ctx_raw as *mut crate::exp::ffi::ASYNC_WAIT_CTX;

                            // Get the callback and callback argument from the wait context
                            let mut callback: Option<extern "C" fn(*mut std::ffi::c_void)> = None;
                            let mut callback_arg: *mut std::ffi::c_void = std::ptr::null_mut();

                            let get_callback_result = crate::exp::ffi::ASYNC_WAIT_CTX_get_callback(
                                wait_ctx,
                                &mut callback,
                                &mut callback_arg,
                            );

                            if get_callback_result == 1 && callback.is_some() {
                                println!(
                                    "✅ Got callback from wait context, invoking to notify ready..."
                                );

                                // First set the status
                                let job_id = CString::new("rsa_async_job").unwrap();
                                let status_result = crate::exp::ffi::ASYNC_WAIT_CTX_set_status(
                                    wait_ctx,
                                    job_id.as_ptr(),
                                    crate::exp::ffi::ASYNC_STATUS_OK,
                                );
                                println!("🔔 ASYNC_WAIT_CTX_set_status returned: {status_result}");

                                // Now invoke the callback to notify that async operation is ready
                                println!(
                                    "📞 Invoking wait context callback to notify async operation ready"
                                );
                                callback.unwrap()(callback_arg);
                                println!(
                                    "✅ Callback invoked - async operation should be resumed!"
                                );
                            } else {
                                println!(
                                    "❌ Failed to get callback from wait context (result={get_callback_result})"
                                );

                                // Fallback to just setting status
                                let job_id = CString::new("rsa_async_job").unwrap();
                                let status_result = crate::exp::ffi::ASYNC_WAIT_CTX_set_status(
                                    wait_ctx,
                                    job_id.as_ptr(),
                                    crate::exp::ffi::ASYNC_STATUS_OK,
                                );
                                println!(
                                    "🔔 ASYNC_WAIT_CTX_set_status fallback returned: {status_result}"
                                );
                            }
                        });

                        // Pause the job - this suspends and returns control
                        println!("⏸️  Calling ASYNC_pause_job...");
                        let pause_result = crate::exp::ffi::ASYNC_pause_job();
                        println!(
                            "✅ ASYNC_pause_job returned: {pause_result} - job has been resumed, continuing with crypto operation"
                        );

                        // Reset for next call
                        CALL_COUNT = 0;

                        // After ASYNC_pause_job returns, we've been resumed by the callback
                        // Now we can perform the actual crypto operation
                        println!("🔄 Job resumed - now performing the actual RSA crypto operation");
                    }
                }
            }
        }

        // Perform the actual RSA operation
        println!("🔄 Performing RSA operation");
        let result = crate::exp::ffi::RSA_meth_get_priv_enc(crate::exp::ffi::RSA_PKCS1_OpenSSL())
            .map(|f| f(flen, from, to, rsa, padding))
            .unwrap_or(-1);

        println!("✅ RSA operation completed with result: {result}");
        result
    }
}

extern "C" fn async_rsa_priv_dec(
    flen: std::os::raw::c_int,
    from: *const std::os::raw::c_uchar,
    to: *mut std::os::raw::c_uchar,
    rsa: *mut crate::exp::ffi::RSA,
    padding: std::os::raw::c_int,
) -> std::os::raw::c_int {
    println!("🔧 Async RSA PRIVATE DECRYPT (key exchange) called with flen={flen}");

    unsafe {
        // Check if we have an active async job
        let job = crate::exp::ffi::ASYNC_get_current_job();
        if job.is_null() {
            println!("⚠️  No async job context - falling back to sync operation");
            // Fall back to default RSA implementation
            return crate::exp::ffi::RSA_meth_get_priv_dec(crate::exp::ffi::RSA_PKCS1_OpenSSL())
                .map(|f| f(flen, from, to, rsa, padding))
                .unwrap_or(-1);
        }

        println!("🚀 Starting async RSA PRIVATE DECRYPT operation with job: {job:p}");

        // For this demo, let's simulate an operation that takes multiple calls
        static mut CALL_COUNT: u32 = 0;
        let count = {
            CALL_COUNT += 1;
            CALL_COUNT
        };

        println!("📞 Async RSA PRIVATE DECRYPT call #{count}");

        if count < 2 {
            // Reduce to just 1 pause, complete on 2nd call
            // First call - simulate work in progress
            println!("⏸️  PRIVATE DECRYPT operation in progress - pausing job (call #{count})");
            // Return ASYNC_PAUSE to indicate we need to be called again
            return crate::exp::ffi::ASYNC_PAUSE;
        }

        // Second call - operation is "complete", do the actual work
        println!(
            "✅ PRIVATE DECRYPT operation ready - performing actual RSA decryption (call #{count})"
        );
        CALL_COUNT = 0; // Reset for next operation

        // Do the actual RSA operation
        let result = crate::exp::ffi::RSA_meth_get_priv_dec(crate::exp::ffi::RSA_PKCS1_OpenSSL())
            .map(|f| f(flen, from, to, rsa, padding))
            .unwrap_or(-1);

        println!("🎉 Async RSA PRIVATE DECRYPT operation completed with result: {result}");
        result
    }
}

// AsyncEngine structure and implementation
pub struct AsyncEngine {
    engine: *mut crate::exp::ffi::ENGINE,
    // rsa_method: *mut crate::exp::ffi::RSA_METHOD,
}

impl AsyncEngine {
    pub fn new() -> Option<Self> {
        unsafe {
            // Create the engine
            let engine = crate::exp::ffi::ENGINE_new();
            if engine.is_null() {
                println!("❌ Failed to create new engine");
                return None;
            }

            println!("✅ Created new engine: {engine:p}");

            // Set engine identity
            let id = CString::new(ENGINE_ID).ok()?;
            let name = CString::new(ENGINE_NAME).ok()?;

            if crate::exp::ffi::ENGINE_set_id(engine, id.as_ptr()) != 1 {
                println!("❌ Failed to set engine ID");
                crate::exp::ffi::ENGINE_free(engine);
                return None;
            }

            if crate::exp::ffi::ENGINE_set_name(engine, name.as_ptr()) != 1 {
                println!("❌ Failed to set engine name");
                crate::exp::ffi::ENGINE_free(engine);
                return None;
            }

            // Set engine callbacks
            crate::exp::ffi::ENGINE_set_init_function(engine, Some(engine_init));
            crate::exp::ffi::ENGINE_set_finish_function(engine, Some(engine_finish));
            crate::exp::ffi::ENGINE_set_destroy_function(engine, Some(engine_destroy));

            // Create RSA method
            let rsa_method = crate::exp::ffi::RSA_meth_new(name.as_ptr(), 0);
            if rsa_method.is_null() {
                println!("❌ Failed to create RSA method");
                crate::exp::ffi::ENGINE_free(engine);
                return None;
            }

            println!("✅ Created RSA method: {rsa_method:p}");

            // Set our async RSA operations
            if crate::exp::ffi::RSA_meth_set_pub_enc(rsa_method, Some(async_rsa_pub_enc)) != 1 {
                println!("❌ Failed to set RSA public encrypt method");
                crate::exp::ffi::RSA_meth_free(rsa_method);
                crate::exp::ffi::ENGINE_free(engine);
                return None;
            }

            if crate::exp::ffi::RSA_meth_set_priv_enc(rsa_method, Some(async_rsa_priv_enc)) != 1 {
                println!("❌ Failed to set RSA private encrypt method");
                crate::exp::ffi::RSA_meth_free(rsa_method);
                crate::exp::ffi::ENGINE_free(engine);
                return None;
            }

            if crate::exp::ffi::RSA_meth_set_priv_dec(rsa_method, Some(async_rsa_priv_dec)) != 1 {
                println!("❌ Failed to set RSA private decrypt method");
                crate::exp::ffi::RSA_meth_free(rsa_method);
                crate::exp::ffi::ENGINE_free(engine);
                return None;
            }

            // Copy other methods from default RSA implementation
            let default_method = crate::exp::ffi::RSA_PKCS1_OpenSSL();

            // Keep the default public decrypt (not commonly used in SSL)
            if let Some(pub_dec) = crate::exp::ffi::RSA_meth_get_pub_dec(default_method) {
                crate::exp::ffi::RSA_meth_set_pub_dec(rsa_method, Some(pub_dec));
            }

            // Copy additional methods that might be required
            if let Some(mod_exp) = crate::exp::ffi::RSA_meth_get_mod_exp(default_method) {
                crate::exp::ffi::RSA_meth_set_mod_exp(rsa_method, Some(mod_exp));
            }

            if let Some(bn_mod_exp) = crate::exp::ffi::RSA_meth_get_bn_mod_exp(default_method) {
                crate::exp::ffi::RSA_meth_set_bn_mod_exp(rsa_method, Some(bn_mod_exp));
            }

            if let Some(init) = crate::exp::ffi::RSA_meth_get_init(default_method) {
                crate::exp::ffi::RSA_meth_set_init(rsa_method, Some(init));
            }

            if let Some(finish) = crate::exp::ffi::RSA_meth_get_finish(default_method) {
                crate::exp::ffi::RSA_meth_set_finish(rsa_method, Some(finish));
            }

            // Set the RSA method in the engine
            if crate::exp::ffi::ENGINE_set_RSA(engine, rsa_method as *const _) != 1 {
                println!("❌ Failed to set RSA method in engine");
                crate::exp::ffi::RSA_meth_free(rsa_method);
                crate::exp::ffi::ENGINE_free(engine);
                return None;
            }

            println!("✅ Successfully created async engine with RSA method");

            Some(AsyncEngine { engine })
        }
    }

    pub fn register(&self) -> bool {
        unsafe {
            // Add the engine to OpenSSL's internal list
            if crate::exp::ffi::ENGINE_add(self.engine) != 1 {
                println!("❌ Failed to add engine to OpenSSL");
                return false;
            }

            println!("✅ Engine added to OpenSSL registry");

            // Set it as default for RSA operations
            if crate::exp::ffi::ENGINE_set_default_RSA(self.engine) != 1 {
                println!("❌ Failed to set engine as default for RSA");
                return false;
            }

            println!("✅ Engine set as default for RSA operations");
            true
        }
    }

    pub fn engine_ptr(&self) -> *mut crate::exp::ffi::ENGINE {
        self.engine
    }
}

impl Drop for AsyncEngine {
    fn drop(&mut self) {
        // TODO: intentional leak.
        // default engine is set to this so drop will cause dangling ptr.

        // unsafe {
        //     println!("🗑️  Dropping AsyncEngine");
        //     if !self.rsa_method.is_null() {
        //         crate::exp::ffi::RSA_meth_free(self.rsa_method);
        //     }
        //     if !self.engine.is_null() {
        //         crate::exp::ffi::ENGINE_free(self.engine);
        //     }
        // }
    }
}

// Public API for creating and using the async engine
pub fn create_async_engine() -> Option<AsyncEngine> {
    AsyncEngine::new()
}

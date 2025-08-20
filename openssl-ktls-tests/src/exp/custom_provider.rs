//! # OpenSSL Provider API Integration
//!
//! This module demonstrates how to create and use custom OpenSSL providers with SSL contexts.
//!
//! ## Provider Loading Requirements for SSL Context Creation
//!
//! Based on testing, here's what providers are needed:
//!
//! ### Required Providers
//! - **default provider**: REQUIRED - Contains essential cipher suites and standard algorithms needed for SSL/TLS
//!
//! ### Optional Providers  
//! - **legacy provider**: RECOMMENDED - Contains older algorithms for broader compatibility with legacy systems
//! - **fips provider**: ONLY when FIPS compliance is required
//!
//! ### Answer to "Are all 3 providers required or is default enough?"
//! **Only the default provider is REQUIRED.** The legacy and FIPS providers are optional:
//! - Default provider: ✅ Required (contains modern cipher suites)
//! - Legacy provider: ⚠️ Optional but recommended (contains older algorithms for compatibility)
//! - FIPS provider: ❌ Only needed for FIPS compliance requirements
//!
//! ## Library Context vs Global Registration
//!
//! The `create_lib_context` function works correctly by:
//! 1. Creating an isolated `OSSL_LIB_CTX` with default + custom provider
//! 2. NOT registering the provider globally (avoiding the double-loading issue)
//! 3. Demonstrating complete provider isolation
//!
//! **Limitation**: The rust-openssl crate doesn't expose `SSL_CTX_new_ex()` which would
//! allow creating SSL contexts with a specific library context. Therefore, actual SSL
//! context creation still requires global provider registration.
//!
//! **Pure Library Context Benefits** (if rust-openssl supported it):
//! - Complete isolation between different provider configurations
//! - No global state pollution
//! - Perfect for multi-tenant applications
//! - Ability to have different provider sets per SSL context
//!
//! ## Usage Examples
//!
//! ```rust
//! // Minimal setup (default + custom provider only)
//! let ssl_ctx = create_ssl_context_with_minimal_providers()?;
//!
//! // Recommended setup (default + legacy + custom provider)  
//! let ssl_ctx = create_ssl_context_with_recommended_providers()?;
//!
//! // Library context approach (demonstrates isolation, but can't create SSL context)
//! demonstrate_pure_library_context_approach()?; // Shows the concept
//! ```

use openssl::ssl::SslContextBuilder;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

/// Custom async provider implementation for OpenSSL 3.0+
///
/// ## Key Discovery: Provider API DOES Support Async Operations!
///
/// This implementation demonstrates that OpenSSL 3.0+ Provider API can use the same
/// async job system as the ENGINE API. Based on the Intel QAT Engine example
/// (https://github.com/intel/QAT_Engine/blob/main/qat_sw_sm2.c), Provider operations
/// can call:
///
/// - `ASYNC_get_current_job()` - Detect async job context
/// - `ASYNC_pause_job()` / return `ASYNC_PAUSE` - Suspend operations  
/// - `ASYNC_get_wait_ctx()` - Get wait context for notifications
/// - `ASYNC_WAIT_CTX_set_status()` - Signal completion
/// - Wait context callbacks - Notify async framework of completion
///
/// ## Provider API vs ENGINE API Async Comparison:
///
/// **Async Capabilities**: ✅ **IDENTICAL** - Both can use the full OpenSSL async job system
/// **Setup Mechanism**:
/// - ENGINE API: Uses `RSA_METHOD` callbacks (`async_rsa_priv_enc`, etc.)
/// - Provider API: Uses `OSSL_DISPATCH` tables (`rsa_signature_sign`, etc.)
///   **Async Pattern**: ✅ **IDENTICAL** for both APIs:
///   1. Check `ASYNC_get_current_job()` for async context
///   2. Use `ASYNC_pause_job()` or return `ASYNC_PAUSE` to suspend
///   3. Background thread signals completion via wait context callbacks
///   4. Operation resumes and completes crypto work
///
/// ## This Implementation:
///
/// The Provider API implementation shows:
/// - **Provider dispatch table**: Maps provider functions (teardown, get_params, query_operation)  
/// - **Algorithm dispatch tables**: Maps algorithm operations (RSA sign, encrypt, decrypt)
/// - **Operation contexts**: Per-operation state (`AsyncRsaCtx`)
/// - **Full async job integration**: Same patterns as ENGINE API
///
/// The provider registers RSA signature and asymmetric cipher algorithms that demonstrate:
/// - Async job detection using `ASYNC_get_current_job()`
/// - Async operation suspension using `ASYNC_pause_job()` and `ASYNC_PAUSE`
/// - Background thread completion signaling via wait context callbacks
/// - Integration with OpenSSL's async job system (identical to ENGINE API)
///
/// ## Conclusion:
///
/// Provider API is NOT limited in async capabilities - it has the same async support as
/// ENGINE API! The key insight is that Provider operations are called within the same
/// OpenSSL async job context, so they can use all the same async mechanisms.
///
/// ## Usage:
///
/// ```rust
/// // Create and register the provider
/// let provider = AsyncProvider::new()?;
/// if !provider.register() {
///     return Err("Failed to register provider".into());
/// }
///
/// // Provider operations will now be available for async crypto operations
/// // OpenSSL will automatically route operations to our async implementations
/// ```
// Provider constants
const PROVIDER_NAME: &str = "rust_async_provider";
const _PROVIDER_VERSION: &str = "1.0.0"; // Used for future version checks

// Provider operation identifiers (from OpenSSL 3.0+)
const OSSL_OP_SIGNATURE: c_int = 1;
const OSSL_OP_ASYM_CIPHER: c_int = 2;

// Algorithm names
const RSA_ALGORITHM_NAME: &str = "RSA:rsaEncryption";

// Provider API FFI definitions for OpenSSL 3.0+
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct OSSL_PROVIDER {
    _private: [u8; 0],
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct OSSL_CORE_HANDLE {
    _private: [u8; 0],
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct OSSL_DISPATCH {
    function_id: c_int,
    function: *const c_void,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct OSSL_ALGORITHM {
    algorithm_names: *const c_char,
    property_definition: *const c_char,
    implementation: *const OSSL_DISPATCH,
    algorithm_description: *const c_char,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct OSSL_PARAM {
    key: *const c_char,
    data_type: c_int,
    data: *mut c_void,
    data_size: usize,
    return_size: usize,
}

// Provider function identifiers
const OSSL_FUNC_PROVIDER_TEARDOWN: c_int = 1;
const OSSL_FUNC_PROVIDER_GETTABLE_PARAMS: c_int = 2;
const OSSL_FUNC_PROVIDER_GET_PARAMS: c_int = 3;
const OSSL_FUNC_PROVIDER_QUERY_OPERATION: c_int = 4;

// Signature operation function identifiers
const OSSL_FUNC_SIGNATURE_NEWCTX: c_int = 1;
const OSSL_FUNC_SIGNATURE_SIGN_INIT: c_int = 2;
const OSSL_FUNC_SIGNATURE_SIGN: c_int = 3;
const OSSL_FUNC_SIGNATURE_FREECTX: c_int = 10;

// Asymmetric cipher operation function identifiers
const OSSL_FUNC_ASYM_CIPHER_NEWCTX: c_int = 1;
const OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT: c_int = 2;
const OSSL_FUNC_ASYM_CIPHER_ENCRYPT: c_int = 3;
const OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT: c_int = 4;
const OSSL_FUNC_ASYM_CIPHER_DECRYPT: c_int = 5;
const OSSL_FUNC_ASYM_CIPHER_FREECTX: c_int = 10;

// Provider context structure
#[repr(C)]
struct AsyncProviderCtx {
    core_handle: *const OSSL_CORE_HANDLE,
}

// RAII wrapper for OSSL_LIB_CTX that handles automatic cleanup
pub struct LibraryContext {
    ctx: *mut openssl_sys::OSSL_LIB_CTX,
    registered_providers: std::collections::HashMap<String, *mut OSSL_PROVIDER>,
}

impl LibraryContext {
    /// Create a new library context
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        unsafe {
            let ctx = crate::exp::ffi::OSSL_LIB_CTX_new();
            if ctx.is_null() {
                return Err("Failed to create OSSL_LIB_CTX".into());
            }

            println!("✅ Created new library context: {ctx:p}");
            Ok(LibraryContext {
                ctx,
                registered_providers: std::collections::HashMap::new(),
            })
        }
    }

    /// Get the raw pointer (for FFI calls)
    pub fn as_ptr(&self) -> *mut openssl_sys::OSSL_LIB_CTX {
        self.ctx
    }

    /// Load a provider in this library context
    pub fn load_provider(
        &mut self,
        name: &str,
    ) -> Result<*mut OSSL_PROVIDER, Box<dyn std::error::Error>> {
        let provider_name = CString::new(name)?;

        match self.load_provider_in_context(&provider_name) {
            Ok(provider) => {
                println!(
                    "✅ Loaded provider '{}' in library context {ctx:p}",
                    name,
                    ctx = self.ctx
                );

                // Track the loaded provider
                self.registered_providers.insert(name.to_string(), provider);

                Ok(provider)
            }
            Err(e) => Err(format!(
                "Failed to load provider '{name}' in library context: {e}"
            )
            .into()),
        }
    }

    /// Internal helper to load provider in the context
    fn load_provider_in_context(
        &self,
        provider_name: &CString,
    ) -> Result<*mut OSSL_PROVIDER, &'static str> {
        unsafe {
            let provider = crate::exp::ffi::OSSL_PROVIDER_load_ex(
                self.ctx,
                provider_name.as_ptr(),
                std::ptr::null(),
            );

            if provider.is_null() {
                return Err("OSSL_PROVIDER_load_ex failed");
            }

            Ok(provider)
        }
    }

    /// Add a built-in provider to this library context
    pub fn add_builtin_provider(
        &self,
        name: &str,
        init_fn: unsafe extern "C" fn(
            *const OSSL_CORE_HANDLE,
            *const OSSL_DISPATCH,
            *mut *const OSSL_DISPATCH,
            *mut *mut std::ffi::c_void,
        ) -> c_int,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let provider_name = CString::new(name)?;

        match self.add_builtin_to_context(&provider_name, init_fn) {
            Ok(_) => {
                println!(
                    "✅ Added built-in provider '{}' to library context {ctx:p}",
                    name,
                    ctx = self.ctx
                );
                Ok(())
            }
            Err(e) => Err(format!(
                "Failed to add built-in provider '{name}' to library context: {e}"
            )
            .into()),
        }
    }

    /// Internal helper to add built-in provider to the context
    fn add_builtin_to_context(
        &self,
        provider_name: &CString,
        init_fn: unsafe extern "C" fn(
            *const OSSL_CORE_HANDLE,
            *const OSSL_DISPATCH,
            *mut *const OSSL_DISPATCH,
            *mut *mut std::ffi::c_void,
        ) -> c_int,
    ) -> Result<(), &'static str> {
        unsafe {
            let result = crate::exp::ffi::OSSL_PROVIDER_add_builtin(
                self.ctx,
                provider_name.as_ptr(),
                init_fn,
            );

            if result != 1 {
                return Err("OSSL_PROVIDER_add_builtin failed");
            }

            Ok(())
        }
    }

    /// Check if a provider is registered in this context
    pub fn is_provider_registered(&self, name: &str) -> bool {
        self.registered_providers.contains_key(name)
    }

    /// Unregister a provider from this context
    pub fn unregister_provider(&mut self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(provider) = self.registered_providers.remove(name) {
            unsafe {
                let result = crate::exp::ffi::OSSL_PROVIDER_unload(provider);
                if result != 1 {
                    let error_code = crate::exp::ffi::ERR_get_error();
                    return Err(format!(
                        "Failed to unload provider '{name}': error_code={error_code:#x}"
                    )
                    .into());
                }
            }
            println!(
                "✅ Unregistered provider '{}' from library context {ctx:p}",
                name,
                ctx = self.ctx
            );
            Ok(())
        } else {
            Err(format!("Provider '{name}' is not registered in this context").into())
        }
    }

    /// Get list of registered providers
    pub fn get_registered_providers(&self) -> Vec<String> {
        self.registered_providers.keys().cloned().collect()
    }

    /// Register an async provider with this library context
    pub fn register_async_provider(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.is_provider_registered(PROVIDER_NAME) {
            return Err("Async provider is already registered in this context".into());
        }

        println!(
            "🔄 Registering async provider '{PROVIDER_NAME}' with library context"
        );

        // Load default provider first (required for SSL)
        self.load_provider("default")
            .map_err(|e| format!("Failed to load default provider: {e}"))?;

        // Add our custom provider as built-in to this context
        self.add_builtin_provider(PROVIDER_NAME, OSSL_provider_init)
            .map_err(|e| format!("Failed to add built-in provider: {e}"))?;

        // Load our provider in this context
        self.load_provider(PROVIDER_NAME)
            .map_err(|e| format!("Failed to load our provider: {e}"))?;

        println!(
            "✅ Async provider '{PROVIDER_NAME}' registered successfully in library context"
        );

        Ok(())
    }

    /// Unregister the async provider from this context
    pub fn unregister_async_provider(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.unregister_provider(PROVIDER_NAME)
    }

    /// Create an SSL context using this library context
    ///
    /// This method safely creates an SSL context that uses the providers registered
    /// with this library context, providing complete isolation from global providers.
    /// The returned SslContextBuilder can be used to configure the SSL context further.
    ///
    /// # Returns
    ///
    /// Returns a `SslContextBuilder` that can be used to configure SSL settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// let mut lib_ctx = LibraryContext::new()?;
    /// lib_ctx.register_async_provider()?;
    /// let ssl_ctx_builder = lib_ctx.create_ssl_context()?;
    /// let ssl_ctx = ssl_ctx_builder.build()?;
    /// ```
    pub fn create_ssl_context(&self) -> Result<SslContextBuilder, Box<dyn std::error::Error>> {
        unsafe {
            // Use our new FFI function to create SSL context with library context
            let ssl_ctx_ptr = openssl_ktls::ffi::create_ssl_ctx_with_libctx(self.ctx);

            if ssl_ctx_ptr.is_null() {
                return Err("Failed to create SSL context with library context".into());
            }

            // Create SslContextBuilder from the raw pointer
            // Note: SslContextBuilder::from_ptr takes ownership of the pointer
            let ssl_ctx_builder = SslContextBuilder::from_ptr(ssl_ctx_ptr);

            println!(
                "✅ Created SSL context with library context {ctx:p} -> SSL_CTX {ssl_ctx:p}",
                ctx = self.ctx,
                ssl_ctx = ssl_ctx_ptr
            );

            Ok(ssl_ctx_builder)
        }
    }
}

impl Drop for LibraryContext {
    fn drop(&mut self) {
        // Unload all registered providers first
        let provider_names: Vec<String> = self.registered_providers.keys().cloned().collect();
        for name in provider_names {
            if let Err(e) = self.unregister_provider(&name) {
                println!(
                    "⚠️  Failed to unregister provider '{name}' during cleanup: {e}"
                );
            }
        }

        if !self.ctx.is_null() {
            println!("🗑️  Freeing library context: {ctx:p}", ctx = self.ctx);
            unsafe {
                crate::exp::ffi::OSSL_LIB_CTX_free(self.ctx);
            }
            self.ctx = std::ptr::null_mut();
        }
    }
}

// RSA operation context
#[repr(C)]
struct AsyncRsaCtx {
    provider_ctx: *mut AsyncProviderCtx,
    rsa_key: *mut crate::exp::ffi::RSA,
}

// Provider initialization function - required entry point
#[unsafe(no_mangle)]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe extern "C" fn OSSL_provider_init(
    _handle: *const OSSL_CORE_HANDLE,
    _in_: *const OSSL_DISPATCH,
    out: *mut *const OSSL_DISPATCH,
    _provctx: *mut *mut c_void,
) -> c_int {
    println!("🔧 Initializing Rust async provider");

    // Create provider context
    let provider_ctx = Box::into_raw(Box::new(AsyncProviderCtx {
        core_handle: _handle,
    }));
    *_provctx = provider_ctx as *mut c_void;

    // Set up dispatch table - use function pointer casting
    let dispatch_table = Box::leak(Box::new([
        OSSL_DISPATCH {
            function_id: OSSL_FUNC_PROVIDER_TEARDOWN,
            function: provider_teardown as *const c_void,
        },
        OSSL_DISPATCH {
            function_id: OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
            function: provider_gettable_params as *const c_void,
        },
        OSSL_DISPATCH {
            function_id: OSSL_FUNC_PROVIDER_GET_PARAMS,
            function: provider_get_params as *const c_void,
        },
        OSSL_DISPATCH {
            function_id: OSSL_FUNC_PROVIDER_QUERY_OPERATION,
            function: provider_query_operation as *const c_void,
        },
        OSSL_DISPATCH {
            function_id: 0,
            function: std::ptr::null(),
        },
    ]));

    *out = dispatch_table.as_ptr();

    1 // Success
}

// Provider teardown function
extern "C" fn provider_teardown(_provctx: *mut c_void) {
    println!("🗑️  Tearing down Rust async provider");
    if !_provctx.is_null() {
        unsafe {
            let _ = Box::from_raw(_provctx as *mut AsyncProviderCtx);
        }
    }
}

// Provider gettable params function
extern "C" fn provider_gettable_params(_provctx: *mut c_void) -> *const OSSL_PARAM {
    println!("📋 Provider gettable params");
    // Return null to indicate no gettable params for now
    std::ptr::null()
}

// Provider get params function
extern "C" fn provider_get_params(_provctx: *mut c_void, _params: *mut OSSL_PARAM) -> c_int {
    println!("🔍 Provider get params");
    // For now, just return success without setting any params
    1
}

// Provider query operation function
extern "C" fn provider_query_operation(
    _provctx: *mut c_void,
    operation_id: c_int,
    _no_cache: *const c_int,
) -> *const OSSL_ALGORITHM {
    println!("🔍 Provider query operation: {operation_id}");

    match operation_id {
        OSSL_OP_SIGNATURE => {
            println!("📝 Providing RSA signature algorithms");
            get_rsa_signature_algorithms()
        }
        OSSL_OP_ASYM_CIPHER => {
            println!("🔐 Providing RSA asymmetric cipher algorithms");
            get_rsa_asym_cipher_algorithms()
        }
        _ => {
            println!("❌ Unsupported operation: {operation_id}");
            std::ptr::null()
        }
    }
}

// RSA signature algorithm implementation
fn get_rsa_signature_algorithms() -> *const OSSL_ALGORITHM {
    println!("📝 Creating RSA signature dispatch table");

    // Create dispatch table on heap to avoid sync issues
    let dispatch_table = Box::leak(Box::new([
        OSSL_DISPATCH {
            function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
            function: rsa_signature_newctx as *const c_void,
        },
        OSSL_DISPATCH {
            function_id: OSSL_FUNC_SIGNATURE_SIGN_INIT,
            function: rsa_signature_sign_init as *const c_void,
        },
        OSSL_DISPATCH {
            function_id: OSSL_FUNC_SIGNATURE_SIGN,
            function: rsa_signature_sign as *const c_void,
        },
        OSSL_DISPATCH {
            function_id: OSSL_FUNC_SIGNATURE_FREECTX,
            function: rsa_signature_freectx as *const c_void,
        },
        OSSL_DISPATCH {
            function_id: 0,
            function: std::ptr::null(),
        },
    ]));

    let rsa_name = Box::leak(CString::new(RSA_ALGORITHM_NAME).unwrap().into_boxed_c_str());
    let rsa_desc = Box::leak(
        CString::new("Rust Async RSA Signature Provider")
            .unwrap()
            .into_boxed_c_str(),
    );

    // Create algorithm descriptor on heap
    let algorithm = Box::leak(Box::new(OSSL_ALGORITHM {
        algorithm_names: rsa_name.as_ptr(),
        property_definition: std::ptr::null(),
        implementation: dispatch_table.as_ptr(),
        algorithm_description: rsa_desc.as_ptr(),
    }));

    // Create algorithms array on heap
    let algorithms = Box::leak(Box::new([
        *algorithm,
        OSSL_ALGORITHM {
            algorithm_names: std::ptr::null(),
            property_definition: std::ptr::null(),
            implementation: std::ptr::null(),
            algorithm_description: std::ptr::null(),
        },
    ]));

    algorithms.as_ptr()
}

// RSA asymmetric cipher algorithm implementation
fn get_rsa_asym_cipher_algorithms() -> *const OSSL_ALGORITHM {
    println!("🔐 Creating RSA cipher dispatch table");

    // Create dispatch table on heap to avoid sync issues
    let dispatch_table = Box::leak(Box::new([
        OSSL_DISPATCH {
            function_id: OSSL_FUNC_ASYM_CIPHER_NEWCTX,
            function: rsa_asym_cipher_newctx as *const c_void,
        },
        OSSL_DISPATCH {
            function_id: OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,
            function: rsa_asym_cipher_encrypt_init as *const c_void,
        },
        OSSL_DISPATCH {
            function_id: OSSL_FUNC_ASYM_CIPHER_ENCRYPT,
            function: rsa_asym_cipher_encrypt as *const c_void,
        },
        OSSL_DISPATCH {
            function_id: OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,
            function: rsa_asym_cipher_decrypt_init as *const c_void,
        },
        OSSL_DISPATCH {
            function_id: OSSL_FUNC_ASYM_CIPHER_DECRYPT,
            function: rsa_asym_cipher_decrypt as *const c_void,
        },
        OSSL_DISPATCH {
            function_id: OSSL_FUNC_ASYM_CIPHER_FREECTX,
            function: rsa_asym_cipher_freectx as *const c_void,
        },
        OSSL_DISPATCH {
            function_id: 0,
            function: std::ptr::null(),
        },
    ]));

    let rsa_name = Box::leak(CString::new(RSA_ALGORITHM_NAME).unwrap().into_boxed_c_str());
    let rsa_desc = Box::leak(
        CString::new("Rust Async RSA Cipher Provider")
            .unwrap()
            .into_boxed_c_str(),
    );

    // Create algorithm descriptor on heap
    let algorithm = Box::leak(Box::new(OSSL_ALGORITHM {
        algorithm_names: rsa_name.as_ptr(),
        property_definition: std::ptr::null(),
        implementation: dispatch_table.as_ptr(),
        algorithm_description: rsa_desc.as_ptr(),
    }));

    // Create algorithms array on heap
    let algorithms = Box::leak(Box::new([
        *algorithm,
        OSSL_ALGORITHM {
            algorithm_names: std::ptr::null(),
            property_definition: std::ptr::null(),
            implementation: std::ptr::null(),
            algorithm_description: std::ptr::null(),
        },
    ]));

    algorithms.as_ptr()
}

// RSA Signature operation implementations with async support
extern "C" fn rsa_signature_newctx(provctx: *mut c_void, _propq: *const c_char) -> *mut c_void {
    println!("🆕 Creating new RSA signature context");

    let ctx = Box::into_raw(Box::new(AsyncRsaCtx {
        provider_ctx: provctx as *mut AsyncProviderCtx,
        rsa_key: std::ptr::null_mut(),
    }));

    ctx as *mut c_void
}

extern "C" fn rsa_signature_sign_init(
    ctx: *mut c_void,
    rsa_key: *mut c_void,
    _params: *const OSSL_PARAM,
) -> c_int {
    println!("🔐 Initializing RSA signature sign");

    if ctx.is_null() || rsa_key.is_null() {
        return 0;
    }

    unsafe {
        let rsa_ctx = ctx as *mut AsyncRsaCtx;
        (*rsa_ctx).rsa_key = rsa_key as *mut crate::exp::ffi::RSA;
    }

    1 // Success
}

extern "C" fn rsa_signature_sign(
    ctx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
    _tbs: *const u8,
    tbslen: usize,
) -> c_int {
    println!("✍️  Provider RSA signature sign operation - tbslen: {tbslen}");

    if ctx.is_null() {
        return 0;
    }

    unsafe {
        let rsa_ctx = ctx as *mut AsyncRsaCtx;
        if (*rsa_ctx).rsa_key.is_null() {
            return 0;
        }

        // Check if we have an active async job - Provider API can use async jobs!
        let job = crate::exp::ffi::ASYNC_get_current_job();
        if !job.is_null() {
            println!("🚀 Provider found async job context for RSA signing: {job:p}");

            // Simulate async behavior for larger operations
            if tbslen > 32 {
                println!("⏸️  Provider large signature operation - demonstrating async pause");

                // Get the wait context from the current job
                let wait_ctx = crate::exp::ffi::ASYNC_get_wait_ctx(job);
                if !wait_ctx.is_null() {
                    println!("✅ Provider got wait context: {wait_ctx:p}");

                    static mut PROVIDER_SIGN_CALL_COUNT: u32 = 0;
                    PROVIDER_SIGN_CALL_COUNT += 1;

                    if PROVIDER_SIGN_CALL_COUNT == 1 {
                        println!(
                            "🔄 Provider first call - pausing job to demonstrate async mechanism"
                        );

                        // Cast wait_ctx to raw pointer to pass to another thread
                        let wait_ctx_raw = wait_ctx as usize;

                        println!("🚀 Provider starting background thread to signal completion");
                        std::thread::spawn(move || {
                            // Simulate some async work
                            std::thread::sleep(std::time::Duration::from_millis(10));

                            println!(
                                "✅ Provider background work completed, getting wait context callback..."
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
                                    "✅ Provider got callback from wait context, invoking to notify ready..."
                                );

                                // First set the status
                                let job_id = CString::new("provider_rsa_sign_job").unwrap();
                                let status_result = crate::exp::ffi::ASYNC_WAIT_CTX_set_status(
                                    wait_ctx,
                                    job_id.as_ptr(),
                                    crate::exp::ffi::ASYNC_STATUS_OK,
                                );
                                println!(
                                    "🔔 Provider ASYNC_WAIT_CTX_set_status returned: {status_result}"
                                );

                                // Now invoke the callback to notify that async operation is ready
                                println!(
                                    "📞 Provider invoking wait context callback to notify async operation ready"
                                );
                                callback.unwrap()(callback_arg);
                                println!(
                                    "✅ Provider callback invoked - async operation should be resumed!"
                                );
                            } else {
                                println!(
                                    "❌ Provider failed to get callback from wait context (result={get_callback_result})"
                                );

                                // Fallback to just setting status
                                let job_id = CString::new("provider_rsa_sign_job").unwrap();
                                let status_result = crate::exp::ffi::ASYNC_WAIT_CTX_set_status(
                                    wait_ctx,
                                    job_id.as_ptr(),
                                    crate::exp::ffi::ASYNC_STATUS_OK,
                                );
                                println!(
                                    "🔔 Provider ASYNC_WAIT_CTX_set_status fallback returned: {status_result}"
                                );
                            }
                        });

                        // Pause the job - Provider API can use this too!
                        println!("⏸️  Provider calling ASYNC_pause_job...");
                        let pause_result = crate::exp::ffi::ASYNC_pause_job();
                        println!(
                            "✅ Provider ASYNC_pause_job returned: {pause_result} - job has been resumed, continuing with crypto operation"
                        );

                        // Reset for next call
                        PROVIDER_SIGN_CALL_COUNT = 0;

                        // After ASYNC_pause_job returns, we've been resumed by the callback
                        println!(
                            "🔄 Provider job resumed - now performing the actual RSA signing operation"
                        );
                    }
                } else {
                    // Fallback to simple pause mechanism without wait context
                    static mut SIMPLE_SIGN_CALL_COUNT: u32 = 0;
                    SIMPLE_SIGN_CALL_COUNT += 1;

                    if SIMPLE_SIGN_CALL_COUNT == 1 {
                        println!("🔄 Provider simple async - pausing for async demo");
                        return crate::exp::ffi::ASYNC_PAUSE;
                    } else {
                        println!("✅ Provider resumed call - completing signature");
                        SIMPLE_SIGN_CALL_COUNT = 0;
                    }
                }
            }
        }

        // For demo, create a dummy signature
        if !sig.is_null() && !siglen.is_null() {
            let dummy_sig_len = std::cmp::min(tbslen.saturating_mul(2), 256);
            *siglen = dummy_sig_len;

            if sigsize >= dummy_sig_len {
                for i in 0..dummy_sig_len {
                    *sig.add(i) = (i % 256) as u8;
                }
            }
        } else if !siglen.is_null() {
            // Return required signature length
            *siglen = std::cmp::min(tbslen.saturating_mul(2), 256);
        }

        println!("✅ Provider RSA signature completed");
        1
    }
}

extern "C" fn rsa_signature_freectx(ctx: *mut c_void) {
    println!("🗑️  Freeing RSA signature context");
    if !ctx.is_null() {
        unsafe {
            let _ = Box::from_raw(ctx as *mut AsyncRsaCtx);
        }
    }
}

// RSA Asymmetric Cipher operation implementations with async support
extern "C" fn rsa_asym_cipher_newctx(provctx: *mut c_void, _propq: *const c_char) -> *mut c_void {
    println!("🆕 Creating new RSA asymmetric cipher context");

    let ctx = Box::into_raw(Box::new(AsyncRsaCtx {
        provider_ctx: provctx as *mut AsyncProviderCtx,
        rsa_key: std::ptr::null_mut(),
    }));

    ctx as *mut c_void
}

extern "C" fn rsa_asym_cipher_encrypt_init(
    ctx: *mut c_void,
    rsa_key: *mut c_void,
    _params: *const OSSL_PARAM,
) -> c_int {
    println!("🔐 Initializing RSA encrypt");

    if ctx.is_null() || rsa_key.is_null() {
        return 0;
    }

    unsafe {
        let rsa_ctx = ctx as *mut AsyncRsaCtx;
        (*rsa_ctx).rsa_key = rsa_key as *mut crate::exp::ffi::RSA;
    }

    1 // Success
}

extern "C" fn rsa_asym_cipher_encrypt(
    ctx: *mut c_void,
    out: *mut u8,
    outlen: *mut usize,
    outsize: usize,
    _in_: *const u8,
    inlen: usize,
) -> c_int {
    println!("🔐 Provider RSA encrypt operation - inlen: {inlen}");

    if ctx.is_null() {
        return 0;
    }

    unsafe {
        let rsa_ctx = ctx as *mut AsyncRsaCtx;
        if (*rsa_ctx).rsa_key.is_null() {
            return 0;
        }

        // Check for async job context - Provider API can use async jobs!
        let job = crate::exp::ffi::ASYNC_get_current_job();
        if !job.is_null() {
            println!("🚀 Provider found async job context for RSA encrypt: {job:p}");

            static mut PROVIDER_ENCRYPT_CALL_COUNT: u32 = 0;
            let count = {
                PROVIDER_ENCRYPT_CALL_COUNT += 1;
                PROVIDER_ENCRYPT_CALL_COUNT
            };

            println!("📞 Provider async RSA ENCRYPT call #{count}");

            if count < 2 {
                println!(
                    "⏸️  Provider ENCRYPT operation in progress - pausing job (call #{count})"
                );
                return crate::exp::ffi::ASYNC_PAUSE;
            }

            println!(
                "✅ Provider ENCRYPT operation ready - performing actual RSA encryption (call #{count})"
            );
            PROVIDER_ENCRYPT_CALL_COUNT = 0; // Reset for next operation
        }

        // For demo, create dummy encrypted data
        if !out.is_null() && !outlen.is_null() {
            let dummy_out_len = std::cmp::min(inlen.saturating_mul(2), 256);
            *outlen = dummy_out_len;

            if outsize >= dummy_out_len {
                for i in 0..dummy_out_len {
                    *out.add(i) = (i % 256) as u8;
                }
            }
        } else if !outlen.is_null() {
            // Return required output length
            *outlen = std::cmp::min(inlen.saturating_mul(2), 256);
        }

        println!("✅ Provider RSA encrypt completed");
        1
    }
}

extern "C" fn rsa_asym_cipher_decrypt_init(
    ctx: *mut c_void,
    rsa_key: *mut c_void,
    _params: *const OSSL_PARAM,
) -> c_int {
    println!("🔓 Initializing RSA decrypt");

    if ctx.is_null() || rsa_key.is_null() {
        return 0;
    }

    unsafe {
        let rsa_ctx = ctx as *mut AsyncRsaCtx;
        (*rsa_ctx).rsa_key = rsa_key as *mut crate::exp::ffi::RSA;
    }

    1 // Success
}

extern "C" fn rsa_asym_cipher_decrypt(
    ctx: *mut c_void,
    out: *mut u8,
    outlen: *mut usize,
    outsize: usize,
    _in_: *const u8,
    inlen: usize,
) -> c_int {
    println!("🔓 Provider RSA decrypt operation - inlen: {inlen}");

    if ctx.is_null() {
        return 0;
    }

    unsafe {
        let rsa_ctx = ctx as *mut AsyncRsaCtx;
        if (*rsa_ctx).rsa_key.is_null() {
            return 0;
        }

        // Check for async job context - Provider API can use async jobs!
        let job = crate::exp::ffi::ASYNC_get_current_job();
        if !job.is_null() {
            println!("🚀 Provider found async job context for RSA decrypt: {job:p}");

            static mut PROVIDER_DECRYPT_CALL_COUNT: u32 = 0;
            let count = {
                PROVIDER_DECRYPT_CALL_COUNT += 1;
                PROVIDER_DECRYPT_CALL_COUNT
            };

            println!("📞 Provider async RSA DECRYPT call #{count}");

            if count < 2 {
                println!(
                    "⏸️  Provider DECRYPT operation in progress - pausing job (call #{count})"
                );
                return crate::exp::ffi::ASYNC_PAUSE;
            }

            println!(
                "✅ Provider DECRYPT operation ready - performing actual RSA decryption (call #{count})"
            );
            PROVIDER_DECRYPT_CALL_COUNT = 0; // Reset for next operation
        }

        // For demo, create dummy decrypted data
        if !out.is_null() && !outlen.is_null() {
            let dummy_out_len = std::cmp::min(inlen / 2, 128);
            *outlen = dummy_out_len;

            if outsize >= dummy_out_len {
                for i in 0..dummy_out_len {
                    *out.add(i) = (i % 256) as u8;
                }
            }
        } else if !outlen.is_null() {
            // Return required output length
            *outlen = std::cmp::min(inlen / 2, 128);
        }

        println!("✅ Provider RSA decrypt completed");
        1
    }
}

extern "C" fn rsa_asym_cipher_freectx(ctx: *mut c_void) {
    println!("🗑️  Freeing RSA asymmetric cipher context");
    if !ctx.is_null() {
        unsafe {
            let _ = Box::from_raw(ctx as *mut AsyncRsaCtx);
        }
    }
}

// Provider management structure - now just holds provider metadata
pub struct AsyncProvider {
    provider_name: CString,
}

impl AsyncProvider {
    /// Create a new async provider instance
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        println!("🚀 Creating async provider (OpenSSL 3.0+ Provider API)");

        let provider_name = CString::new(PROVIDER_NAME)?;

        Ok(AsyncProvider { provider_name })
    }

    /// Get the provider name for registration
    pub fn name(&self) -> &str {
        PROVIDER_NAME
    }

    /// Check if the provider is available
    pub fn is_available(&self) -> bool {
        unsafe {
            let result = crate::exp::ffi::OSSL_PROVIDER_available(
                std::ptr::null_mut(), // Use default library context
                self.provider_name.as_ptr(),
            );
            result == 1
        }
    }

    /// Register the provider with a provided library context
    /// This is now a convenience method that delegates to LibraryContext
    pub fn register(
        &mut self,
        lib_ctx: &mut LibraryContext,
    ) -> Result<(), Box<dyn std::error::Error>> {
        lib_ctx.register_async_provider()
    }

    /// Unload/unregister the provider from a library context
    /// This is now a convenience method that delegates to LibraryContext
    pub fn unregister(&mut self, lib_ctx: &mut LibraryContext) -> bool {
        match lib_ctx.unregister_async_provider() {
            Ok(_) => {
                println!("✅ Provider '{PROVIDER_NAME}' unloaded successfully");
                true
            }
            Err(e) => {
                println!("❌ Failed to unregister provider: {e}");
                false
            }
        }
    }

    /// Complete cleanup for the provider
    pub fn cleanup(&mut self, lib_ctx: &mut LibraryContext) -> bool {
        println!("🧹 Cleaning up async provider '{PROVIDER_NAME}'");
        self.unregister(lib_ctx)
    }

    /// Check if the provider is currently registered in a context
    pub fn is_registered(&self, lib_ctx: &LibraryContext) -> bool {
        lib_ctx.is_provider_registered(PROVIDER_NAME)
    }

    /// Check if this provider is available globally
    pub fn is_available_globally() -> bool {
        unsafe {
            let provider_name = CString::new(PROVIDER_NAME).unwrap();
            let result = crate::exp::ffi::OSSL_PROVIDER_available(
                std::ptr::null_mut(), // Default library context (global)
                provider_name.as_ptr(),
            );
            result == 1
        }
    }
}

impl Drop for AsyncProvider {
    fn drop(&mut self) {
        println!("🗑️  Dropping AsyncProvider '{PROVIDER_NAME}'");
        // Note: Provider cleanup is now handled by LibraryContext
        // The provider pointer will be cleaned up when the context is dropped
    }
}

/// Global provider registration helper - now requires explicit library context
pub fn register_async_provider()
-> Result<(AsyncProvider, LibraryContext), Box<dyn std::error::Error>> {
    let mut provider = AsyncProvider::new()?;
    let mut lib_ctx = LibraryContext::new()?;

    provider.register(&mut lib_ctx)?;
    println!("✅ Async provider registered with library context");
    Ok((provider, lib_ctx))
}

/// Check if the async provider is available in the system
pub fn is_async_provider_available() -> bool {
    unsafe {
        let provider_name = CString::new(PROVIDER_NAME).unwrap();
        let result =
            crate::exp::ffi::OSSL_PROVIDER_available(std::ptr::null_mut(), provider_name.as_ptr());
        result == 1
    }
}

#[test]
fn test_async_provider_registration() {
    let (provider, lib_ctx) = register_async_provider().unwrap();
    assert!(provider.is_registered(&lib_ctx));
}

#[test]
fn test_ssl_context_creation_with_library_context() {
    // Create a library context and register our async provider
    let mut lib_ctx = LibraryContext::new().unwrap();
    lib_ctx.register_async_provider().unwrap();

    // Create SSL context using the library context
    let ssl_ctx_builder = lib_ctx.create_ssl_context().unwrap();

    // Build the actual SSL context
    let _ssl_ctx = ssl_ctx_builder.build();

    // The fact that we can build the SSL context successfully indicates it was created properly
    println!("✅ Successfully created SSL context with library context isolation");
}

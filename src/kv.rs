//! Shared KV store exposed to JS interceptors via `env.KV`.
//!
//! Three ops surface it:
//!
//! - `env.KV.get(key)`            → value | undefined (absent)
//! - `env.KV.put(key, value)`     → void
//! - `env.KV.update(key, fn)`     → new value  (atomic read-modify-write)
//!
//! Null and undefined are distinct: `null` is a stored value; `undefined`
//! returned from the `update` callback deletes the key.
//!
//! `update` holds the write lock while the synchronous JavaScript callback runs.
//! That gives one callback invocation and one atomic store/delete decision.

use deno_core::OpState;
use deno_core::op2;
use deno_core::serde_v8;
use deno_core::v8;
use deno_error::JsErrorBox;
use serde::Serialize;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Arc, RwLock};

pub struct SharedKv {
    store: RwLock<HashMap<String, serde_json::Value>>,
}

impl SharedKv {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            store: RwLock::new(HashMap::new()),
        })
    }
}

fn kv_from_state(state: &Rc<RefCell<OpState>>) -> Arc<SharedKv> {
    Arc::clone(state.borrow().borrow::<Arc<SharedKv>>())
}

/// Return value for `op_outgate_kv_get`.
///
/// Distinguishes "key absent" (`found=false`) from "key holds null"
/// (`found=true, value=null`). The JS wrapper converts `found=false` to
/// `undefined`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KvGetResult {
    found: bool,
    value: serde_json::Value,
}

#[op2]
#[serde]
pub fn op_outgate_kv_get(
    state: Rc<RefCell<OpState>>,
    #[string] key: String,
) -> Result<KvGetResult, JsErrorBox> {
    let kv = kv_from_state(&state);
    let guard = kv.store.read().unwrap();
    Ok(match guard.get(&key) {
        None => KvGetResult {
            found: false,
            value: serde_json::Value::Null,
        },
        Some(v) => KvGetResult {
            found: true,
            value: v.clone(),
        },
    })
}

#[op2]
pub fn op_outgate_kv_put(
    state: Rc<RefCell<OpState>>,
    #[string] key: String,
    #[serde] value: serde_json::Value,
) -> Result<(), JsErrorBox> {
    let kv = kv_from_state(&state);
    kv.store.write().unwrap().insert(key, value);
    Ok(())
}

/// Atomic read-modify-write.
///
/// The callback must be synchronous. Returning `undefined` deletes the key;
/// returning any other JSON-serializable value stores that value.
#[op2]
pub fn op_outgate_kv_update<'s, 'i>(
    scope: &mut v8::PinScope<'s, 'i>,
    state: Rc<RefCell<OpState>>,
    #[string] key: String,
    callback: v8::Local<'s, v8::Function>,
) -> Result<v8::Local<'s, v8::Value>, JsErrorBox> {
    let kv = kv_from_state(&state);
    let mut guard = kv.store.write().unwrap();

    let current = match guard.get(&key) {
        None => v8::undefined(scope).into(),
        Some(value) => serde_v8::to_v8(scope, value).map_err(|err| {
            JsErrorBox::generic(format!("KV: failed to convert stored value to V8: {err}"))
        })?,
    };

    let receiver = v8::undefined(scope).into();
    let Some(next) = callback.call(scope, receiver, &[current]) else {
        return Ok(v8::undefined(scope).into());
    };

    if next.is_promise() {
        return Err(JsErrorBox::type_error(
            "env.KV.update callback must be synchronous",
        ));
    }

    if next.is_undefined() {
        guard.remove(&key);
    } else {
        let value = serde_v8::from_v8(scope, next).map_err(|err| {
            JsErrorBox::generic(format!(
                "KV: failed to convert callback result to JSON: {err}"
            ))
        })?;
        guard.insert(key, value);
    }

    Ok(next)
}

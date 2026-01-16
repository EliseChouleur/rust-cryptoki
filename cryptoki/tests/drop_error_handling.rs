// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Tests for Drop error handling in Session.
//!
//! These tests verify that the Drop implementation handles errors gracefully
//! and does not log errors when close() was called explicitly or when
//! close_on_drop is disabled.

mod common;

use common::test_logger::{clear_logs, init_logger, logs_contain_error, print_logs};
use common::{init_pins, USER_PIN};
use cryptoki::session::{CloseOnDrop, Session, UserType};
use cryptoki::types::AuthPin;
use serial_test::serial;

// ============================================================================
// Tests
// ============================================================================

/// Test that when Drop is called on a session with an invalid handle,
/// an error IS logged (this is expected behavior for unexpected errors).
#[test]
#[serial]
fn drop_with_invalid_handle_logs_error() {
    init_logger();
    clear_logs();

    let (pkcs11, _slot) = init_pins();

    // Create a session with an invalid handle
    let session =
        unsafe { Session::new_from_raw(999999, pkcs11, CloseOnDrop::AutomaticallyCloseSession) };

    // Drop the session - should log error for invalid handle
    drop(session);

    println!("Captured logs:");
    print_logs();

    assert!(
        logs_contain_error("Failed to close session"),
        "Error SHOULD appear because the handle is invalid"
    );
}

/// Test that when close() is called explicitly (even if it fails),
/// no error is logged during Drop.
#[test]
#[serial]
fn close_then_drop_no_error_logged() {
    init_logger();
    clear_logs();

    let (pkcs11, _slot) = init_pins();

    // Create a session with an invalid handle
    let session =
        unsafe { Session::new_from_raw(999999, pkcs11, CloseOnDrop::AutomaticallyCloseSession) };

    // Call close() explicitly - it will fail but sets closed=true
    let close_result = session.close();
    assert!(
        close_result.is_err(),
        "close() should return error for invalid handle"
    );

    // Drop has already been called by close() consuming self,
    // but since closed=true, it should NOT log an error

    println!("Captured logs:");
    print_logs();

    assert!(
        !logs_contain_error("Failed to close session"),
        "Error should NOT appear because close() was called explicitly"
    );
}

/// Test that when using CloseOnDrop::DoNotClose, Drop does NOT attempt to close
/// the session and does NOT log any error.
#[test]
#[serial]
fn no_close_on_drop_no_error_logged() {
    init_logger();
    clear_logs();

    let (pkcs11, _slot) = init_pins();

    // Create a session with an invalid handle but close_on_drop=DoNotClose
    let session = unsafe { Session::new_from_raw(999999, pkcs11, CloseOnDrop::DoNotClose) };

    // Drop the session WITHOUT calling close()
    // Since close_on_drop=DoNotClose, Drop should not attempt to close
    drop(session);

    println!("Captured logs:");
    print_logs();

    assert!(
        !logs_contain_error("Failed to close session"),
        "Error should NOT appear because CloseOnDrop::DoNotClose was used"
    );
}

/// Test that a normal session close works without errors.
#[test]
#[serial]
fn normal_session_close_no_error() {
    init_logger();
    clear_logs();

    let (pkcs11, slot) = init_pins();

    // Open a valid session
    let session = pkcs11.open_ro_session(slot).unwrap();

    // Login
    session
        .login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))
        .unwrap();

    // Close explicitly
    let close_result = session.close();
    assert!(
        close_result.is_ok(),
        "close() should succeed for valid session"
    );

    println!("Captured logs:");
    print_logs();

    assert!(
        !logs_contain_error("Failed to close session"),
        "No error should be logged for normal session close"
    );
}

// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Tests for Drop error handling in Session.
//!
//! These tests use a mock PKCS#11 library that can simulate token removal,
//! allowing us to verify that Drop implementations handle errors gracefully
//! without logging an error when close() was called explicitly.

mod common;

use common::mock_pkcs11::{get_mock_library, MockPkcs11};
use common::test_logger::{clear_logs, init_logger, logs_contain_error, print_logs};
use serial_test::serial;

// ============================================================================
// Tests
// ============================================================================

/// Test that when close() is called explicitly after token removal,
/// no error is logged during Drop.
///
/// Scenario:
/// 1. Open a valid session
/// 2. Simulate token removal (via mock API)
/// 3. get_session_info() returns error (handle invalid)
/// 4. close() is called explicitly and error is ignored
/// 5. Drop runs but should NOT log an error because close() was called
#[test]
#[serial]
fn mock_session_close_after_token_removal_no_error() {
    init_logger();
    clear_logs();

    let mock = match MockPkcs11::new() {
        Some(m) => m,
        None => {
            println!("Skipping test: not using mock PKCS#11 library");
            return;
        }
    };
    mock.reset();

    // Load the mock library via cryptoki
    let pkcs11 = get_mock_library().unwrap();

    // 1. Open a valid session
    let slot = pkcs11.get_slots_with_token().unwrap()[0];
    let session = pkcs11.open_ro_session(slot).unwrap();

    // Verify the session is valid
    assert!(
        session.get_session_info().is_ok(),
        "Session should be valid initially"
    );

    // 2. Simulate token removal
    mock.simulate_token_removal();

    // 3. get_session_info() returns error (handle invalid)
    let result = session.get_session_info();
    assert!(
        result.is_err(),
        "get_session_info should fail after token removal"
    );

    // 4. Close the session explicitly and IGNORE the error
    // (this is the pattern users would use when handling token removal gracefully)
    let close_result = session.close();
    assert!(
        close_result.is_err(),
        "close() should return error after token removal"
    );

    // 5. Drop has been called, but since close() set closed=true,
    //    it should not log an error

    // 6. Verify that NO error was logged
    println!("Captured logs:");
    print_logs();

    assert!(
        !logs_contain_error("Failed to close session"),
        "Error should NOT appear because close() was called explicitly"
    );
}

/// Test that when using open_ro_session_no_drop, Drop does NOT attempt to close
/// the session and does NOT log any error, even after token removal.
///
/// Scenario:
/// 1. Open a session with open_ro_session_no_drop (close_on_drop=false)
/// 2. Simulate token removal
/// 3. Drop the session WITHOUT calling close()
/// 4. Verify NO error is logged (because Drop should not attempt to close)
#[test]
#[serial]
fn mock_session_no_drop_after_token_removal_no_error() {
    init_logger();
    clear_logs();

    let mock = match MockPkcs11::new() {
        Some(m) => m,
        None => {
            println!("Skipping test: not using mock PKCS#11 library");
            return;
        }
    };
    mock.reset();

    let pkcs11 = get_mock_library().unwrap();

    // 1. Open a session with open_ro_session_no_drop
    let slot = pkcs11.get_slots_with_token().unwrap()[0];
    let session = pkcs11.open_ro_session_no_drop(slot).unwrap();

    // Verify the session is valid
    assert!(
        session.get_session_info().is_ok(),
        "Session should be valid initially"
    );

    // 2. Simulate token removal
    mock.simulate_token_removal();

    // 3. Drop the session WITHOUT calling close()
    // Since close_on_drop=false, Drop should not attempt to close
    drop(session);

    // 4. Verify that NO error was logged
    println!("Captured logs:");
    print_logs();

    assert!(
        !logs_contain_error("Failed to close session"),
        "Error should NOT appear because open_ro_session_no_drop was used"
    );
}

/// Test that when a session is dropped without explicit close() after token removal,
/// an error IS logged (this is expected behavior for unexpected errors).
#[test]
#[serial]
fn mock_session_drop_without_close_after_token_removal_logs_error() {
    init_logger();
    clear_logs();

    let mock = match MockPkcs11::new() {
        Some(m) => m,
        None => {
            println!("Skipping test: not using mock PKCS#11 library");
            return;
        }
    };
    mock.reset();

    let pkcs11 = get_mock_library().unwrap();

    // Open a valid session
    let slot = pkcs11.get_slots_with_token().unwrap()[0];
    let session = pkcs11.open_ro_session(slot).unwrap();

    // Verify the session is valid
    assert!(session.get_session_info().is_ok());

    // Simulate token removal
    mock.simulate_token_removal();

    // Drop the session WITHOUT calling close()
    // This should trigger the Drop error
    drop(session);

    // Verify that an error WAS logged
    println!("Captured logs:");
    print_logs();

    assert!(
        logs_contain_error("Failed to close session"),
        "Error SHOULD appear because close() was NOT called explicitly"
    );
}

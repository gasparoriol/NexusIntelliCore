// Audit baseline fixture — synthetic code, NOT production.
// Frozen by Fase 0: contains exactly 2 unsafe blocks and 1 SQL-injection heuristic pattern.

fn deref_raw_ptr(p: *const u32) -> u32 {
    // SAFETY: caller guarantees p is valid and aligned.
    unsafe { *p }
}

fn write_raw_ptr(p: *mut u32, val: u32) {
    // SAFETY: caller guarantees p is valid, aligned, and exclusively owned.
    unsafe {
        *p = val;
    }
}

fn build_user_query(id: &str) -> String {
    format!("SELECT name FROM users WHERE id = {}", id)
}

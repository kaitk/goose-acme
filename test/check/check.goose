// What the tests under test/ share. Each check prints what it checked, for
// the test's golden file in test/expected/, then asserts it, so a failure
// shows in the output as well as in the exit code.
namespace check;

import std;

let DIGITS = "0123456789abcdef";

// Prints "label: ok", or "label: FAILED".
fn that(label: const u8[:], ok: bool) {
    print(label, if ok { ": ok" } else { ": FAILED" });
    assert(ok);
}

// Prints the value, and what was expected if it differs.
fn eq(label: const u8[:], got: i64, want: i64) {
    if got == want { print(label, ": ", got); }
    else { print(label, ": ", got, ", expected ", want, ": FAILED"); }
    assert(got == want);
}

// Prints the text, and what was expected if it differs.
fn text(label: const u8[:], got: const u8[:], want: const u8[:]) {
    let ok = got == want;
    if ok { print(label, ": ", got); }
    else { print(label, ": \"", got, "\", expected \"", want, "\": FAILED"); }
    assert(ok);
}

// The bytes in lowercase hexadecimal.
fn hex(data: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for b in data {
        out.push(DIGITS[b >> 4]);
        out.push(DIGITS[b & 15]);
    }
    return out;
}

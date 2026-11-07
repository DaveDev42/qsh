//! L3 loopback tests for `ScreenEcho` (ADR-0053 decision 3, M23 DoD 8 and 7):
//! the capability gate in both directions, the signal after input that does
//! not change the screen, and its order behind each `ScreenUpdate`.
//! Pipe-backed sessions, so they run on every OS; a pipe has no line
//! discipline, so `tty` is `UNKNOWN`, which is also what a Windows host
//! reports.

use std::time::Duration;

use qsh_core::client::screen::ClientScreen;
use qsh_core::client::{AttachEvent, Session};
use qsh_proto::wire::{self, TtyEcho};
use qsh_testkit::loopback::LoopbackHarness;

use crate::screen_sync::{DEADLINE, open_attached, open_req, wait_ring_end};

/// Read events until `pick` returns a value, acking screen updates on the way.
async fn until<T>(
    att: &mut qsh_core::client::Attached,
    screen: &mut ClientScreen,
    mut pick: impl FnMut(&AttachEvent, &ClientScreen) -> Option<T>,
) -> T {
    tokio::time::timeout(DEADLINE, async {
        loop {
            let event = att.next().await.expect("event").expect("stream open");
            match &event {
                AttachEvent::Screen(part) => {
                    let outcome = screen.on_part(part).expect("part");
                    if let Some(n) = outcome.ack() {
                        att.send_screen_ack(n).await.expect("ack");
                    }
                }
                AttachEvent::ScreenDatagram(part) => {
                    let outcome = screen.on_datagram_part(part);
                    if let Some(n) = outcome.ack() {
                        att.send_screen_ack(n).await.expect("ack");
                    }
                }
                _ => {}
            }
            if let Some(v) = pick(&event, screen) {
                return v;
            }
        }
    })
    .await
    .expect("expected event arrived")
}

#[tokio::test(flavor = "multi_thread")]
async fn screen_echo_is_sent_after_input_even_when_the_screen_does_not_change() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    let req = open_req(&s);
    let (opened, mut pipe, mut att) = open_attached(&h, &mut s, req).await;
    assert_eq!(opened.screen_channel.len(), 16);
    let mut screen = ClientScreen::new();
    // Settle on the first screen so the input below changes nothing visible.
    let text = b"password: ";
    pipe.write_output(text).await.unwrap();
    wait_ring_end(&h, &opened.session_id, text.len() as u64).await;
    until(&mut att, &mut screen, |_, sc| (sc.num() > 0).then_some(())).await;
    // Drain echoes for the first screen.
    let sent = att.send_input(b"secret").await.unwrap();
    assert_eq!(sent, 6);
    let pipe_in = pipe.read_input(16).await.unwrap();
    assert_eq!(pipe_in, b"secret");
    // The pipe echoes nothing, so no new ScreenUpdate comes; the timer path
    // must still report the input offset once ECHO_GRACE has passed.
    let echo = until(&mut att, &mut screen, |ev, _| match ev {
        AttachEvent::ScreenEcho(e) if e.input_seq == 6 => Some(*e),
        _ => None,
    })
    .await;
    assert_eq!(echo.tty_echo(), TtyEcho::Unknown);
    assert!(echo.state_num > 0);
    assert_eq!(att.echo_rejected(), 0);
    s.close();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn screen_echo_follows_each_screen_update_on_the_same_carrier() {
    let h = LoopbackHarness::start().await;
    h.server.hide_capabilities(&[wire::CAP_DATAGRAM_V1]);
    let mut s = h.session().await;
    let req = open_req(&s);
    let (opened, mut pipe, mut att) = open_attached(&h, &mut s, req).await;
    let mut screen = ClientScreen::new();
    let mut updates_seen = 0;
    let mut last_update = 0;
    for chunk in [&b"one\r\n"[..], b"two\r\n", b"three\r\n"] {
        pipe.write_output(chunk).await.unwrap();
        // Each update is followed by an echo for the state it carried or a
        // newer one; read until the echo for `last_update` arrives.
        let target = tokio::time::timeout(DEADLINE, async {
            loop {
                let ev = att.next().await.unwrap().unwrap();
                match ev {
                    AttachEvent::Screen(part) => {
                        let outcome = screen.on_part(&part).unwrap();
                        if let Some(n) = outcome.ack() {
                            att.send_screen_ack(n).await.unwrap();
                            updates_seen += 1;
                            last_update = n;
                        }
                    }
                    AttachEvent::ScreenEcho(e)
                        if updates_seen > 0 && e.state_num >= last_update =>
                    {
                        return e.state_num;
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("an echo follows the update");
        assert!(target >= last_update);
    }
    assert!(updates_seen >= 1);
    let _ = opened;
    s.close();
    h.shutdown().await;
}

async fn no_echo_within(h: &LoopbackHarness, mut s: Session) {
    let req = open_req(&s);
    let (opened, mut pipe, mut att) = open_attached(h, &mut s, req).await;
    assert_eq!(opened.screen_channel.len(), 16, "screen sync still runs");
    let mut screen = ClientScreen::new();
    pipe.write_output(b"hi").await.unwrap();
    wait_ring_end(h, &opened.session_id, 2).await;
    att.send_input(b"abc").await.unwrap();
    assert_eq!(pipe.read_input(8).await.unwrap(), b"abc");
    // Wait well past ECHO_GRACE plus a screen cycle; nothing but screen
    // updates may arrive.
    let _ = tokio::time::timeout(Duration::from_millis(600), async {
        loop {
            match att.next().await.unwrap().unwrap() {
                AttachEvent::ScreenEcho(e) => panic!("ScreenEcho without the capability: {e:?}"),
                AttachEvent::Screen(part) => {
                    if let Some(n) = screen.on_part(&part).unwrap().ack() {
                        att.send_screen_ack(n).await.unwrap();
                    }
                }
                _ => {}
            }
        }
    })
    .await;
    assert!(screen.num() > 0, "the screen did arrive");
    s.close();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_without_screen_echo_gets_no_screen_echo_frames() {
    let h = LoopbackHarness::start().await;
    let dialed = h.dialer.dial(h.addr, "127.0.0.1").await.expect("dial");
    let s = Session::negotiate_hiding(dialed.connection, "laptop", &[wire::CAP_SCREEN_ECHO_V1])
        .await
        .expect("negotiate");
    assert!(!s.capabilities.iter().any(|c| c == wire::CAP_SCREEN_ECHO_V1));
    no_echo_within(&h, s).await;
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_without_screen_echo_gets_no_screen_echo_frames() {
    let h = LoopbackHarness::start().await;
    h.server.hide_capabilities(&[wire::CAP_SCREEN_ECHO_V1]);
    let s = h.session().await;
    assert!(!s.capabilities.iter().any(|c| c == wire::CAP_SCREEN_ECHO_V1));
    no_echo_within(&h, s).await;
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn both_sides_advertise_screen_echo() {
    let h = LoopbackHarness::start().await;
    let s = h.session().await;
    assert!(s.capabilities.iter().any(|c| c == wire::CAP_SCREEN_ECHO_V1));
    s.close();
    h.shutdown().await;
}

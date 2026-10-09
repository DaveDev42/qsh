//! The accept-hold gate (ADR-0023 decision 19), without a socket where the
//! rule is about time or counts, so its bounds are exact under a paused
//! clock.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::tunnel::testutil::loopback_pair;

const WINDOW: Duration = Duration::from_secs(2);

fn down_view() -> (watch::Sender<CarrierState>, CarrierView) {
    let (tx, rx) = watch::channel(CarrierState::Disconnected);
    (tx, CarrierView::watching(rx, None))
}

/// A view with a gate and a supervisor that is attempting right now.
fn held_view(window: Duration) -> (watch::Sender<CarrierState>, CarrierView, HoldSignal) {
    let (tx, view) = down_view();
    let (gate, signal) = hold_gate(window);
    signal.attempting();
    (tx, view.with_hold(gate), signal)
}

fn is_refused(admit: &Admit) -> bool {
    matches!(admit, Admit::Refused)
}

#[tokio::test(start_paused = true)]
async fn accept_hold_zero_keeps_the_immediate_rejection_of_decision_6() {
    // No gate at all, which is what `accept_hold_ms` of 0 builds.
    let (_tx, view) = down_view();
    assert!(is_refused(&view.admit()));
}

/// The hold ends exactly at the window: not a tick before, and the caller is
/// told to refuse, having been handed no carrier to send anything on.
#[tokio::test(start_paused = true)]
async fn accept_hold_rejects_at_the_deadline_without_sending_a_byte_to_any_carrier_gate() {
    let (_tx, view, _signal) = held_view(WINDOW);
    let Admit::Held(held) = view.admit() else {
        panic!("an attempt is running, so the connection is held");
    };
    let started = Instant::now();
    let waiter = tokio::spawn({
        let view = view.clone();
        async move { held.wait(&view).await.is_some() }
    });
    tokio::time::advance(WINDOW - Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert!(!waiter.is_finished(), "still held a millisecond early");
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(!waiter.await.unwrap(), "the deadline refuses");
    assert_eq!(Instant::now() - started, WINDOW);
}

/// Decision 19: a wait for the next attempt that is longer than the hold is
/// not held; one that starts inside the window is, and so is one running.
#[tokio::test(start_paused = true)]
async fn accept_hold_is_not_used_during_a_backoff_wait_longer_than_the_hold() {
    let (_tx, view, signal) = held_view(WINDOW);

    signal.next_in(WINDOW + Duration::from_millis(1));
    assert!(is_refused(&view.admit()), "a wait past the window");

    signal.next_in(WINDOW);
    assert!(
        matches!(view.admit(), Admit::Held(_)),
        "a start exactly at the deadline"
    );

    // The wait shrinks as time passes: the same planned start is inside the
    // window a little later.
    signal.next_in(WINDOW + Duration::from_secs(1));
    assert!(is_refused(&view.admit()));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(matches!(view.admit(), Admit::Held(_)));

    signal.attempting();
    assert!(matches!(view.admit(), Admit::Held(_)), "an attempt runs");

    signal.idle();
    assert!(is_refused(&view.admit()), "no attempt is pending");
}

/// The sixty-fifth connection is refused at once; a slot freed by a held
/// connection ending is usable again.
#[tokio::test(start_paused = true)]
async fn accept_hold_rejects_past_sixty_four_held_connections() {
    let (_tx, view, _signal) = held_view(WINDOW);
    let mut held = Vec::new();
    for n in 0..HELD_MAX {
        match view.admit() {
            Admit::Held(h) => held.push(h),
            _ => panic!("connection {n} should be held"),
        }
    }
    assert!(is_refused(&view.admit()), "the 65th");
    assert!(is_refused(&view.admit()), "and the one after");
    drop(held.pop());
    assert!(matches!(view.admit(), Admit::Held(_)), "a slot came free");
}

/// A held connection that has been refused frees its slot and its place in
/// the queue, so it cannot block the ones behind it.
#[tokio::test(start_paused = true)]
async fn accept_hold_slot_and_turn_are_released_when_the_hold_ends() {
    let (_tx, view, _signal) = held_view(WINDOW);
    let Admit::Held(first) = view.admit() else {
        panic!("held");
    };
    assert_eq!(view.hold.as_ref().unwrap().held(), 1);
    assert!(first.wait(&view).await.is_none());
    assert_eq!(view.hold.as_ref().unwrap().held(), 0);
    assert!(view.hold.as_ref().unwrap().turns.lock().queue.is_empty());
}

/// Held connections go out in the order they were taken, even when many
/// wake at once on a multi-threaded runtime. Without the queue the order is
/// whatever the scheduler wakes first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accept_hold_preserves_accept_order_on_dispatch() {
    let (client, _host) = loopback_pair().await;
    let (tx, rx) = watch::channel(CarrierState::Disconnected);
    let (gate, signal) = hold_gate(Duration::from_secs(30));
    let view = CarrierView::watching(rx, None).with_hold(gate);
    signal.attempting();

    let dispatched = Arc::new(Mutex::new(Vec::new()));
    let mut waiters = Vec::new();
    for id in 0..12_usize {
        let Admit::Held(held) = view.admit() else {
            panic!("connection {id} should be held");
        };
        let view = view.clone();
        let dispatched = Arc::clone(&dispatched);
        waiters.push(tokio::spawn(async move {
            let (_, turn) = held.wait(&view).await.expect("the carrier comes back");
            // Writing a request takes a moment, and the earlier a connection
            // was taken the longer it takes here: without the queue the
            // last one would finish first.
            tokio::time::sleep(Duration::from_millis(3 * (12 - id as u64))).await;
            dispatched.lock().unwrap().push(id);
            drop(turn);
        }));
    }
    tx.send(CarrierState::Live(Arc::new(ForwardCarrier::Direct(client))))
        .unwrap();
    for waiter in waiters {
        waiter.await.unwrap();
    }
    assert_eq!(
        *dispatched.lock().unwrap(),
        (0..12).collect::<Vec<_>>(),
        "dispatch follows the order the connections were taken"
    );
}

/// A connection whose hold ends at the front of the queue does not stall the
/// one behind it.
#[tokio::test(start_paused = true)]
async fn accept_hold_a_refused_connection_at_the_front_does_not_stall_the_queue() {
    let (client, _host) = loopback_pair().await;
    let (tx, rx) = watch::channel(CarrierState::Disconnected);
    let (gate, signal) = hold_gate(WINDOW);
    let view = CarrierView::watching(rx, None).with_hold(gate);
    signal.attempting();
    let Admit::Held(first) = view.admit() else {
        panic!("held");
    };
    tokio::time::advance(Duration::from_secs(1)).await;
    let Admit::Held(second) = view.admit() else {
        panic!("held");
    };
    let first = tokio::spawn({
        let view = view.clone();
        async move { first.wait(&view).await.is_some() }
    });
    let second = tokio::spawn({
        let view = view.clone();
        async move { second.wait(&view).await.is_some() }
    });
    // The first one's window (2 s from its accept) ends at t = 2 s, the
    // second's at t = 3 s. The carrier comes back in between.
    tokio::time::advance(Duration::from_millis(1_500)).await;
    assert!(!first.await.unwrap(), "the first was held past its window");
    tx.send(CarrierState::Live(Arc::new(ForwardCarrier::Direct(client))))
        .unwrap();
    assert!(second.await.unwrap(), "the second is dispatched");
}

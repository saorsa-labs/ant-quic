// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Endpoint bind strategy, separated from socket creation so address and fallback
//! contracts can be tested without opening network sockets.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, PartialEq, Eq)]
pub(super) enum BoundSocket<D, S> {
    Dual(D),
    Single(S),
}

pub(super) async fn bind<D, S, DF, SF>(
    requested: Option<SocketAddr>,
    mut dual: impl FnMut(u16) -> DF,
    mut single: impl FnMut(SocketAddr) -> SF,
) -> io::Result<BoundSocket<D, S>>
where
    DF: Future<Output = io::Result<D>>,
    SF: Future<Output = io::Result<S>>,
{
    // Preserve the complete address (including IPv6 scope and flow info). An
    // explicit bind failure must not silently widen to a wildcard interface.
    if let Some(addr) = requested.filter(|addr| !addr.ip().is_unspecified()) {
        return single(addr).await.map(BoundSocket::Single);
    }

    let port = requested.map_or(0, |addr| addr.port());
    let dual_error = match dual(port).await {
        Ok(socket) => return Ok(BoundSocket::Dual(socket)),
        Err(error) => error,
    };
    let v6_default = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    let addr = requested.unwrap_or(v6_default);
    match single(addr).await {
        Ok(socket) => Ok(BoundSocket::Single(socket)),
        Err(v6_error) if addr == v6_default => {
            let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
            single(v4).await.map(BoundSocket::Single).map_err(|v4_error| {
                io::Error::new(v4_error.kind(), format!(
                    "All socket binds failed (dual: {dual_error}, v6: {v6_error}, v4: {v4_error})"
                ))
            })
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::future::ready;
    use std::net::SocketAddrV6;
    use std::task::{Context, Poll, Waker};

    // Every injected binder returns Ready. No runtime, timers, I/O or sockets.
    fn completed<T>(future: impl Future<Output = T>) -> T {
        let mut future = std::pin::pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("pure binder unexpectedly pending"),
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Attempt {
        Dual(u16),
        Single(SocketAddr),
    }

    #[test]
    fn explicit_address_preserves_family_scope_and_actual_port() {
        for requested in [
            "127.0.0.1:0".parse().unwrap(),
            "192.0.2.7:43123".parse().unwrap(),
            "[::1]:0".parse().unwrap(),
            SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 0, 17, 9)),
        ] {
            let attempts = RefCell::new(Vec::new());
            let mut actual = requested;
            if actual.port() == 0 {
                actual.set_port(43124);
            }
            let result = completed(bind(
                Some(requested),
                |port| {
                    attempts.borrow_mut().push(Attempt::Dual(port));
                    // Deliberately succeeds with an unrelated wildcard family/port.
                    ready(Ok("[::]:49999".parse::<SocketAddr>().unwrap()))
                },
                |addr| {
                    attempts.borrow_mut().push(Attempt::Single(addr));
                    ready(Ok(actual))
                },
            ))
            .unwrap();
            assert_eq!(result, BoundSocket::Single(actual));
            assert_eq!(*attempts.borrow(), vec![Attempt::Single(requested)]);
        }
    }

    #[test]
    fn explicit_failure_never_attempts_wildcard_fallback() {
        for requested in ["127.0.0.1:43123", "[::1]:0"] {
            let requested = requested.parse().unwrap();
            let attempts = RefCell::new(Vec::new());
            let error = completed(bind(
                Some(requested),
                |port| {
                    attempts.borrow_mut().push(Attempt::Dual(port));
                    ready(Ok(()))
                },
                |addr| {
                    attempts.borrow_mut().push(Attempt::Single(addr));
                    ready(Err::<(), _>(io::Error::from(io::ErrorKind::AddrInUse)))
                },
            ))
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
            assert_eq!(*attempts.borrow(), vec![Attempt::Single(requested)]);
        }
    }

    #[test]
    fn wildcard_and_default_prefer_dual_socket_without_rewriting_result() {
        for requested in [
            None,
            Some("0.0.0.0:0".parse().unwrap()),
            Some("[::]:43123".parse().unwrap()),
        ] {
            let attempts = RefCell::new(Vec::new());
            // Dual port-zero sockets can have different actual ports.
            let actual = (
                "0.0.0.0:43124".parse::<SocketAddr>().unwrap(),
                "[::]:43125".parse::<SocketAddr>().unwrap(),
            );
            let result = completed(bind(
                requested,
                |port| {
                    attempts.borrow_mut().push(Attempt::Dual(port));
                    ready(Ok(actual))
                },
                |addr| {
                    attempts.borrow_mut().push(Attempt::Single(addr));
                    ready(Ok(()))
                },
            ))
            .unwrap();
            assert_eq!(result, BoundSocket::Dual(actual));
            assert_eq!(
                *attempts.borrow(),
                vec![Attempt::Dual(requested.map_or(0, |addr| addr.port()))]
            );
        }
    }

    #[test]
    fn wildcard_fallbacks_preserve_order_address_and_port() {
        for requested in [
            None,
            Some("[::]:43123".parse().unwrap()),
            Some("0.0.0.0:43123".parse().unwrap()),
        ] {
            let port = requested.map_or(0, |addr: SocketAddr| addr.port());
            let attempts = RefCell::new(Vec::new());
            let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
            let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
            let result = completed(bind(
                requested,
                |port| {
                    attempts.borrow_mut().push(Attempt::Dual(port));
                    ready(Err::<(), _>(io::Error::from(
                        io::ErrorKind::AddrNotAvailable,
                    )))
                },
                |addr| {
                    attempts.borrow_mut().push(Attempt::Single(addr));
                    ready(if addr.is_ipv6() {
                        Err(io::Error::from(io::ErrorKind::AddrNotAvailable))
                    } else {
                        Ok(addr)
                    })
                },
            ))
            .unwrap();
            let expected = if requested.is_some_and(|addr| addr.is_ipv4()) {
                vec![Attempt::Dual(port), Attempt::Single(v4)]
            } else {
                vec![
                    Attempt::Dual(port),
                    Attempt::Single(v6),
                    Attempt::Single(v4),
                ]
            };
            assert_eq!(result, BoundSocket::Single(v4));
            assert_eq!(*attempts.borrow(), expected);
        }
    }

    #[test]
    fn wildcard_single_success_stops_and_total_failure_propagates() {
        for succeed in [true, false] {
            let attempts = RefCell::new(Vec::new());
            let v6 = "[::]:43123".parse().unwrap();
            let result = completed(bind(
                Some(v6),
                |port| {
                    attempts.borrow_mut().push(Attempt::Dual(port));
                    ready(Err::<(), _>(io::Error::from(
                        io::ErrorKind::AddrNotAvailable,
                    )))
                },
                |addr| {
                    attempts.borrow_mut().push(Attempt::Single(addr));
                    ready(if succeed {
                        Ok(addr)
                    } else {
                        Err(io::Error::from(io::ErrorKind::PermissionDenied))
                    })
                },
            ));
            if succeed {
                assert_eq!(result.unwrap(), BoundSocket::Single(v6));
                assert_eq!(attempts.borrow().len(), 2);
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
                assert_eq!(
                    *attempts.borrow(),
                    vec![
                        Attempt::Dual(43123),
                        Attempt::Single(v6),
                        Attempt::Single("0.0.0.0:43123".parse().unwrap())
                    ]
                );
            }
        }
    }
}

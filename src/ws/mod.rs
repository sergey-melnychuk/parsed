//! WebSocket protocol ([RFC 6455](https://www.rfc-editor.org/rfc/rfc6455)).
//!
//! - [`handshake`]: validating the opening handshake and computing
//!   `Sec-WebSocket-Accept`;
//! - [`MessageReader`]: reading whole messages, with fragmented messages reassembled,
//!   control frames delivered as they arrive, payloads unmasked, and the protocol
//!   validated (UTF-8 of text messages, close codes, message size); errors map to the
//!   close code to fail the connection with ([`WsError::close_code`]);
//! - [`Message::encode`] and [`Message::fragments`] for sending;
//! - frame level: [`FrameParser`] (resumable), [`parse_frame`], and the zero-copy
//!   [`parse_frame_ref`].
//!
//! Extensions (e.g. permessage-deflate) are not implemented: with reserved bits allowed
//! in [`FrameConfig::allowed_rsv`], frames can be processed by the caller.

mod frame;
pub mod handshake;
mod message;

pub use frame::{
    Frame, FrameConfig, FrameParser, FrameRef, Masking, OpCode, apply_mask, frame_matcher,
    parse_frame, parse_frame_ref,
};
pub use message::{CloseFrame, Message, MessageConfig, MessageReader};

use crate::matcher::{ErrorKind, MatchError};
use std::borrow::Cow;
use std::fmt;

/// Category of a [`WsError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WsErrorKind {
    /// Input ended before a frame was complete: retry when more bytes arrive.
    Incomplete,
    /// Protocol violation (close code 1002).
    Protocol,
    /// Invalid payload data, e.g. a text message that is not UTF-8 (close code 1007).
    InvalidData,
    /// A frame or message exceeds a size limit (close code 1009).
    TooLarge,
    /// A frame arrived after the close frame.
    Closed,
}

/// WebSocket error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsError {
    kind: WsErrorKind,
    message: Cow<'static, str>,
}

impl WsError {
    pub(crate) fn new(kind: WsErrorKind, message: impl Into<Cow<'static, str>>) -> WsError {
        WsError {
            kind,
            message: message.into(),
        }
    }

    pub(crate) fn protocol(message: impl Into<Cow<'static, str>>) -> WsError {
        WsError::new(WsErrorKind::Protocol, message)
    }

    /// Category of the error.
    pub fn kind(&self) -> WsErrorKind {
        self.kind
    }

    /// Shorthand for `self.kind() == WsErrorKind::Incomplete`.
    pub fn is_incomplete(&self) -> bool {
        self.kind == WsErrorKind::Incomplete
    }

    /// Status code of the close frame to fail the connection with, if the error is
    /// a reason to fail it.
    pub fn close_code(&self) -> Option<u16> {
        match self.kind {
            WsErrorKind::Protocol => Some(1002),
            WsErrorKind::InvalidData => Some(1007),
            WsErrorKind::TooLarge => Some(1009),
            WsErrorKind::Incomplete | WsErrorKind::Closed => None,
        }
    }
}

impl From<MatchError> for WsError {
    fn from(e: MatchError) -> WsError {
        let kind = match e.kind() {
            ErrorKind::Incomplete => WsErrorKind::Incomplete,
            ErrorKind::TooLarge => WsErrorKind::TooLarge,
            _ => WsErrorKind::Protocol,
        };
        WsError::new(kind, e.to_string())
    }
}

impl fmt::Display for WsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for WsError {}

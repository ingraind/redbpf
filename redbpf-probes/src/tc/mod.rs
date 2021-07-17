use crate::socket::SocketError;

/// Possible actions in tc programs
///
/// Allowed return opcodes from BPF programs are listed at
/// <https://elixir.bootlin.com/linux/v5.13.2/source/net/sched/cls_bpf.c#L65>
#[repr(i32)]
pub enum TcAction {
    /// Use the default action configured from `tc`
    Unspec = -1,
    /// Terminate the packet processing pipeline and allows the packet to
    /// proceed
    Ok = 0,
    /// Terminate the packet processing pipeline and start classification from
    /// the beginning
    #[deprecated(note = "linux kernel commit `5cf8ca0e` (linux v4.3) removed this from cls_bpf")]
    Reclassify,
    /// Terminate the packet processing pipeline and drops the packet
    Shot = 2,
    /// Iterate to the next action, if available
    #[deprecated(note = "linux kernel commit `5cf8ca0e` (linux v4.3) removed this from cls_bpf")]
    Pipe,
    /// TC_ACT_SHOT will indicate to the kernel that the skb was released
    /// through kfree_skb() and return NET_XMIT_DROP to the callers for
    /// immediate feedback, whereas TC_ACT_STOLEN will release the skb through
    /// consume_skb() and pretend to upper layers that the transmission was
    /// successful through NET_XMIT_SUCCESS. The perf’s drop monitor which
    /// records traces of kfree_skb() will therefore also not see any drop
    /// indications from TC_ACT_STOLEN since its semantics are such that the
    /// skb has been “consumed” or queued but certainly not “dropped”.
    /// cf) <https://docs.cilium.io/en/latest/bpf/#tc-traffic-control>
    Stolen = 4,
    /// Allow to redirect the skb to the same or another’s device ingress or
    /// egress path together with the bpf_redirect() helper
    Redirect = 7,
    /// For hw path, this means "trap to cpu" and don't further process the
    /// frame in hardware. For sw path, this is equivalent of `Stolen` - drop
    /// the skb and act like everything is alright.
    Trap = 8,
}

/// Result type for tc action programs.
pub type TcActionResult = Result<TcAction, SocketError>;

pub mod prelude {
    pub use super::*;

    pub use crate::bindings::*;
    pub use crate::helpers::*;
    pub use crate::maps::*;
    pub use crate::socket::*;
    pub use redbpf_macros::{program, tc_action};
}

__all__ = ["ReplayWindow"]

WINDOW_SIZE = 64


class ReplayWindow:
    """
    IPsec-style anti-replay window (RFC 4303, Appendix A).

    Tracks the highest accepted sequence number and a bitmap of
    the last WINDOW_SIZE entries.

    Accepted:   new seq > highest  (advance window)
                seq inside window AND not yet seen
    Rejected:   seq == 0  (reserved/invalid)
                seq outside window on the left  (too old)
                seq already in bitmap  (duplicate / replay)

    NOTE: Caller must only COMMIT the update after AEAD tag verification
    succeeds, to prevent a forged packet from poisoning the window.
    """

    def __init__(self, window: int = WINDOW_SIZE):
        self.window  = window
        self.highest = 0
        self._bitmap = 0

    def is_acceptable(self, seq: int) -> bool:
        if seq <= 0:
            return False
        if seq > self.highest:
            return True
        offset = self.highest - seq
        if offset >= self.window:
            return False
        return not bool(self._bitmap & (1 << offset))

    def accept(self, seq: int) -> bool:
        if seq <= 0:
            return False
        if seq > self.highest:
            shift = seq - self.highest
            self._bitmap = (
                (self._bitmap << shift) | 1
            ) & ((1 << self.window) - 1)
            self.highest = seq
            return True
        offset = self.highest - seq
        if offset >= self.window:
            return False
        mask = 1 << offset
        if self._bitmap & mask:
            return False
        self._bitmap |= mask
        return True

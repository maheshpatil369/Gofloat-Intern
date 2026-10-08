import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from replay import ReplayWindow


def test_new_seq_accepted():
    r = ReplayWindow()
    assert r.accept(1) is True
    assert r.accept(2) is True
    assert r.accept(3) is True


def test_duplicate_rejected():
    r = ReplayWindow()
    r.accept(5)
    assert r.accept(5) is False


def test_seq_zero_rejected():
    r = ReplayWindow()
    assert r.accept(0) is False


def test_old_seq_rejected():
    r = ReplayWindow(window=4)
    for i in range(1, 10):
        r.accept(i)
    assert r.accept(1) is False
    assert r.accept(3) is False


def test_out_of_order_inside_window():
    r = ReplayWindow(window=64)
    r.accept(10)
    assert r.accept(7)  is True
    assert r.accept(7)  is False   # duplicate now


def test_highest_advances():
    r = ReplayWindow()
    r.accept(1)
    assert r.highest == 1
    r.accept(100)
    assert r.highest == 100


def test_is_acceptable_does_not_commit():
    r = ReplayWindow()
    assert r.is_acceptable(1) is True
    assert r.is_acceptable(1) is True   # not committed, still acceptable
    r.accept(1)
    assert r.is_acceptable(1) is False  # committed, now a duplicate


def test_gap_allowed():
    r = ReplayWindow()
    r.accept(1)
    r.accept(5)       # gap: 2,3,4 never received (packet loss)
    assert r.accept(3) is True   # late arrival, inside window, never seen

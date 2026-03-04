from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer, SemanticPattern


def test_confidence_calibration():
    pr = PatternRecognizer()
    # Add a strict pattern
    pat = SemanticPattern(
        name="STRICT_SEQ",
        pattern_type="test",
        signature=["0x01", "0x02", "0x03"],
        confidence_threshold=0.8,
    )
    pr.add_pattern(pat)

    seq_match = [0x01, 0x02, 0x03]
    seq_off = [0x01, 0x02, 0x04]

    m1 = pat.matches(seq_match)[1]
    m2 = pat.matches(seq_off)[1]

    assert m1 >= 0.8
    assert m2 < 0.8

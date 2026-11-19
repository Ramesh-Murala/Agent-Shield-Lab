from agentshield import gate_untrusted_content


def test_low_score_pass_does_not_claim_no_rule_matched():
    result = gate_untrusted_content("This tutorial discusses base64 encoding.")

    assert result["decision"] == "pass"
    assert result["report"]["findings"]
    assert result["report"]["score"] < 20
    assert "No rule matched" not in result["reason"]
    assert "below review threshold" in result["reason"]

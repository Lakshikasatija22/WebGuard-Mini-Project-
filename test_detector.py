from detector import analyze_url, analyze_message, risk_category

def test_bad_url():
    r = analyze_url("http://paypal.secure-login.xyz/verify?acc=1")
    assert r["score"] >= 60

def test_good_url():
    r = analyze_url("https://www.google.com")
    assert r["score"] < 30

def test_bad_message():
    r = analyze_message("URGENT! Your SBI account will be blocked. Verify KYC now: http://sbi-kyc-update.top/login")
    assert risk_category(r["score"]) == "HIGH RISK"

def test_safe_message():
    r = analyze_message("Hey, are we meeting for lunch tomorrow?")
    assert r["score"] < 30

if __name__ == "__main__":
    test_bad_url(); test_good_url(); test_bad_message(); test_safe_message()
    print("All tests passed")

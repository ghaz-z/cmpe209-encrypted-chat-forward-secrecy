from cryptography.exceptions import InvalidTag

from client import build_encrypted_message, decrypt_incoming_message
from crypto import generate_key


def test_build_encrypted_message_encrypts_for_each_recipient():
    maya_key = generate_key()
    zane_key = generate_key()

    message = build_encrypted_message(
        "skye",
        "xin chao moi nguoi",
        {"maya": maya_key, "zane": zane_key},
    )

    assert message["type"] == "chat"
    assert set(message["ciphertexts"]) == {"maya", "zane"}
    assert decrypt_incoming_message(message, "maya", {"skye": maya_key}) == "xin chao moi nguoi"
    assert decrypt_incoming_message(message, "zane", {"skye": zane_key}) == "xin chao moi nguoi"


def test_build_encrypted_message_requires_session_keys():
    try:
        build_encrypted_message("skye", "xin chao", {})
    except ValueError as exc:
        assert "No session keys established" in str(exc)
    else:
        raise AssertionError("Expected ValueError when no session keys exist")


def test_decrypt_incoming_message_rejects_sender_tampering():
    shared_key = generate_key()
    message = build_encrypted_message("skye", "bi mat", {"maya": shared_key})
    tampered = dict(message)
    tampered["sender"] = "blake"

    try:
        decrypt_incoming_message(tampered, "maya", {"blake": shared_key})
    except InvalidTag:
        pass
    else:
        raise AssertionError("Expected InvalidTag for tampered sender identity")

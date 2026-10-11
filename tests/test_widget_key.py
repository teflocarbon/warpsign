from unittest import mock

import pytest

from warpsign.src.apple.apple_account_login import AppleDeveloperAuth


def _response(status=200, headers=None, json_body=None):
    response = mock.Mock(status_code=status, headers=headers or {})
    if json_body is None:
        response.json.side_effect = ValueError("not JSON")
    else:
        response.json.return_value = json_body
    return response


@pytest.fixture
def auth(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "warpsign.src.apple.apple_account_login.get_session_dir", lambda: tmp_path
    )
    return AppleDeveloperAuth()


def test_reads_the_key_from_the_sign_out_redirect(auth):
    location = "https://appstoreconnect.apple.com/login?targetUrl=%2F&widgetKey=abc123"
    with mock.patch(
        "requests.head", return_value=_response(302, {"Location": location})
    ) as head:
        with mock.patch.object(auth.session, "get") as get:
            assert auth.widget_key == "abc123"
            assert auth.widget_key == "abc123"
    head.assert_called_once()
    assert head.call_args.kwargs["allow_redirects"] is False
    get.assert_not_called()


def test_falls_back_to_the_olympus_config(auth):
    with mock.patch("requests.head", return_value=_response(404)):
        with mock.patch.object(
            auth.session,
            "get",
            return_value=_response(json_body={"authServiceKey": "old"}),
        ):
            assert auth.widget_key == "old"


def test_reports_a_missing_key(auth):
    with mock.patch(
        "requests.head", side_effect=__import__("requests").ConnectionError()
    ):
        with mock.patch.object(auth.session, "get", return_value=_response(404)):
            with pytest.raises(Exception, match=r"HTTP 404"):
                auth.widget_key

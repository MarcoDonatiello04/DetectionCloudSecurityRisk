import pytest
from unittest.mock import patch, MagicMock
from src.core.bola.attack_vector import BOLAAttackVector

@patch('src.core.bola.attack_vector.requests.request')
def test_execute_tampering_methods(mock_request):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = '{"status": "success"}'
    mock_request.return_value = mock_response

    headers_matrix = {
        "userA": {"Authorization": "Bearer tokenA"},
        "userB": {"Authorization": "Bearer tokenB"},
        "userC": {"Authorization": "Bearer tokenC"},
        "anonymous": {}
    }

    vector = BOLAAttackVector(zap_proxy_url="http://localhost:8090")
    
    # Test a POST request
    results = vector.execute_tampering(
        method="POST",
        target_base_url="http://localhost:5000",
        path="/api/orders/{id}",
        headers_matrix=headers_matrix,
        uuid_alice="alice-uuid",
        uuid_bob="bob-uuid",
        uuid_charlie="charlie-uuid"
    )

    # 3 scenarios * 3 requests per scenario (legitimate, attack, anonymous) = 9 total calls to requests.request
    assert mock_request.call_count == 9
    
    # Let's inspect the first call to requests.request (legitimate user Alice on POST)
    args, kwargs = mock_request.call_args_list[0]
    assert args[0] == "POST"
    assert "json" in kwargs
    assert kwargs["json"]["owner"] == "user_a"
    assert kwargs["headers"]["Authorization"] == "Bearer tokenA"
    
    # Test a PATCH request
    mock_request.reset_mock()
    results = vector.execute_tampering(
        method="PATCH",
        target_base_url="http://localhost:5000",
        path="/api/orders/{id}",
        headers_matrix=headers_matrix,
        uuid_alice="alice-uuid",
        uuid_bob="bob-uuid",
        uuid_charlie="charlie-uuid"
    )

    assert mock_request.call_count == 9
    args, kwargs = mock_request.call_args_list[0]
    assert args[0] == "PATCH"
    assert "json" in kwargs
    assert kwargs["json"]["owner"] == "user_a"

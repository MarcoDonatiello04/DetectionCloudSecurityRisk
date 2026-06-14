import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from src.core.broken_authentication.discovery import (
    run, Config, LLMConfig, StackInfo, LLMClient, OllamaClient,
    ManifestNotFoundException, LLMResponseException, LLMConnectionException
)

# Mock LLMClient for testing run() with dependency injection
class MockLLMClient(LLMClient):
    def __init__(self, responses: list):
        self.responses = responses
        self.calls = 0
        super().__init__(LLMConfig())

    async def complete(self, system: str, user: str) -> str:
        if self.calls < len(self.responses):
            res = self.responses[self.calls]
            self.calls += 1
            return res
        return ""

@pytest.mark.asyncio
async def test_run_success_with_manifest(tmp_path):
    # Setup temporary repository structure
    package_json = tmp_path / "package.json"
    package_json.write_text('{"dependencies": {"express": "^4.18", "jsonwebtoken": "^9.0"}}', encoding="utf-8")
    
    env_example = tmp_path / ".env.example"
    env_example.write_text("PORT=3000\nJWT_SECRET=supersecret\n", encoding="utf-8")

    # Mock response
    mock_json = (
        '{"linguaggio": "JavaScript", "framework": "Express", '
        '"librerie_auth": ["jsonwebtoken"], "identity_provider": null, '
        '"file_configurazione_rilevanti": ["package.json", ".env.example"]}'
    )
    llm_client = MockLLMClient([mock_json])
    
    config = Config()
    result = await run(str(tmp_path), config, llm_client)
    
    assert isinstance(result, StackInfo)
    assert result.linguaggio == "JavaScript"
    assert result.framework == "Express"
    assert "jsonwebtoken" in result.librerie_auth
    assert result.identity_provider is None
    assert "package.json" in result.file_configurazione_rilevanti
    assert llm_client.calls == 1

@pytest.mark.asyncio
async def test_run_manifest_not_found(tmp_path):
    # Setup repository with no manifest files
    env_example = tmp_path / ".env.example"
    env_example.write_text("PORT=3000\n", encoding="utf-8")
    
    config = Config()
    llm_client = MockLLMClient([])
    
    with pytest.raises(ManifestNotFoundException) as exc_info:
        await run(str(tmp_path), config, llm_client)
        
    assert "Nessun file manifest di dipendenze" in str(exc_info.value)

@pytest.mark.asyncio
async def test_run_llm_malformed_response_retry_success(tmp_path):
    # Setup repo
    package_json = tmp_path / "package.json"
    package_json.write_text('{"dependencies": {"express": "^4.18"}}', encoding="utf-8")
    
    # LLM returns malformed data first, then valid JSON
    malformed_resp = "Here is your JSON: {invalid json}"
    valid_json = (
        '{"linguaggio": "JavaScript", "framework": "Express", '
        '"librerie_auth": [], "identity_provider": null, '
        '"file_configurazione_rilevanti": ["package.json"]}'
    )
    llm_client = MockLLMClient([malformed_resp, valid_json])
    
    config = Config()
    result = await run(str(tmp_path), config, llm_client)
    
    assert result.linguaggio == "JavaScript"
    assert result.framework == "Express"
    assert llm_client.calls == 2

@pytest.mark.asyncio
async def test_run_llm_response_exception_after_retries(tmp_path):
    # Setup repo
    package_json = tmp_path / "package.json"
    package_json.write_text('{"dependencies": {"express": "^4.18"}}', encoding="utf-8")
    
    # LLM returns malformed data twice
    malformed_resp1 = "Not JSON data"
    malformed_resp2 = "```json\nstill not JSON\n```"
    llm_client = MockLLMClient([malformed_resp1, malformed_resp2])
    
    config = Config()
    
    with pytest.raises(LLMResponseException) as exc_info:
        await run(str(tmp_path), config, llm_client)
        
    assert "non è parsabile in JSON dopo i tentativi di recupero" in str(exc_info.value)
    assert llm_client.calls == 2

@pytest.mark.asyncio
async def test_ollama_client_success():
    llm_config = LLMConfig(base_url="http://localhost:11434", model="llama3.1")
    client = OllamaClient(llm_config)
    
    # Mock httpx AsyncClient post response
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"message": {"content": '{"ok": true}'}}
    
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        
        response = await client.complete("system instruction", "user instruction")
        assert response == '{"ok": true}'
        mock_post.assert_called_once()

@pytest.mark.asyncio
async def test_ollama_client_connection_error():
    llm_config = LLMConfig(base_url="http://localhost:11434")
    client = OllamaClient(llm_config)
    
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = httpx.ConnectError("Connection refused")
        
        with pytest.raises(LLMConnectionException) as exc_info:
            await client.complete("system", "user")
            
        assert "Impossibile raggiungere Ollama" in str(exc_info.value)

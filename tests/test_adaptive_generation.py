"""Tests for adaptive payload generation."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from chaos_kitten.brain.adaptive_planner import AdaptivePayloadGenerator
from chaos_kitten.brain.orchestrator import execute_and_analyze, Orchestrator, AgentState

# Mock LangChain responses
class MockAIMessage:
    def __init__(self, content):
        self.content = content

@pytest.fixture
def mock_llm():
    llm = MagicMock()
    # Setup chain mock
    chain = MagicMock()
    invoke_mock = MagicMock(return_value=["{'price': -100}", "{'price': '1 OR 1=1'}"])
    chain.invoke = invoke_mock
    return llm

@pytest.fixture
def adaptive_gen(mock_llm):
    return AdaptivePayloadGenerator(mock_llm)

def test_generate_payloads_success(adaptive_gen):
    endpoint = {"method": "POST", "path": "/api/order"}
    previous_payload = {"price": 10}
    response = {"status_code": 200, "body": "OK"}
    
    with patch("chaos_kitten.brain.adaptive_planner.ChatPromptTemplate") as mock_prompt:
        mock_chain = MagicMock()
        mock_chain.invoke.return_value = ["payload1", "payload2"]
        mock_prompt.from_template.return_value.__or__.return_value.__or__.return_value = mock_chain
        
        payloads = adaptive_gen.generate_payloads(endpoint, previous_payload, response)
        
        assert len(payloads) == 2
        assert payloads[0] == "payload1"
        assert payloads[1] == "payload2"

def test_generate_payloads_error_handling(adaptive_gen):
    endpoint = {"method": "GET", "path": "/api/test"}
    with patch("chaos_kitten.brain.adaptive_planner.ChatPromptTemplate") as mock_prompt:
        mock_chain = MagicMock()
        mock_chain.invoke.side_effect = Exception("LLM Error")
        mock_prompt.from_template.return_value.__or__.return_value.__or__.return_value = mock_chain
        
        payloads = adaptive_gen.generate_payloads(endpoint, "pkg", {})
        assert payloads == []

@pytest.mark.asyncio
async def test_orchestrator_adaptive_integration():
    # Setup mocks
    executor = AsyncMock()
    executor.execute_attack.return_value = {
        "status_code": 500, 
        "body": "Error", 
        "elapsed_ms": 100
    }
    
    state = {
        "current_endpoint": 0,
        "endpoints": [{"method": "POST", "path": "/api/test"}],
        "planned_attacks": [{"payload": {"test": 1}, "name": "Test Attack"}],
        "findings": []
    }
    
    config = {
        "adaptive": {
            "enabled": True,
            "max_rounds": 2
        }
    }
    
    with patch("chaos_kitten.brain.orchestrator.AdaptivePayloadGenerator") as MockGen, \
         patch("chaos_kitten.brain.orchestrator.ChatAnthropic") as MockLLM:
        
        mock_gen_instance = MockGen.return_value
        mock_gen_instance.generate_payloads.return_value = ['{"p": 1}', '{"p": 2}']
        
        result = await execute_and_analyze(state, executor, config)
        
        assert executor.execute_attack.call_count == 3
        mock_gen_instance.generate_payloads.assert_called_once()

@pytest.mark.asyncio
async def test_orchestrator_adaptive_max_rounds():
    # Setup mocks
    executor = AsyncMock()
    executor.execute_attack.return_value = {"status_code": 200, "body": "OK"}
    
    state = {
        "current_endpoint": 0,
        "endpoints": [{"method": "POST", "path": "/api/test"}],
        "planned_attacks": [
            {"payload": "P1", "name": "A1"},
            {"payload": "P2", "name": "A2"}
        ],
        "findings": []
    }
    
    config = {
        "adaptive": {
            "enabled": True,
            "max_rounds": 1
        }
    }
    
    with patch("chaos_kitten.brain.orchestrator.AdaptivePayloadGenerator") as MockGen, \
         patch("chaos_kitten.brain.orchestrator.ChatAnthropic"):
        
        mock_gen_instance = MockGen.return_value
        mock_gen_instance.generate_payloads.return_value = ["AP1"]
        
        await execute_and_analyze(state, executor, config)
        
        assert mock_gen_instance.generate_payloads.call_count == 1
        assert executor.execute_attack.call_count == 3

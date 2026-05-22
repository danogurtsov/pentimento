from pathlib import Path

from pentimento.detection.domain_signals import DomainId
from pentimento.domain.models import CDVUnit, NodeType
from pentimento.services.routing import run_routing


class FakeLLM:
    def __init__(self, response: str) -> None:
        self.response = response
        self.calls: list[tuple[str, str]] = []

    def complete(self, prompt: str, *, model: str) -> str:
        self.calls.append((prompt, model))
        return self.response


def test_run_routing_sends_signatures_not_bodies_and_parses_the_typed_result(tmp_path: Path) -> None:
    (tmp_path / "Earn.sol").write_text(
        """
        contract Earn {
            function setSupplyQueue(address[] calldata q) external {}
            function updateWithdrawQueue(uint256[] calldata idx) external {}
            function reallocate(uint256[] calldata a) external {}
        }
        """
    )
    unit = CDVUnit(unit_id="Earn", contract_name="Earn", node_type=NodeType.VAULT, source_files=["Earn.sol"])
    llm = FakeLLM(
        "\n".join(
            [
                "ROUTE lending: SKIP — no collateral/borrow shape",
                "ROUTE amm_dex: SKIP — no swap/LP shape",
                "ROUTE yield_vault: ACTIVATE — reallocate + queue management present",
            ]
        )
    )

    decision = run_routing(unit, tmp_path, llm, "router-model")

    assert llm.calls[0][1] == "router-model"
    assert "function reallocate" in llm.calls[0][0]
    assert "contract Earn {" not in llm.calls[0][0]  # bodies withheld, see run_routing's docstring
    assert decision.unit_id == "Earn"
    assert decision.activated_domains() == (DomainId.YIELD_VAULT,)

from scripts.verify_metrics import recompute_all_metrics, verify_doc_consistency


def test_verify_metrics_runs_and_passes() -> None:
    """Verify that all metrics are reproducible from raw results and match docs."""
    metrics = recompute_all_metrics()
    assert "sample" in metrics
    assert "campaign" in metrics
    assert "benign" in metrics
    assert "dependency_additions" in metrics

    # Assert total counts
    assert metrics["sample"]["v1.2"]["ALL"]["pairs"] == 1349
    assert metrics["campaign"]["v1.2"]["ALL"]["campaigns"] == 84
    assert metrics["benign"]["total_benign"]["pairs"] == 800
    assert metrics["benign"]["total_benign"]["false_blocks"] == 0

    # Assert verification against documentation passes
    verify_doc_consistency(metrics)

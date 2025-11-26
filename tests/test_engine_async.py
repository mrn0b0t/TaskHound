# Tests for async/parallel processing engine.

import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock, patch

import pytest

from taskhound.engine_async import (
    AsyncConfig,
    AsyncTaskHound,
    TargetResult,
    aggregate_results,
)
from taskhound.laps import LAPSFailure


# Mock process function that simulates target processing
def mock_process_target(
    target: str,
    all_rows: List[Dict[str, Any]],
    delay: float = 0.1,
    should_fail: bool = False,
    **kwargs,
) -> Tuple[List[str], Optional[bool]]:
    """Mock process_target for testing."""
    if should_fail:
        raise Exception(f"Simulated failure for {target}")
    
    time.sleep(delay)  # Simulate network I/O
    
    all_rows.append({
        "host": target,
        "type": "TASK",
        "task_path": f"\\Tasks\\{target}_task",
    })
    
    lines = [f"[TASK] {target}: Found 1 task"]
    return lines, None


class TestAsyncConfig:
    """Tests for AsyncConfig dataclass."""
    
    def test_default_values(self):
        config = AsyncConfig()
        assert config.workers == 10
        assert config.rate_limit is None
        assert config.timeout == 30
        assert config.show_progress is True
    
    def test_custom_values(self):
        config = AsyncConfig(workers=20, rate_limit=5.0, timeout=60)
        assert config.workers == 20
        assert config.rate_limit == 5.0
        assert config.timeout == 60


class TestTargetResult:
    """Tests for TargetResult dataclass."""
    
    def test_default_values(self):
        result = TargetResult(target="192.168.1.1", success=True)
        assert result.target == "192.168.1.1"
        assert result.success is True
        assert result.lines == []
        assert result.rows == []
        assert result.laps_result is None
        assert result.error is None
        assert result.elapsed_ms == 0.0
    
    def test_with_data(self):
        result = TargetResult(
            target="server01",
            success=True,
            lines=["line1", "line2"],
            rows=[{"host": "server01"}],
            elapsed_ms=150.5,
        )
        assert len(result.lines) == 2
        assert len(result.rows) == 1
        assert result.elapsed_ms == 150.5


class TestAsyncTaskHound:
    """Tests for AsyncTaskHound parallel processor."""
    
    def test_sequential_mode(self):
        """Test --threads 1 behaves like original sequential processing."""
        config = AsyncConfig(workers=1, show_progress=False)
        engine = AsyncTaskHound(config)
        
        targets = ["host1", "host2", "host3"]
        results = engine.run(
            targets,
            mock_process_target,
            delay=0.01,
        )
        
        assert len(results) == 3
        assert all(r.success for r in results)
        assert all(len(r.rows) == 1 for r in results)
    
    def test_parallel_mode(self):
        """Test parallel processing with multiple workers."""
        config = AsyncConfig(workers=3, show_progress=False)
        engine = AsyncTaskHound(config)
        
        targets = ["host1", "host2", "host3", "host4", "host5"]
        
        start = time.perf_counter()
        results = engine.run(
            targets,
            mock_process_target,
            delay=0.1,
        )
        elapsed = time.perf_counter() - start
        
        assert len(results) == 5
        assert all(r.success for r in results)
        
        # With 3 workers and 0.1s delay, 5 targets should take ~0.2s not ~0.5s
        # Allow some margin for thread overhead
        assert elapsed < 0.4, f"Parallel processing took too long: {elapsed}s"
    
    def test_handles_failures(self):
        """Test that failures are captured but don't stop processing."""
        config = AsyncConfig(workers=2, show_progress=False)
        engine = AsyncTaskHound(config)
        
        def failing_process(target, all_rows, **kwargs):
            if target == "fail_host":
                raise Exception("Simulated failure")
            return [f"OK: {target}"], None
        
        targets = ["host1", "fail_host", "host2"]
        results = engine.run(targets, failing_process)
        
        assert len(results) == 3
        
        successes = [r for r in results if r.success]
        failures = [r for r in results if not r.success]
        
        assert len(successes) == 2
        assert len(failures) == 1
        assert failures[0].target == "fail_host"
        assert "Simulated failure" in failures[0].error
    
    def test_empty_targets(self):
        """Test handling of empty target list."""
        engine = AsyncTaskHound()
        results = engine.run([], mock_process_target)
        assert results == []
    
    def test_rate_limiting(self):
        """Test that rate limiting slows down processing."""
        # 2 targets/second = 0.5s between targets
        config = AsyncConfig(workers=10, rate_limit=2.0, show_progress=False)
        engine = AsyncTaskHound(config)
        
        targets = ["host1", "host2", "host3"]
        
        start = time.perf_counter()
        results = engine.run(
            targets,
            mock_process_target,
            delay=0.01,  # Very fast processing
        )
        elapsed = time.perf_counter() - start
        
        assert len(results) == 3
        # 3 targets at 2/sec should take ~1.0s minimum
        # First target starts immediately, then 0.5s, 0.5s for next two
        assert elapsed >= 0.8, f"Rate limiting not working: {elapsed}s"
    
    def test_rows_collected_per_target(self):
        """Test that each target gets its own row collector."""
        config = AsyncConfig(workers=3, show_progress=False)
        engine = AsyncTaskHound(config)
        
        targets = ["host1", "host2", "host3"]
        results = engine.run(
            targets,
            mock_process_target,
            delay=0.01,
        )
        
        # Each result should have exactly 1 row
        for result in results:
            assert len(result.rows) == 1
            assert result.rows[0]["host"] == result.target
    
    def test_thread_safety_of_output_lock(self):
        """Test that output lock prevents interleaving."""
        config = AsyncConfig(workers=5, show_progress=False)
        engine = AsyncTaskHound(config)
        
        output_order = []
        lock = threading.Lock()
        
        def tracking_process(target, all_rows, **kwargs):
            # Simulate some work
            time.sleep(0.05)
            with lock:
                output_order.append(target)
            return [target], None
        
        targets = [f"host{i}" for i in range(10)]
        results = engine.run(targets, tracking_process)
        
        assert len(results) == 10
        assert len(output_order) == 10
        # All targets should be processed (order may vary due to parallelism)
        assert set(output_order) == set(targets)


class TestAggregateResults:
    """Tests for aggregate_results function."""
    
    def test_aggregates_rows(self):
        results = [
            TargetResult(target="h1", success=True, rows=[{"host": "h1"}]),
            TargetResult(target="h2", success=True, rows=[{"host": "h2"}, {"host": "h2_2"}]),
        ]
        
        all_rows, laps_failures, laps_successes = aggregate_results(results)
        
        assert len(all_rows) == 3
        assert laps_successes == 0
        assert laps_failures == []
    
    def test_aggregates_laps_results(self):
        failure = LAPSFailure(
            hostname="badhost",
            failure_type="no_password",
            message="No LAPS password found",
        )
        
        results = [
            TargetResult(target="h1", success=True, laps_result=True),
            TargetResult(target="h2", success=False, laps_result=failure),
            TargetResult(target="h3", success=True, laps_result=True),
        ]
        
        all_rows, laps_failures, laps_successes = aggregate_results(results)
        
        assert laps_successes == 2
        assert len(laps_failures) == 1
        assert laps_failures[0].hostname == "badhost"
    
    def test_handles_mixed_results(self):
        results = [
            TargetResult(target="h1", success=True, rows=[{"a": 1}]),
            TargetResult(target="h2", success=False, error="failed", rows=[]),
            TargetResult(target="h3", success=True, rows=[{"b": 2}]),
        ]
        
        all_rows, _, _ = aggregate_results(results)
        
        assert len(all_rows) == 2

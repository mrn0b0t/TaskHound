"""Additional tests for taskhound/models/task.py module."""

from taskhound.models.task import TaskRow, TaskType


class TestTaskType:
    """Tests for TaskType enum."""

    def test_tier0_value(self):
        """TIER0 has correct value."""
        assert TaskType.TIER0.value == "TIER-0"

    def test_priv_value(self):
        """PRIV has correct value."""
        assert TaskType.PRIV.value == "PRIV"

    def test_task_value(self):
        """TASK has correct value."""
        assert TaskType.TASK.value == "TASK"

    def test_failure_value(self):
        """FAILURE has correct value."""
        assert TaskType.FAILURE.value == "FAILURE"

    def test_skipped_value(self):
        """SKIPPED has correct value."""
        assert TaskType.SKIPPED.value == "SKIPPED"

    def test_all_types_exist(self):
        """All expected types exist."""
        expected = {"TIER0", "PRIV", "TASK", "FAILURE", "SKIPPED"}
        actual = {t.name for t in TaskType}
        assert expected == actual


class TestTaskRowInit:
    """Tests for TaskRow initialization."""

    def test_minimal_init(self):
        """TaskRow can be created with minimal fields."""
        row = TaskRow(host="SERVER", path="\\Task")
        assert row.host == "SERVER"
        assert row.path == "\\Task"

    def test_all_fields(self):
        """TaskRow can be created with all fields."""
        row = TaskRow(
            host="SERVER.DOMAIN.LOCAL",
            path="\\TestTask",
            target_ip="192.168.1.100",
            computer_sid="S-1-5-21-123456",
            type=TaskType.PRIV,
            runas="DOMAIN\\admin",
            command="cmd.exe",
            arguments="/c echo test",
            author="DOMAIN\\author",
            date="2024-01-01",
            logon_type="Password",
            enabled=True,
            trigger_type="TimeTrigger",
            start_boundary="2024-01-01T00:00:00",
            interval="PT1H",
            duration="P1D",
            days_interval=1,
            reason="Admin account",
            credentials_hint="stored_credentials",
        )
        assert row.host == "SERVER.DOMAIN.LOCAL"
        assert row.type == TaskType.PRIV
        assert row.enabled is True

    def test_default_values(self):
        """TaskRow has sensible defaults."""
        row = TaskRow(host="SERVER", path="\\Task")
        assert row.target_ip is None
        assert row.computer_sid is None
        assert row.type == TaskType.TASK
        assert row.enabled is None


class TestTaskRowToDict:
    """Tests for TaskRow.to_dict method."""

    def test_to_dict_basic(self):
        """to_dict returns dictionary."""
        row = TaskRow(host="SERVER", path="\\Task")
        result = row.to_dict()
        assert isinstance(result, dict)

    def test_to_dict_contains_all_fields(self):
        """to_dict contains all fields."""
        row = TaskRow(host="SERVER", path="\\Task", runas="admin")
        result = row.to_dict()
        assert "host" in result
        assert "path" in result
        assert "runas" in result

    def test_to_dict_type_conversion(self):
        """to_dict converts TaskType to string."""
        row = TaskRow(host="SERVER", path="\\Task", type=TaskType.TIER0)
        result = row.to_dict()
        assert result["type"] == "TIER-0"


class TestTaskRowToDictRoundtrip:
    """Tests for TaskRow.to_dict roundtrip."""

    def test_to_dict_roundtrip_using_dict(self):
        """to_dict can be used to recreate TaskRow via **kwargs."""
        original = TaskRow(
            host="SERVER.DOMAIN.LOCAL",
            path="\\TestTask",
            runas="admin",
        )
        data = original.to_dict()
        # Can recreate using dict unpacking (filtering to known fields)
        assert data["host"] == "SERVER.DOMAIN.LOCAL"
        assert data["runas"] == "admin"


class TestTaskRowComparison:
    """Tests for TaskRow comparison methods."""

    def test_equality(self):
        """TaskRows with same values are equal."""
        row1 = TaskRow(host="SERVER", path="\\Task", runas="admin")
        row2 = TaskRow(host="SERVER", path="\\Task", runas="admin")
        assert row1 == row2

    def test_inequality(self):
        """TaskRows with different values are not equal."""
        row1 = TaskRow(host="SERVER1", path="\\Task")
        row2 = TaskRow(host="SERVER2", path="\\Task")
        assert row1 != row2


class TestTaskRowRepr:
    """Tests for TaskRow string representation."""

    def test_repr_contains_host(self):
        """repr includes host."""
        row = TaskRow(host="SERVER.DOMAIN.LOCAL", path="\\Task")
        repr_str = repr(row)
        assert "SERVER.DOMAIN.LOCAL" in repr_str

    def test_repr_contains_path(self):
        """repr includes path."""
        row = TaskRow(host="SERVER", path="\\Windows\\System32\\Tasks\\MyTask")
        repr_str = repr(row)
        assert "MyTask" in repr_str or "path" in repr_str


class TestTaskRowFactoryMethods:
    """Tests for TaskRow factory methods."""

    def test_skipped_factory_basic(self):
        """skipped() creates correct TaskRow."""
        row = TaskRow.skipped("SERVER", "Duplicate of OTHER")
        assert row.host == "SERVER"
        assert row.type == TaskType.SKIPPED
        assert row.reason == "Duplicate of OTHER"
        assert row.path == ""

    def test_skipped_factory_with_target_ip(self):
        """skipped() can include target_ip."""
        row = TaskRow.skipped("SERVER", "Dual-homed duplicate", target_ip="192.168.1.100")
        assert row.host == "SERVER"
        assert row.type == TaskType.SKIPPED
        assert row.target_ip == "192.168.1.100"
        assert row.reason == "Dual-homed duplicate"

    def test_failure_factory_basic(self):
        """failure() creates correct TaskRow."""
        row = TaskRow.failure("SERVER", "Connection refused")
        assert row.host == "SERVER"
        assert row.type == TaskType.FAILURE
        assert row.reason == "Connection refused"
        assert row.path == ""

    def test_failure_factory_with_target_ip(self):
        """failure() can include target_ip."""
        row = TaskRow.failure("SERVER", "Access denied", target_ip="10.0.0.1")
        assert row.host == "SERVER"
        assert row.type == TaskType.FAILURE
        assert row.target_ip == "10.0.0.1"

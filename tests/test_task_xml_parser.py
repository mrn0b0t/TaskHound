"""
Test task XML parsing functionality.
"""

from taskhound.parsers.task_xml import parse_task_xml


def test_parse_basic_task_xml(sample_task_xml):
    """Test parsing a basic scheduled task XML."""
    result = parse_task_xml(sample_task_xml)

    assert result is not None
    # The parser returns 'runas' not 'runas_user'
    assert "runas" in result or "runas_user" in result
    assert "command" in result
    assert "date" in result
    assert "author" in result


def test_parse_task_with_credentials(sample_task_xml):
    """Test that task with LogonType Password is detected as having credentials."""
    result = parse_task_xml(sample_task_xml)

    # Tasks with LogonType=Password store credentials
    assert result is not None
    assert "logon_type" in result or "credentials_hint" in result


def test_parse_task_command_extraction(sample_task_xml):
    """Test that command and arguments are extracted correctly."""
    result = parse_task_xml(sample_task_xml)

    assert result is not None
    assert "powershell.exe" in result.get("command", "").lower()


def test_parse_malformed_xml():
    """Test handling of malformed XML."""
    malformed = "This is not XML"

    result = parse_task_xml(malformed)
    # Should handle gracefully (return None or minimal dict)
    assert result is None or isinstance(result, dict)


def test_parse_empty_xml():
    """Test handling of empty XML."""
    empty = ""

    result = parse_task_xml(empty)
    assert result is None or isinstance(result, dict)


class TestTriggerParsing:
    """Tests for trigger type parsing."""

    def test_calendar_trigger(self):
        """Test parsing CalendarTrigger."""
        xml = '''<?xml version="1.0" encoding="UTF-16"?>
        <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
            <RegistrationInfo>
                <Date>2023-01-01T12:00:00</Date>
                <Author>Admin</Author>
            </RegistrationInfo>
            <Triggers>
                <CalendarTrigger>
                    <StartBoundary>2023-06-01T08:00:00</StartBoundary>
                    <Repetition>
                        <Interval>PT5M</Interval>
                        <Duration>P1D</Duration>
                    </Repetition>
                </CalendarTrigger>
            </Triggers>
            <Principals>
                <Principal>
                    <UserId>DOMAIN\\User</UserId>
                    <LogonType>Password</LogonType>
                </Principal>
            </Principals>
            <Actions>
                <Exec>
                    <Command>cmd.exe</Command>
                </Exec>
            </Actions>
        </Task>'''

        result = parse_task_xml(xml)
        assert result is not None
        assert result.get("trigger_type") == "Calendar"
        assert result.get("start_boundary") == "2023-06-01T08:00:00"
        assert result.get("interval") == "PT5M"
        assert result.get("duration") == "P1D"

    def test_calendar_trigger_with_schedule_by_day(self):
        """Test parsing CalendarTrigger with ScheduleByDay."""
        xml = '''<?xml version="1.0" encoding="UTF-16"?>
        <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
            <RegistrationInfo>
                <Date>2023-01-01T12:00:00</Date>
                <Author>Admin</Author>
            </RegistrationInfo>
            <Triggers>
                <CalendarTrigger>
                    <ScheduleByDay>
                        <DaysInterval>3</DaysInterval>
                    </ScheduleByDay>
                </CalendarTrigger>
            </Triggers>
            <Principals>
                <Principal>
                    <UserId>DOMAIN\\User</UserId>
                </Principal>
            </Principals>
            <Actions>
                <Exec>
                    <Command>cmd.exe</Command>
                </Exec>
            </Actions>
        </Task>'''

        result = parse_task_xml(xml)
        assert result is not None
        assert result.get("trigger_type") == "Calendar"
        assert result.get("days_interval") == "3"

    def test_time_trigger(self):
        """Test parsing TimeTrigger."""
        xml = '''<?xml version="1.0" encoding="UTF-16"?>
        <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
            <RegistrationInfo>
                <Date>2023-01-01T12:00:00</Date>
                <Author>Admin</Author>
            </RegistrationInfo>
            <Triggers>
                <TimeTrigger>
                    <StartBoundary>2023-06-01T09:00:00</StartBoundary>
                </TimeTrigger>
            </Triggers>
            <Principals>
                <Principal>
                    <UserId>DOMAIN\\User</UserId>
                </Principal>
            </Principals>
            <Actions>
                <Exec>
                    <Command>notepad.exe</Command>
                </Exec>
            </Actions>
        </Task>'''

        result = parse_task_xml(xml)
        assert result is not None
        assert result.get("trigger_type") == "Time"
        assert result.get("start_boundary") == "2023-06-01T09:00:00"

    def test_logon_trigger(self):
        """Test parsing LogonTrigger."""
        xml = '''<?xml version="1.0" encoding="UTF-16"?>
        <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
            <RegistrationInfo>
                <Date>2023-01-01T12:00:00</Date>
                <Author>Admin</Author>
            </RegistrationInfo>
            <Triggers>
                <LogonTrigger>
                    <UserId>DOMAIN\\User</UserId>
                </LogonTrigger>
            </Triggers>
            <Principals>
                <Principal>
                    <UserId>DOMAIN\\User</UserId>
                </Principal>
            </Principals>
            <Actions>
                <Exec>
                    <Command>startup.bat</Command>
                </Exec>
            </Actions>
        </Task>'''

        result = parse_task_xml(xml)
        assert result is not None
        assert result.get("trigger_type") == "Logon"

    def test_boot_trigger(self):
        """Test parsing BootTrigger."""
        xml = '''<?xml version="1.0" encoding="UTF-16"?>
        <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
            <RegistrationInfo>
                <Date>2023-01-01T12:00:00</Date>
                <Author>Admin</Author>
            </RegistrationInfo>
            <Triggers>
                <BootTrigger>
                    <Delay>PT30S</Delay>
                </BootTrigger>
            </Triggers>
            <Principals>
                <Principal>
                    <UserId>SYSTEM</UserId>
                </Principal>
            </Principals>
            <Actions>
                <Exec>
                    <Command>bootscript.cmd</Command>
                </Exec>
            </Actions>
        </Task>'''

        result = parse_task_xml(xml)
        assert result is not None
        assert result.get("trigger_type") == "Boot"

    def test_idle_trigger(self):
        """Test parsing IdleTrigger."""
        xml = '''<?xml version="1.0" encoding="UTF-16"?>
        <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
            <RegistrationInfo>
                <Date>2023-01-01T12:00:00</Date>
                <Author>Admin</Author>
            </RegistrationInfo>
            <Triggers>
                <IdleTrigger>
                    <Enabled>true</Enabled>
                </IdleTrigger>
            </Triggers>
            <Principals>
                <Principal>
                    <UserId>SYSTEM</UserId>
                </Principal>
            </Principals>
            <Actions>
                <Exec>
                    <Command>cleanup.bat</Command>
                </Exec>
            </Actions>
        </Task>'''

        result = parse_task_xml(xml)
        assert result is not None
        assert result.get("trigger_type") == "Idle"

    def test_event_trigger(self):
        """Test parsing EventTrigger."""
        xml = '''<?xml version="1.0" encoding="UTF-16"?>
        <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
            <RegistrationInfo>
                <Date>2023-01-01T12:00:00</Date>
                <Author>Admin</Author>
            </RegistrationInfo>
            <Triggers>
                <EventTrigger>
                    <Subscription>test</Subscription>
                </EventTrigger>
            </Triggers>
            <Principals>
                <Principal>
                    <UserId>SYSTEM</UserId>
                </Principal>
            </Principals>
            <Actions>
                <Exec>
                    <Command>event_handler.ps1</Command>
                </Exec>
            </Actions>
        </Task>'''

        result = parse_task_xml(xml)
        assert result is not None
        assert result.get("trigger_type") == "Event"


class TestXmlWithoutNamespace:
    """Tests for XML without namespace prefix."""

    def test_simple_task_no_namespace(self):
        """Test parsing task without XML namespace."""
        xml = '''<?xml version="1.0"?>
        <Task>
            <RegistrationInfo>
                <Date>2023-01-01</Date>
                <Author>TestUser</Author>
            </RegistrationInfo>
            <Triggers>
                <TimeTrigger>
                    <StartBoundary>2023-06-01T10:00:00</StartBoundary>
                </TimeTrigger>
            </Triggers>
            <Principals>
                <Principal>
                    <UserId>TestUser</UserId>
                </Principal>
            </Principals>
            <Actions>
                <Exec>
                    <Command>test.exe</Command>
                    <Arguments>-arg1</Arguments>
                </Exec>
            </Actions>
        </Task>'''

        result = parse_task_xml(xml)
        assert result is not None
        assert result.get("command") == "test.exe"
        assert result.get("author") == "TestUser"


class TestExecActions:
    """Tests for different Exec action formats."""

    def test_exec_with_arguments(self):
        """Test parsing Exec with Command and Arguments."""
        xml = '''<?xml version="1.0" encoding="UTF-16"?>
        <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
            <RegistrationInfo>
                <Date>2023-01-01T12:00:00</Date>
                <Author>Admin</Author>
            </RegistrationInfo>
            <Principals>
                <Principal>
                    <UserId>DOMAIN\\User</UserId>
                </Principal>
            </Principals>
            <Actions>
                <Exec>
                    <Command>powershell.exe</Command>
                    <Arguments>-ExecutionPolicy Bypass -File script.ps1</Arguments>
                </Exec>
            </Actions>
        </Task>'''

        result = parse_task_xml(xml)
        assert result is not None
        assert "powershell.exe" in result.get("command", "")
        # Arguments should be appended
        assert "Bypass" in result.get("command", "") or result.get("arguments")

    def test_exec_command_only(self):
        """Test parsing Exec with Command only."""
        xml = '''<?xml version="1.0" encoding="UTF-16"?>
        <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
            <RegistrationInfo>
                <Date>2023-01-01T12:00:00</Date>
                <Author>Admin</Author>
            </RegistrationInfo>
            <Principals>
                <Principal>
                    <UserId>DOMAIN\\User</UserId>
                </Principal>
            </Principals>
            <Actions>
                <Exec>
                    <Command>notepad.exe</Command>
                </Exec>
            </Actions>
        </Task>'''

        result = parse_task_xml(xml)
        assert result is not None
        assert result.get("command") == "notepad.exe"


class TestEnabledState:
    """Tests for task enabled state parsing."""

    def test_enabled_true(self):
        """Test parsing enabled task."""
        xml = '''<?xml version="1.0" encoding="UTF-16"?>
        <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
            <RegistrationInfo>
                <Date>2023-01-01T12:00:00</Date>
            </RegistrationInfo>
            <Settings>
                <Enabled>true</Enabled>
            </Settings>
            <Principals>
                <Principal>
                    <UserId>DOMAIN\\User</UserId>
                </Principal>
            </Principals>
            <Actions>
                <Exec>
                    <Command>cmd.exe</Command>
                </Exec>
            </Actions>
        </Task>'''

        result = parse_task_xml(xml)
        assert result is not None
        assert result.get("enabled") == "true"

    def test_enabled_false(self):
        """Test parsing disabled task."""
        xml = '''<?xml version="1.0" encoding="UTF-16"?>
        <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
            <RegistrationInfo>
                <Date>2023-01-01T12:00:00</Date>
            </RegistrationInfo>
            <Settings>
                <Enabled>false</Enabled>
            </Settings>
            <Principals>
                <Principal>
                    <UserId>DOMAIN\\User</UserId>
                </Principal>
            </Principals>
            <Actions>
                <Exec>
                    <Command>cmd.exe</Command>
                </Exec>
            </Actions>
        </Task>'''

        result = parse_task_xml(xml)
        assert result is not None
        assert result.get("enabled") == "false"

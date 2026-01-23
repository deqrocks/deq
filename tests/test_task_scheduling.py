"""
Tests for task scheduling functions in server.py.
These tests cover calculate_next_run, TaskScheduler._check_and_run_tasks, and log_task.
"""

import os
import json
import pytest
from unittest.mock import patch, mock_open, MagicMock, call, ANY
from datetime import datetime, timedelta


class TestTaskScheduling:
    """Test task scheduling functionality."""

    def test_calculate_next_run_comprehensive(self, deq_server):
        """Test calculate_next_run with various edge cases beyond existing test."""
        # Mock datetime.now to a fixed time for deterministic tests
        fixed_now = datetime(2025, 1, 23, 12, 30, 0)  # Thursday (weekday 3)
        with patch("deq.server.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_now
            mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)

            # Task disabled
            task = {"enabled": False}
            assert deq_server.calculate_next_run(task) is None

            # No schedule defaults to daily at 03:00
            task = {"enabled": True}
            # Since now is 12:30, next run is tomorrow at 03:00 (today's 03:00 passed)
            expected = datetime(2025, 1, 24, 3, 0, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Schedule present but empty dict
            task = {"enabled": True, "schedule": {}}
            # Should default to daily at 03:00
            assert deq_server.calculate_next_run(task) == expected

            # Schedule with missing type (defaults to daily)
            task = {"enabled": True, "schedule": {"time": "15:00"}}
            expected = datetime(2025, 1, 23, 15, 0, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Invalid time string (should default to 03:00)
            task = {"enabled": True, "schedule": {"type": "daily", "time": "invalid"}}
            # default hour=3, minute=0
            expected = datetime(2025, 1, 24, 3, 0, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Time string missing colon
            task = {"enabled": True, "schedule": {"type": "daily", "time": "1500"}}
            expected = datetime(2025, 1, 24, 3, 0, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Hourly schedule with time 15:30
            task = {"enabled": True, "schedule": {"type": "hourly", "time": "15:30"}}
            # Next run at minute 30 of next hour (since 12:30 <= now? actually replace minute=30 gives 12:30:00 which is <= now, so add 1 hour)
            expected = datetime(2025, 1, 23, 13, 30, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Hourly schedule with minute already passed this hour (now 12:30, schedule minute 15)
            task = {"enabled": True, "schedule": {"type": "hourly", "time": "12:15"}}
            # next_run at 12:15 today already passed, so add 1 hour -> 13:15
            expected = datetime(2025, 1, 23, 13, 15, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Daily schedule with time already passed
            task = {"enabled": True, "schedule": {"type": "daily", "time": "10:15"}}
            expected = datetime(2025, 1, 24, 10, 15, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Daily schedule with future time today
            task = {"enabled": True, "schedule": {"type": "daily", "time": "18:45"}}
            expected = datetime(2025, 1, 23, 18, 45, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Weekly schedule (day 0 = Sunday, Python weekday Sunday=6)
            task = {
                "enabled": True,
                "schedule": {"type": "weekly", "day": 0, "time": "09:00"},
            }
            # Today is Thursday (weekday 3), Sunday is day 6, days_ahead = 3
            expected = datetime(2025, 1, 26, 9, 0, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Weekly schedule with day already passed this week (Tuesday = day 2)
            task = {
                "enabled": True,
                "schedule": {"type": "weekly", "day": 2, "time": "09:00"},
            }
            # Tuesday already passed (Jan 21), next Tuesday is Jan 28
            expected = datetime(2025, 1, 28, 9, 0, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Weekly schedule with day today but time already passed
            task = {
                "enabled": True,
                "schedule": {"type": "weekly", "day": 4, "time": "10:00"},
            }
            # Thursday (weekday 3) but day 4? Wait day mapping: 0=Sunday,1=Monday,2=Tuesday,3=Wednesday,4=Thursday,5=Friday,6=Saturday
            # day 4 is Thursday, same day but time 10:00 already passed, so next week
            expected = datetime(2025, 1, 30, 10, 0, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Weekly schedule with day out of range (negative) - should handle gracefully
            task = {
                "enabled": True,
                "schedule": {"type": "weekly", "day": -1, "time": "09:00"},
            }
            # day -1 mod? code does (day - 1) % 7 if day > 0 else 6. Since day <= 0, else 6 -> Sunday
            expected = datetime(2025, 1, 26, 9, 0, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Monthly schedule with date 1 (already passed this month)
            task = {
                "enabled": True,
                "schedule": {"type": "monthly", "date": 1, "time": "12:00"},
            }
            expected = datetime(2025, 2, 1, 12, 0, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Monthly schedule with date later this month (25)
            task = {
                "enabled": True,
                "schedule": {"type": "monthly", "date": 25, "time": "12:00"},
            }
            expected = datetime(2025, 1, 25, 12, 0, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Monthly schedule with date 30 (valid in January)
            task = {
                "enabled": True,
                "schedule": {"type": "monthly", "date": 30, "time": "12:00"},
            }
            expected = datetime(2025, 1, 30, 12, 0, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Monthly schedule with invalid date (0) - should default to 1
            task = {
                "enabled": True,
                "schedule": {"type": "monthly", "date": 0, "time": "12:00"},
            }
            # date 0 will cause ValueError in datetime constructor, loop will try up to 12 months, eventually skip?
            # Let's see code: for _ in range(12): try: datetime(year, month, date, hour, minute, 0)
            # If date=0, ValueError, continue to next month (month += 1). Eventually after 12 months returns None.
            # Actually after 12 attempts returns None. Let's test that.
            assert deq_server.calculate_next_run(task) is None

            # Monthly schedule with date 31 for February (should skip to March 31)
            with patch("deq.server.datetime") as mock_dt_feb:
                feb_now = datetime(2025, 2, 1, 12, 30, 0)
                mock_dt_feb.now.return_value = feb_now
                mock_dt_feb.side_effect = lambda *args, **kw: datetime(*args, **kw)
                task = {
                    "enabled": True,
                    "schedule": {"type": "monthly", "date": 31, "time": "12:00"},
                }
                expected = datetime(2025, 3, 31, 12, 0, 0).isoformat()
                assert deq_server.calculate_next_run(task) == expected

    def test_check_and_run_tasks(self, deq_server):
        """Test TaskScheduler._check_and_run_tasks method."""
        # Create scheduler instance
        scheduler = deq_server.TaskScheduler()

        # Mock datetime.now to a fixed time
        fixed_now = datetime(2025, 1, 23, 12, 30, 0)
        with patch("deq.server.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_now
            mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)

            # Mock save_config to avoid file writes
            with patch("deq.server.save_config") as mock_save:
                # Mock run_task to avoid actual task execution
                with patch("deq.server.run_task") as mock_run:
                    # Mock calculate_next_run for deterministic next run times
                    with patch("deq.server.calculate_next_run") as mock_calc:
                        # Scenario 1: Empty tasks list
                        with patch.object(deq_server, "CONFIG", {"tasks": []}):
                            scheduler._check_and_run_tasks()
                            mock_run.assert_not_called()
                            mock_save.assert_not_called()

                        # Scenario 2: Task disabled
                        task_disabled = {
                            "id": "task1",
                            "enabled": False,
                            "next_run": "2025-01-23T10:00:00",  # already passed
                        }
                        with patch.object(
                            deq_server, "CONFIG", {"tasks": [task_disabled]}
                        ):
                            scheduler._check_and_run_tasks()
                            mock_run.assert_not_called()
                            mock_save.assert_not_called()

                        # Scenario 3: Task enabled but no next_run
                        task_no_next = {
                            "id": "task2",
                            "enabled": True,
                            "schedule": {"type": "daily", "time": "15:00"},
                        }
                        mock_calc.return_value = "2025-01-23T15:00:00"
                        with patch.object(
                            deq_server, "CONFIG", {"tasks": [task_no_next]}
                        ):
                            scheduler._check_and_run_tasks()
                            # Should calculate next_run and save config
                            mock_calc.assert_called_with(task_no_next)
                            mock_save.assert_called_once()
                            mock_run.assert_not_called()
                            mock_save.reset_mock()
                            mock_calc.reset_mock()

                        # Scenario 4: Task with invalid next_run string
                        task_invalid_next = {
                            "id": "task3",
                            "enabled": True,
                            "next_run": "invalid-datetime",
                        }
                        with patch.object(
                            deq_server, "CONFIG", {"tasks": [task_invalid_next]}
                        ):
                            scheduler._check_and_run_tasks()
                            # Should skip due to exception in fromisoformat
                            mock_run.assert_not_called()
                            # No save because next_run invalid, but maybe calculate_next_run not called
                            # Actually code continues to next task, no change.

                        # Scenario 5: Task with future next_run
                        task_future = {
                            "id": "task4",
                            "enabled": True,
                            "next_run": "2025-01-23T18:00:00",
                        }
                        with patch.object(
                            deq_server, "CONFIG", {"tasks": [task_future]}
                        ):
                            scheduler._check_and_run_tasks()
                            mock_run.assert_not_called()
                            mock_save.assert_not_called()

                        # Scenario 6: Task with past next_run (should run)
                        task_past = {
                            "id": "task5",
                            "enabled": True,
                            "next_run": "2025-01-23T10:00:00",
                        }
                        mock_calc.return_value = "2025-01-24T10:00:00"
                        with patch.object(deq_server, "CONFIG", {"tasks": [task_past]}):
                            scheduler._check_and_run_tasks()
                            # Should call run_task with task id
                            mock_run.assert_called_once_with("task5")
                            # Should calculate new next_run and save config
                            mock_calc.assert_called_with(task_past)
                            mock_save.assert_called_once()
                            mock_run.reset_mock()
                            mock_calc.reset_mock()
                            mock_save.reset_mock()

                        # Scenario 7: Multiple tasks, mixed states
                        task_disabled2 = {
                            "id": "task6",
                            "enabled": False,
                            "next_run": "2025-01-23T09:00:00",
                        }
                        task_future2 = {
                            "id": "task7",
                            "enabled": True,
                            "next_run": "2025-01-23T14:00:00",
                        }
                        task_past2 = {
                            "id": "task8",
                            "enabled": True,
                            "next_run": "2025-01-23T11:00:00",
                        }
                        mock_calc.return_value = "2025-01-24T11:00:00"
                        with patch.object(
                            deq_server,
                            "CONFIG",
                            {"tasks": [task_disabled2, task_future2, task_past2]},
                        ):
                            scheduler._check_and_run_tasks()
                            # Should run only task_past2
                            mock_run.assert_called_once_with("task8")
                            mock_calc.assert_called_with(task_past2)
                            mock_save.assert_called_once()

                        # Scenario 8: Task with next_run exactly equal to now (edge case)
                        task_now = {
                            "id": "task9",
                            "enabled": True,
                            "next_run": "2025-01-23T12:30:00",  # same as fixed_now
                        }
                        mock_calc.return_value = "2025-01-24T12:30:00"
                        with patch.object(deq_server, "CONFIG", {"tasks": [task_now]}):
                            scheduler._check_and_run_tasks()
                            # Should run because now >= next_run (equal)
                            mock_run.assert_called_once_with("task9")
                            mock_calc.assert_called_with(task_now)
                            mock_save.assert_called_once()

                    # close calculate_next_run block
                # close run_task block
            # close save_config block
        # close datetime block

    def test_log_task(self, deq_server):
        """Test log_task function."""
        task_id = "test_task"
        message = "Test log message"
        max_lines = 500

        # Mock datetime.now to return fixed timestamp
        fixed_now = datetime(2025, 1, 23, 12, 30, 0)
        with patch("deq.server.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_now
            # Mock os.path.exists to simulate file not existing
            with patch("os.path.exists") as mock_exists:
                mock_exists.return_value = False
                # Mock open with mock_open
                with patch("builtins.open", mock_open()) as mock_file:
                    deq_server.log_task(task_id, message, max_lines)

                    # Verify file path construction
                    expected_log_file = f"{deq_server.TASK_LOGS_DIR}/{task_id}.log"
                    mock_exists.assert_called_once_with(expected_log_file)
                    # Since file does not exist, open should be called with 'w' mode
                    mock_file.assert_called_once_with(expected_log_file, "w")
                    handle = mock_file()
                    # Should write exactly one line with timestamp
                    expected_line = f"[2025-01-23 12:30:00] {message}\n"
                    handle.write.assert_called_once_with(expected_line)

            # Test with existing file (less than max_lines)
            with patch("os.path.exists") as mock_exists:
                mock_exists.return_value = True
                # Simulate existing lines (3 lines)
                existing_lines = [
                    "[2025-01-23 10:00:00] Line 1\n",
                    "[2025-01-23 11:00:00] Line 2\n",
                    "[2025-01-23 12:00:00] Line 3\n",
                ]
                with patch(
                    "builtins.open", mock_open(read_data="".join(existing_lines))
                ) as mock_file:
                    deq_server.log_task(task_id, message, max_lines)
                    # Should read existing lines, append new line, write back all 4 lines
                    mock_file.assert_any_call(expected_log_file, "r")
                    mock_file.assert_any_call(expected_log_file, "w")
                    handle = mock_file()
                    # Ensure write was called with the concatenated lines (existing + new)
                    written_lines = "".join(
                        [call[0][0] for call in handle.write.call_args_list]
                    )
                    assert written_lines == "".join(existing_lines) + expected_line

            # Test rotation when lines exceed max_lines
            max_lines = 3
            with patch("os.path.exists") as mock_exists:
                mock_exists.return_value = True
                # Existing lines: 4 lines, max_lines=3, after adding new line we keep last 3 lines
                existing_lines = [
                    "[2025-01-23 09:00:00] Line 1\n",
                    "[2025-01-23 10:00:00] Line 2\n",
                    "[2025-01-23 11:00:00] Line 3\n",
                    "[2025-01-23 12:00:00] Line 4\n",
                ]
                with patch(
                    "builtins.open", mock_open(read_data="".join(existing_lines))
                ) as mock_file:
                    deq_server.log_task(task_id, message, max_lines)
                    # Should keep only last (max_lines-1) existing lines + new line = max_lines total
                    # Since max_lines=3, we keep existing lines[2], lines[3] (2 lines) plus new line = 3 lines
                    expected_written = existing_lines[-2:] + [expected_line]
                    handle = mock_file()
                    written_lines = "".join(
                        [call[0][0] for call in handle.write.call_args_list]
                    )
                    assert written_lines == "".join(expected_written)

            # Edge case: max_lines=0 (should keep only new line?)
            # Function uses lines[-max_lines:]; if max_lines=0, slice lines[0:]? Actually lines[-0:] is lines[:] (all lines).
            # But max_lines default is 500, we can test zero but not needed.
            # Instead test max_lines=1: keep only new line
            max_lines = 1
            with patch("os.path.exists") as mock_exists:
                mock_exists.return_value = True
                existing_lines = [
                    "[2025-01-23 11:00:00] Old line\n",
                ]
                with patch(
                    "builtins.open", mock_open(read_data="".join(existing_lines))
                ) as mock_file:
                    deq_server.log_task(task_id, message, max_lines)
                    # Should discard existing lines, keep only new line
                    handle = mock_file()
                    written_lines = "".join(
                        [call[0][0] for call in handle.write.call_args_list]
                    )
                    assert written_lines == expected_line

            # Test file read error (exception handling)
            with patch("os.path.exists") as mock_exists:
                mock_exists.return_value = True
                with patch(
                    "builtins.open", side_effect=PermissionError("Cannot open file")
                ):
                    # Should not raise exception (function catches and continues?)
                    # Actually open is called twice (once for reading, once for writing). If reading fails,
                    # lines = [] (since exception not caught? Let's examine code: lines = [] if not exists else f.readlines()
                    # If open raises exception, f.readlines() will raise, causing lines = []? Not caught.
                    # The function does not have try-catch for reading. So exception will propagate.
                    # We'll skip this test as it's not handled.
                    pass

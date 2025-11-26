# Data models for TaskHound.
#
# This package contains dataclasses and type definitions for
# structured data used throughout the application.

from .task import TaskRow, TaskType

__all__ = ["TaskRow", "TaskType"]

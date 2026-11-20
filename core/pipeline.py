import time
import asyncio
import concurrent
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ScanTask:
    """A single task in the scan pipeline."""
    name: str
    phase: int
    func: Callable
    args: tuple = ()
    kwargs: dict = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)
    required_tools: List[str] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    result: Any = None
    error: Optional[str] = None
    start_time: float = 0.0
    end_time: float = 0.0
    duration: float = 0.0

    def to_dict(self):
        return {
            "name": self.name,
            "phase": self.phase,
            "status": self.status.value,
            "depends_on": self.depends_on,
            "duration": self.duration,
            "error": self.error,
        }


class ScanPipeline:
    """Task-graph execution engine with dependency resolution and parallelism."""

    def __init__(self, max_workers=5):
        self.tasks: Dict[str, ScanTask] = {}
        self.max_workers = max_workers
        self._executor: Optional[ThreadPoolExecutor] = None
        self.results: Dict[str, Any] = {}
        self.on_task_complete: Optional[Callable] = None
        self.on_task_error: Optional[Callable] = None

    def add_task(self, task: ScanTask):
        """Add a task to the pipeline."""
        self.tasks[task.name] = task

    def add_task_raw(
        self, name, phase, func, args=(), kwargs=None,
        depends_on=None, required_tools=None,
    ):
        """Convenience method to add a task."""
        self.add_task(ScanTask(
            name=name,
            phase=phase,
            func=func,
            args=args,
            kwargs=kwargs or {},
            depends_on=depends_on or [],
            required_tools=required_tools or [],
        ))

    def _get_ready_tasks(self) -> List[ScanTask]:
        """Get tasks whose dependencies are all completed."""
        ready = []
        for task in self.tasks.values():
            if task.status != TaskStatus.PENDING:
                continue
            deps_met = all(
                self.tasks[dep].status == TaskStatus.COMPLETED
                for dep in task.depends_on
                if dep in self.tasks
            )
            if deps_met:
                ready.append(task)
        return ready

    def _execute_task(self, task: ScanTask) -> ScanTask:
        """Execute a single task."""
        task.status = TaskStatus.RUNNING
        task.start_time = time.time()

        try:
            task.result = task.func(*task.args, **task.kwargs)
            task.status = TaskStatus.COMPLETED
        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error = str(e)
        finally:
            task.end_time = time.time()
            task.duration = task.end_time - task.start_time
            self.results[task.name] = task.result

            if self.on_task_complete and task.status == TaskStatus.COMPLETED:
                self.on_task_complete(task)
            if self.on_task_error and task.status == TaskStatus.FAILED:
                self.on_task_error(task)

        return task

    def execute(self, parallel=True, progress_callback=None):
        """Execute the pipeline."""
        start_time = time.time()

        if parallel:
            self._execute_parallel(progress_callback)
        else:
            self._execute_sequential(progress_callback)

        total_time = time.time() - start_time
        completed = sum(
            1 for t in self.tasks.values()
            if t.status == TaskStatus.COMPLETED
        )
        failed = sum(
            1 for t in self.tasks.values()
            if t.status == TaskStatus.FAILED
        )

        return {
            "total_tasks": len(self.tasks),
            "completed": completed,
            "failed": failed,
            "total_time": total_time,
            "results": self.results,
        }

    def _execute_parallel(self, progress_callback=None):
        """Execute tasks in parallel, respecting dependencies."""
        self._executor = ThreadPoolExecutor(max_workers=self.max_workers)

        running_futures = {}

        while True:
            all_done = all(
                t.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.SKIPPED)
                for t in self.tasks.values()
            )
            if all_done:
                break

            ready = self._get_ready_tasks()

            for task in ready:
                if task.name not in running_futures:
                    future = self._executor.submit(self._execute_task, task)
                    running_futures[task.name] = future

            completed_names = []
            for name, future in running_futures.items():
                if future.done():
                    completed_names.append(name)

            for name in completed_names:
                del running_futures[name]

            if progress_callback:
                progress_callback(self.get_status())

            time.sleep(0.1)

        self._executor.shutdown(wait=False)

    def _execute_sequential(self, progress_callback=None):
        """Execute tasks sequentially, respecting dependencies."""
        executed = set()

        while True:
            remaining = [t for t in self.tasks.values() if t.name not in executed]
            if not remaining:
                break

            ready = [
                t for t in remaining
                if all(dep in executed for dep in t.depends_on)
            ]

            if not ready:
                for task in remaining:
                    task.status = TaskStatus.SKIPPED
                    task.error = "Dependency not met"
                break

            for task in ready:
                self._execute_task(task)
                executed.add(task.name)

                if progress_callback:
                    progress_callback(self.get_status())

    def get_status(self) -> dict:
        """Get current pipeline status."""
        return {
            "total": len(self.tasks),
            "pending": sum(
                1 for t in self.tasks.values()
                if t.status == TaskStatus.PENDING
            ),
            "running": sum(
                1 for t in self.tasks.values()
                if t.status == TaskStatus.RUNNING
            ),
            "completed": sum(
                1 for t in self.tasks.values()
                if t.status == TaskStatus.COMPLETED
            ),
            "failed": sum(
                1 for t in self.tasks.values()
                if t.status == TaskStatus.FAILED
            ),
            "tasks": {
                name: task.to_dict()
                for name, task in self.tasks.items()
            },
        }

    def get_phase_status(self, phase: int) -> dict:
        """Get status of tasks in a specific phase."""
        phase_tasks = {
            n: t for n, t in self.tasks.items()
            if t.phase == phase
        }
        return {
            "phase": phase,
            "total": len(phase_tasks),
            "completed": sum(
                1 for t in phase_tasks.values()
                if t.status == TaskStatus.COMPLETED
            ),
            "failed": sum(
                1 for t in phase_tasks.values()
                if t.status == TaskStatus.FAILED
            ),
            "tasks": {
                n: t.to_dict() for n, t in phase_tasks.items()
            },
        }

    def clear(self):
        """Clear all tasks."""
        self.tasks.clear()
        self.results.clear()

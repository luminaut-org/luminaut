from rich.console import Console
from rich.progress import Progress

console = Console()


class TaskProgress:
    def __init__(
        self, task_progress: Progress | None = None, description: str = "", **kwargs
    ):
        self.task_progress = task_progress
        self.description = description
        self.task_id = None
        self.progress_kwargs = kwargs

    def __enter__(self):
        if self.task_progress:
            self.task_id = self.task_progress.add_task(
                description=self.description, **self.progress_kwargs
            )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.task_progress and self.task_id:
            self.task_progress.stop_task(self.task_id)

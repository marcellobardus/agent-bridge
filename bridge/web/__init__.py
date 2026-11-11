"""Human oversight dashboard: server-rendered Jinja2 pages under /app (no JavaScript, no external assets).
JSON routes under /app keep answering JSON; browsers (Accept: text/html) get HTML pages and 303 redirects."""
from fastapi import FastAPI, Request

from ..errors import Problem
from .render import html_problem, wants_html


def install(app: FastAPI) -> None:
    from .pages import router
    app.include_router(router)
    json_handler = app.exception_handlers[Problem]

    async def problem(request: Request, exc: Problem):
        path = request.url.path
        if path.startswith("/app") and not path.startswith("/app/api/") and wants_html(request):
            return html_problem(request, exc)
        return await json_handler(request, exc)

    app.add_exception_handler(Problem, problem)

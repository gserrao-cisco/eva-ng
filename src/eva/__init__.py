import logging
from typing import Optional

import typer
from dotenv import load_dotenv
from rich.logging import RichHandler
from typing_extensions import Annotated

import pkgutil
import importlib

import eva.vulns as vulns_pkg

modules = {}
for finder, name, ispkg in pkgutil.iter_modules(vulns_pkg.__path__):
    mod = importlib.import_module(f"{vulns_pkg.__name__}.{name}")
    modules[getattr(mod, "MODULE_NAME", None)] = mod

from eva.commands.generate import generate_app

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, omit_repeated_times=False)])

log = logging.getLogger('eva')

app = typer.Typer(context_settings={"help_option_names": ["-h", "--help"]}, no_args_is_help=True)
app.add_typer(generate_app, name="generate", help="Generate coverage")

load_dotenv()

app_state = {
    "temp": 0.0,
    "model": "gpt-4.1",
}

@app.callback()
def main(
        verbose: Annotated[Optional[bool], typer.Option("-v", "--verbose", help="Enable verbose output")] = False,
        temperature: Annotated[Optional[float], typer.Option("-t", "--temp", help="specify model temperature")] = 0.0,
        model: Annotated[Optional[str], typer.Option("-m", "--model", help="specify model")] = "gpt-4.1",
):
    """
    Eva Vulnerability Research Tools
    """

    if verbose:
        log.setLevel(logging.DEBUG)

    app_state["temp"] = temperature
    app_state["model"] = model

from eva.commands import list

if __name__ == "__main__":
    app()

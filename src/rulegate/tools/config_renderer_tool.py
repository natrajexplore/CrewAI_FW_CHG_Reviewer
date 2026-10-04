from rulegate.render import render
from rulegate.tools.base import ContextTool


class ConfigRendererTool(ContextTool):
    name: str = "config_renderer"
    description: str = ("Renders vendor-specific STAGED configuration (PAN-OS set commands or an FMC REST payload) "
                        "from Jinja2 templates, plus the pre/post-change test plan and rollback. Text only: nothing "
                        "is sent to any device.")

    def _run(self) -> str:
        return render(self.ctx).model_dump_json(indent=2)

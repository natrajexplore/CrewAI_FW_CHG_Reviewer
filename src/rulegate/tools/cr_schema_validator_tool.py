import json

from rulegate.tools.base import ContextTool


class CRSchemaValidatorTool(ContextTool):
    name: str = "cr_schema_validator"
    description: str = ("Returns the validated, vendor-neutral change request under review, the fields that are "
                        "missing for CAB approval, and any assumptions made while normalizing a free-text request.")

    def _run(self) -> str:
        cr = self.ctx.request
        return json.dumps({
            "normalized_request": cr.model_dump(mode="json"),
            "missing_fields": cr.missing_fields(),
            "assumptions": cr.assumptions,
        }, indent=2)

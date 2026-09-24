import json

from odoo import http
from odoo.fields import Domain
from odoo.http import Response, request, route
from odoo.tools.safe_eval import safe_eval


class AraRestApiController(http.Controller):
    def _response(self, payload, status=200):
        return Response(
            json.dumps(payload, default=str),
            status=status,
            content_type="application/json",
        )

    def _error(self, message, status=400, code="bad_request"):
        return self._response(
            {"success": False, "error": {"code": code, "message": message}}, status
        )

    def _auth(self):
        header = request.httprequest.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None, self._error(
                "Use Authorization: Bearer <token>.", 401, "missing_token"
            )
        raw_token = header[7:].strip()
        token = request.env["ara.rest.api.token"].authenticate_token(raw_token)
        if not token:
            return None, self._error("Token is invalid or expired.", 401, "invalid_token")
        return token, None

    def _model_context(self, token, model_name, permission):
        access = token.access_line_ids.filtered(
            lambda line: line.model_id.model == model_name
        )[:1]
        if not access or not getattr(access, f"can_{permission}"):
            return None, self._error(
                f"The token cannot {permission} model {model_name}.",
                403,
                "model_not_allowed",
            )
        try:
            model = request.env[model_name].with_user(token.user_id)
        except KeyError:
            return None, self._error("Model does not exist.", 404, "unknown_model")
        return (model, access), None

    def _fields(self, access, model, requested=None):
        try:
            if requested:
                names = [item.strip()
                         for item in requested.split(",") if item.strip()]
                available = set(model.fields_get().keys())
                invalid = set(names) - available
                if invalid:
                    raise ValueError(
                        f"Unknown field(s): {', '.join(sorted(invalid))}")
                configured = access.field_names(model)
                forbidden = set(names) - set(configured)
                if forbidden:
                    raise ValueError(
                        f"Field(s) not allowed by this token: {', '.join(sorted(forbidden))}"
                    )
                return names, None
            return access.field_names(model), None
        except Exception as error:
            return None, self._error(str(error), 400, "invalid_fields")

    def _requested_fields(self, access, model):
        requested = request.httprequest.args.get("fields")
        return self._fields(access, model, requested)

    def _request_domain(self, model, access, token):
        raw_domain = request.httprequest.args.get("domain", "[]")
        try:
            domain = json.loads(raw_domain)
            if not isinstance(domain, list):
                raise ValueError("domain must be a JSON list")
            Domain(domain).validate(model)
            return access.domain(model, token.user_id) + domain, None
        except Exception as error:
            return None, self._error(str(error), 400, "invalid_domain")

    @route("/api/v1/models", type="http", auth="none", methods=["GET"], csrf=False)
    def models(self, **kwargs):
        token, error = self._auth()
        if error:
            return error
        records = [
            {
                "model": line.model_id.model,
                "name": line.model_id.name,
                "permissions": {
                    "read": line.can_read,
                    "create": line.can_create,
                    "write": line.can_write,
                    "delete": line.can_delete,
                },
            }
            for line in token.access_line_ids
        ]
        return self._response({"success": True, "data": records})

    @route("/api/v1/<string:model_name>", type="http", auth="none", methods=["GET"], csrf=False)
    def list_records(self, model_name, **kwargs):
        token, error = self._auth()
        if error:
            return error
        result, error = self._model_context(token, model_name, "read")
        if error:
            return error
        model, access = result
        field_names, error = self._requested_fields(access, model)
        if error:
            return error
        domain, error = self._request_domain(model, access, token)
        if error:
            return error
        try:
            limit = min(
                max(int(request.httprequest.args.get("limit", 80)), 1), 200)
            offset = max(int(request.httprequest.args.get("offset", 0)), 0)
            order = request.httprequest.args.get("order", "id asc")
            records = model.search_read(
                domain, field_names, offset=offset, limit=limit, order=order)
            return self._response(
                {
                    "success": True,
                    "data": records,
                    "meta": {"count": len(records), "limit": limit, "offset": offset},
                }
            )
        except Exception as exc:
            return self._error(str(exc), 400, "query_failed")

    @route("/api/v1/<string:model_name>/<int:record_id>", type="http", auth="none", methods=["GET"], csrf=False)
    def get_record(self, model_name, record_id, **kwargs):
        token, error = self._auth()
        if error:
            return error
        result, error = self._model_context(token, model_name, "read")
        if error:
            return error
        model, access = result
        field_names, error = self._fields(access, model)
        if error:
            return error
        record = model.browse(record_id)
        if not record.exists():
            return self._error("Record not found.", 404, "not_found")
        return self._response({"success": True, "data": record.read(field_names)[0]})

    @route("/api/v1/<string:model_name>", type="http", auth="none", methods=["POST"], csrf=False)
    def create_record(self, model_name, **kwargs):
        return self._mutate(model_name, "create")

    @route("/api/v1/<string:model_name>/<int:record_id>", type="http", auth="none", methods=["PUT", "PATCH"], csrf=False)
    def update_record(self, model_name, record_id, **kwargs):
        return self._mutate(model_name, "write", record_id)

    @route("/api/v1/<string:model_name>/<int:record_id>", type="http", auth="none", methods=["DELETE"], csrf=False)
    def delete_record(self, model_name, record_id, **kwargs):
        return self._mutate(model_name, "delete", record_id)

    def _mutate(self, model_name, permission, record_id=None):
        token, error = self._auth()
        if error:
            return error
        result, error = self._model_context(token, model_name, permission)
        if error:
            return error
        model, access = result
        field_names, error = self._fields(access, model)
        if error:
            return error
        try:
            body = request.httprequest.get_json(silent=True) or {}
            if not isinstance(body, dict):
                return self._error("Request body must be a JSON object.", 400, "invalid_body")
            values = {key: value for key,
                      value in body.items() if key in field_names}
            if set(values) != set(body):
                return self._error("The body contains a field not allowed by this token.", 403, "field_not_allowed")
            if permission == "create":
                record = model.create(values)
                return self._response({"success": True, "data": record.read(field_names)[0]}, 201)
            record = model.browse(record_id)
            if not record.exists():
                return self._error("Record not found.", 404, "not_found")
            if permission == "write":
                record.write(values)
                return self._response({"success": True, "data": record.read(field_names)[0]})
            record.unlink()
            return self._response({"success": True, "data": {"id": record_id}})
        except Exception as exc:
            return self._error(str(exc), 400, "mutation_failed")

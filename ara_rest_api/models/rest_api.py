import hashlib
import secrets
from datetime import datetime

from odoo import _, api, fields, models
from odoo.exceptions import ValidationError
from odoo.fields import Domain
from odoo.tools.safe_eval import safe_eval


class RestApiToken(models.Model):
    _name = "ara.rest.api.token"
    _description = "REST API Token"
    _order = "name, id"

    name = fields.Char(required=True)
    active = fields.Boolean(default=True)
    user_id = fields.Many2one("res.users", required=True, ondelete="cascade")
    token_prefix = fields.Char(readonly=True, copy=False)
    token_hash = fields.Char(readonly=True, copy=False)
    expires_at = fields.Datetime(copy=False)
    last_used_at = fields.Datetime(readonly=True, copy=False)
    access_line_ids = fields.One2many(
        "ara.rest.api.access", "token_id", string="API Access"
    )
    token_count = fields.Integer(compute="_compute_token_count")

    @api.depends("access_line_ids")
    def _compute_token_count(self):
        for token in self:
            token.token_count = len(token.access_line_ids)

    @api.constrains("expires_at")
    def _check_expiry(self):
        for token in self:
            if token.expires_at and token.expires_at <= fields.Datetime.now():
                raise ValidationError(_("Expiry must be in the future."))

    def action_generate_token(self):
        self.ensure_one()
        raw_token = f"ara_{secrets.token_urlsafe(36)}"
        self.write(
            {
                "token_prefix": raw_token[:12],
                "token_hash": self._hash_token(raw_token),
            }
        )
        return {
            "type": "ir.actions.act_window",
            "name": _("New API Token"),
            "res_model": "ara.rest.api.token.wizard",
            "view_mode": "form",
            "target": "new",
            "context": {"default_token": raw_token, "default_token_id": self.id},
        }

    def action_revoke(self):
        self.ensure_one()
        self.write({"active": False})
        return True

    @staticmethod
    def _hash_token(raw_token):
        return hashlib.sha256(raw_token.encode()).hexdigest()

    @api.model
    def authenticate_token(self, raw_token):
        if not raw_token or not raw_token.startswith("ara_"):
            return self.browse()
        token = self.sudo().search(
            [("token_hash", "=", self._hash_token(raw_token)), ("active", "=", True)],
            limit=1,
        )
        if token.expires_at and token.expires_at <= fields.Datetime.now():
            return self.browse()
        if token:
            token.write({"last_used_at": fields.Datetime.now()})
        return token


class RestApiAccess(models.Model):
    _name = "ara.rest.api.access"
    _description = "REST API Model Access"
    _order = "model_id, id"

    token_id = fields.Many2one(
        "ara.rest.api.token", required=True, ondelete="cascade")
    model_id = fields.Many2one(
        "ir.model",
        required=True,
        ondelete="cascade",
        domain=[("transient", "=", False)],
    )
    allowed_fields = fields.Text(
        help="Comma-separated technical field names. Leave empty to allow all readable fields."
    )
    can_read = fields.Boolean(default=True)
    can_create = fields.Boolean()
    can_write = fields.Boolean()
    can_delete = fields.Boolean()
    domain_force = fields.Text(
        help="Optional Odoo domain evaluated with the API user's context."
    )

    _unique_token_model = models.Constraint(
        "UNIQUE(token_id, model_id)",
        "A model can only appear once per API token.",
    )

    @api.constrains("can_read", "can_create", "can_write", "can_delete")
    def _check_permissions(self):
        for access in self:
            if not any(
                (access.can_read, access.can_create,
                 access.can_write, access.can_delete)
            ):
                raise ValidationError(_("Enable at least one API permission."))

    def field_names(self, model):
        names = [item.strip() for item in (
            self.allowed_fields or "").split(",") if item.strip()]
        if not names:
            return list(model.fields_get().keys())
        invalid = set(names) - set(model.fields_get().keys())
        if invalid:
            raise ValidationError(
                _("Unknown field(s): %s", ", ".join(sorted(invalid))))
        return names

    def domain(self, model, api_user):
        if not self.domain_force:
            return []
        domain = safe_eval(
            self.domain_force,
            {"user": api_user, "uid": api_user.id,
                "context": api_user.env.context},
        )
        Domain(domain).validate(model)
        return domain


class RestApiTokenWizard(models.TransientModel):
    _name = "ara.rest.api.token.wizard"
    _description = "REST API Token Wizard"

    token_id = fields.Many2one("ara.rest.api.token", readonly=True)
    token = fields.Char(readonly=True)

    def action_close(self):
        return {"type": "ir.actions.act_window_close"}

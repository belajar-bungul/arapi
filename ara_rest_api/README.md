# ARA REST API for Odoo 19

A secure, token-based REST API for selected Odoo models.

## Setup

1. Add the parent folder to `addons_path`.
2. Update the Apps List.
3. Install **ARA REST API**.
4. Open **Settings > REST API > API Tokens**.
5. Create a token, assign it to an Odoo user, and configure allowed models.
6. Generate the token and store it in a secret manager. The full value is shown once.

## Authentication

Send the token in every request:

```http
Authorization: Bearer ara_your_token
```

## Endpoints

Base URL: `/api/v1`

- `GET /api/v1/models` lists models allowed by the token.
- `GET /api/v1/<model>` lists records.
- `GET /api/v1/<model>/<id>` returns one record.
- `POST /api/v1/<model>` creates a record when create access is enabled.
- `PUT` or `PATCH /api/v1/<model>/<id>` updates a record when write access is enabled.
- `DELETE /api/v1/<model>/<id>` deletes a record when delete access is enabled.

Example list request:

```text
/api/v1/res.partner?fields=name,email&limit=20&offset=0&domain=[["is_company","=",true]]
```

The API enforces the token allowlist, Odoo user permissions, record rules, field allowlists, optional domains, pagination limits, and token expiry.

## Response format

Successful responses use:

```json
{
    "success": true,
    "data": []
}
```

Errors use:

```json
{
    "success": false,
    "error": {
        "code": "invalid_token",
        "message": "Token is invalid or expired."
    }
}
```

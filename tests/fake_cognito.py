"""A stand-in for the Cognito user pool that behaves like the real one in the ways that matter.

It checks the client-secret hash of every call (for refresh against the user's sub, as Cognito
does), refuses what Cognito refuses with Cognito's own error codes, issues JWTs that carry the
user's attributes, and lets admin calls address a user by email or by sub.
"""
import base64
import hashlib
import hmac
import json
import itertools

from botocore.exceptions import ClientError

CLIENT_ID = "client-test-123"
CLIENT_SECRET = "test-secret-" + "x" * 41  # real ones are 51 characters; the API model requires 24 or more
POOL_ID = "us-east-1_TESTPOOL"


def error(code, operation, message="x"):
    return ClientError({"Error": {"Code": code, "Message": message}}, operation)


def b64(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


class FakeCognito:
    def __init__(self):
        self.users = {}            # sub -> record
        self.calls = []            # (operation, kwargs) for assertions
        self.sent_codes = []       # (kind, email, code)
        self.revoked = set()
        self._ids = itertools.count(1)

    # ------------------------------------------------------------ helpers
    def _hash(self, username):
        digest = hmac.new(CLIENT_SECRET.encode(), (username + CLIENT_ID).encode(), hashlib.sha256).digest()
        return base64.b64encode(digest).decode()

    def _check(self, operation, kwargs, username):
        self.calls.append((operation, kwargs))
        assert kwargs["ClientId"] == CLIENT_ID, "wrong client id"
        if kwargs.get("SecretHash") is not None or operation == "initiate_auth":
            given = kwargs.get("SecretHash") or kwargs["AuthParameters"].get("SECRET_HASH")
            if given != self._hash(username):
                raise error("NotAuthorizedException", operation, "Unable to verify secret hash for client")

    def find(self, username):
        for sub, user in self.users.items():
            if username == sub or username.lower() == user["email"]:
                return sub, user
        return None, None

    def _token(self, sub, user, use="id"):
        header = b64({"alg": "RS256", "kid": "k"})
        claims = {"sub": sub, "token_use": use, "aud": CLIENT_ID, "email": user["email"],
                  "email_verified": "true", "cognito:username": sub, "iss": "https://cognito-idp/" + POOL_ID}
        claims.update({k: v for k, v in user["attrs"].items() if k.startswith("custom:")})
        return "{}.{}.sig".format(header, b64(claims))

    def _code(self):
        return "{:06d}".format(next(self._ids) * 7919 % 1000000)

    # ------------------------------------------------------- public (client) calls
    def sign_up(self, **kw):
        email = kw["Username"]
        self._check("sign_up", kw, email)
        if self.find(email)[1] is not None:
            raise error("UsernameExistsException", "SignUp")
        if len(kw["Password"]) < 12:
            raise error("InvalidPasswordException", "SignUp")
        attrs = {a["Name"]: a["Value"] for a in kw["UserAttributes"]}
        sub = "sub-{:04d}".format(next(self._ids))
        code = self._code()
        self.users[sub] = {"email": email, "password": kw["Password"], "confirmed": False, "enabled": True,
                           "code": code, "reset_code": None, "attrs": attrs}
        self.sent_codes.append(("signup", email, code))
        return {"UserConfirmed": False, "UserSub": sub}

    def resend_confirmation_code(self, **kw):
        self._check("resend_confirmation_code", kw, kw["Username"])
        sub, user = self.find(kw["Username"])
        if user is None:
            raise error("UserNotFoundException", "ResendConfirmationCode")
        if user["confirmed"]:
            raise error("InvalidParameterException", "ResendConfirmationCode", "User is already confirmed")
        user["code"] = self._code()
        self.sent_codes.append(("resend", user["email"], user["code"]))
        return {}

    def confirm_sign_up(self, **kw):
        self._check("confirm_sign_up", kw, kw["Username"])
        sub, user = self.find(kw["Username"])
        if user is None:
            raise error("UserNotFoundException", "ConfirmSignUp")
        if user["confirmed"]:
            raise error("NotAuthorizedException", "ConfirmSignUp", "User cannot be confirmed. Current status is CONFIRMED")
        if kw["ConfirmationCode"] != user["code"]:
            raise error("CodeMismatchException", "ConfirmSignUp")
        user["confirmed"] = True
        return {}

    def initiate_auth(self, **kw):
        params = kw["AuthParameters"]
        if kw["AuthFlow"] == "USER_PASSWORD_AUTH":
            self._check("initiate_auth", kw, params["USERNAME"])
            sub, user = self.find(params["USERNAME"])
            if user is None or user["password"] != params["PASSWORD"] or not user["enabled"]:
                raise error("NotAuthorizedException", "InitiateAuth", "Incorrect username or password.")
            if not user["confirmed"]:
                raise error("UserNotConfirmedException", "InitiateAuth")
            refresh_token = "rt-{}-{}".format(sub, next(self._ids))
            user["refresh"] = refresh_token
            return {"AuthenticationResult": {"IdToken": self._token(sub, user), "AccessToken": self._token(sub, user, "access"),
                                             "RefreshToken": refresh_token, "ExpiresIn": 900, "TokenType": "Bearer"}}
        if kw["AuthFlow"] == "REFRESH_TOKEN_AUTH":
            token = params["REFRESH_TOKEN"]
            sub = token[3:].rsplit("-", 1)[0] if token.startswith("rt-") else None  # "rt-<sub>-<n>"
            user = self.users.get(sub)
            # Cognito computes this hash from the user's real username (the sub), not the email.
            self._check("initiate_auth", kw, sub or "")
            if user is None or token in self.revoked or not user["enabled"] or user.get("refresh") != token:
                raise error("NotAuthorizedException", "InitiateAuth", "Invalid Refresh Token")
            return {"AuthenticationResult": {"IdToken": self._token(sub, user), "AccessToken": self._token(sub, user, "access"),
                                             "ExpiresIn": 900, "TokenType": "Bearer"}}
        raise AssertionError("unexpected flow " + kw["AuthFlow"])

    def revoke_token(self, **kw):
        self.calls.append(("revoke_token", kw))
        assert kw["ClientSecret"] == CLIENT_SECRET
        self.revoked.add(kw["Token"])
        return {}

    def forgot_password(self, **kw):
        self._check("forgot_password", kw, kw["Username"])
        sub, user = self.find(kw["Username"])
        if user is None:
            return {"CodeDeliveryDetails": {}}  # PreventUserExistenceErrors: looks like success
        if not user["confirmed"]:
            raise error("InvalidParameterException", "ForgotPassword")
        user["reset_code"] = self._code()
        self.sent_codes.append(("reset", user["email"], user["reset_code"]))
        return {"CodeDeliveryDetails": {}}

    def confirm_forgot_password(self, **kw):
        self._check("confirm_forgot_password", kw, kw["Username"])
        sub, user = self.find(kw["Username"])
        if user is None or kw["ConfirmationCode"] != user.get("reset_code"):
            raise error("CodeMismatchException", "ConfirmForgotPassword")
        if len(kw["Password"]) < 12:
            raise error("InvalidPasswordException", "ConfirmForgotPassword")
        user["password"], user["reset_code"] = kw["Password"], None
        return {}

    # ------------------------------------------------------------ admin calls
    def admin_get_user(self, **kw):
        self.calls.append(("admin_get_user", kw))
        sub, user = self.find(kw["Username"])
        if user is None:
            raise error("UserNotFoundException", "AdminGetUser")
        attrs = dict(user["attrs"], email=user["email"], sub=sub)
        return {"Username": sub, "Enabled": user["enabled"], "UserAttributes": [{"Name": k, "Value": v} for k, v in attrs.items()]}

    def admin_update_user_attributes(self, **kw):
        self.calls.append(("admin_update_user_attributes", kw))
        sub, user = self.find(kw["Username"])
        if user is None:
            raise error("UserNotFoundException", "AdminUpdateUserAttributes")
        user["attrs"].update({a["Name"]: a["Value"] for a in kw["UserAttributes"]})
        return {}

    def admin_disable_user(self, **kw):
        self.calls.append(("admin_disable_user", kw))
        sub, user = self.find(kw["Username"])
        if user is None:
            raise error("UserNotFoundException", "AdminDisableUser")
        user["enabled"] = False
        return {}

    def admin_enable_user(self, **kw):
        self.calls.append(("admin_enable_user", kw))
        sub, user = self.find(kw["Username"])
        if user is None:
            raise error("UserNotFoundException", "AdminEnableUser")
        user["enabled"] = True
        return {}

    def admin_user_global_sign_out(self, **kw):
        self.calls.append(("admin_user_global_sign_out", kw))
        sub, user = self.find(kw["Username"])
        if user is not None:
            user["refresh"] = None
        return {}

    # ----------------------------------------------------------- test helpers
    def last_code(self, email):
        return [c for c in self.sent_codes if c[1] == email][-1][2]

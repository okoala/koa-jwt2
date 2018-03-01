const jwt = require("jsonwebtoken");
const assert = require("assert");

const koajwt = require("../lib");
const UnauthorizedError = require("../lib/errors/UnauthorizedError");
const mockContext = require("./context");

describe("multitenancy", function() {
  const tenants = {
    a: {
      secret: "secret-a"
    }
  };

  let ctx;

  beforeEach(() => {
    ctx = mockContext();
  });

  const secretAsync = async function(ctx, payload) {
    const issuer = payload.iss;
    if (tenants[issuer]) {
      return tenants[issuer].secret;
    }

    throw new UnauthorizedError("missing_secret", {
      message: "Could not find secret for issuer."
    });
  };

  const middleware = koajwt({
    secret: secretAsync
  });

  it("should retrieve secret using callback", async () => {
    const token = jwt.sign({ iss: "a", foo: "bar" }, tenants.a.secret);

    ctx.headers.authorization = "Bearer " + token;

    await middleware(ctx, () => {});
    assert.equal("bar", ctx.state.user.foo);
  });

  it("should throw if an error ocurred when retrieving the token", async () => {
    const secret = "shhhhhh";
    const token = jwt.sign({ iss: "inexistent", foo: "bar" }, secret);

    ctx.headers.authorization = "Bearer " + token;

    try {
      await middleware(ctx, () => {});
    } catch (err) {
      assert.ok(err);
      assert.equal(err.code, "missing_secret");
      assert.equal(err.message, "Could not find secret for issuer.");
    }
  });

  it("should fail if token is revoked", async () => {
    const token = jwt.sign({ iss: "a", foo: "bar" }, tenants.a.secret);
    ctx.headers.authorization = "Bearer " + token;

    try {
      await koajwt({
        secret: secretAsync,
        isRevoked: async function(ctx, payload) {
          return true;
        }
      })(ctx, () => {});
    } catch (err) {
      assert.ok(err);
      assert.equal(err.code, "revoked_token");
      assert.equal(err.message, "The token has been revoked.");
    }
  });
});

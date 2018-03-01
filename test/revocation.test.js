const jwt = require("jsonwebtoken");
const assert = require("assert");

const koajwt = require("../lib");
const UnauthorizedError = require("../lib/errors/UnauthorizedError");
const mockContext = require("./context");

describe("revoked jwts", function() {
  const secret = "shhhhhh";
  const revoked_id = "1234";

  let ctx;

  beforeEach(() => {
    ctx = mockContext();
  });

  const middleware = koajwt({
    secret: secret,
    isRevoked: async function(ctx, payload) {
      return payload.jti && payload.jti === revoked_id;
    }
  });

  it("should throw if token is revoked", async () => {
    const token = jwt.sign({ jti: revoked_id, foo: "bar" }, secret);

    ctx.headers.authorization = "Bearer " + token;

    try {
      await middleware(ctx, () => {});
    } catch (err) {
      assert.ok(err);
      assert.equal(err.code, "revoked_token");
      assert.equal(err.message, "The token has been revoked.");
    }
  });

  it("should work if token is not revoked", async () => {
    const token = jwt.sign({ jti: "1233", foo: "bar" }, secret);
    ctx.headers.authorization = "Bearer " + token;

    await middleware(ctx, () => {});
    assert.equal("bar", ctx.state.user.foo);
  });

  it("should throw if error occurs checking if token is revoked", async () => {
    const token = jwt.sign({ jti: revoked_id, foo: "bar" }, secret);
    ctx.headers.authorization = "Bearer " + token;

    try {
      await koajwt({
        secret,
        isRevoked: async (ctx, payload) => {
          throw new Error("An error ocurred");
        }
      })(ctx, () => {});
    } catch (err) {
      assert.ok(err);
      assert.equal(err.message, "An error ocurred");
    }
  });
});

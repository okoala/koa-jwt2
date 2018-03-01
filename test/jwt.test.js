const jwt = require("jsonwebtoken");
const assert = require("assert");

const koajwt = require("../lib");
const UnauthorizedError = require("../lib/errors/UnauthorizedError");
const mockContext = require("./context");

describe("failure tests", function() {
  let ctx;

  beforeEach(() => {
    ctx = mockContext();
  });

  it("should throw if options not sent", function() {
    try {
      koajwt();
    } catch (err) {
      assert.ok(err);
      assert.equal(err.message, "secret should be set");
    }
  });

  it("should throw if no authorization header and credentials are required", async () => {
    try {
      await koajwt({ secret: "shhhh", credentialsRequired: true })(
        ctx,
        () => {}
      );
    } catch (err) {
      assert.ok(err);
      assert.equal(err.code, "credentials_required");
    }
  });

  it("support unless skip", async () => {
    ctx.req.url = "/index.html";
    await koajwt({ secret: "shhhh" }).unless({
      path: "/index.html",
      useOriginalUrl: false
    })(ctx, () => {});
    assert.ok(true);
  });

  it("should skip on CORS preflight", async () => {
    ctx.req.method = "OPTIONS";
    ctx.req.headers = {
      "access-control-request-headers": "sasa, sras,  authorization"
    };
    await koajwt({ secret: "shhhh" })(ctx, () => {});
    assert.ok(true);
  });

  it("should throw if authorization header is malformed", async () => {
    ctx.headers.authorization = "wrong";
    try {
      await koajwt({ secret: "shhhh" })(ctx, () => {});
    } catch (err) {
      assert.ok(err);
      assert.equal(err.code, "credentials_bad_format");
    }
  });

  it("should throw if authorization header is not Bearer", async () => {
    ctx.headers.authorization = "Basic foobar";
    try {
      await koajwt({ secret: "shhhh" })(ctx, () => {});
    } catch (err) {
      assert.equal(err.code, "credentials_bad_scheme");
    }
  });

  it("should next if authorization header is not Bearer and credentialsRequired is false", async () => {
    ctx.headers.authorization = "Basic foobar";
    await koajwt({ secret: "shhhh", credentialsRequired: false })(
      ctx,
      () => {}
    );
    assert.ok(true);
  });

  it("should throw if authorization header is not well-formatted jwt", async () => {
    ctx.headers.authorization = "Bearer wrongjwt";
    try {
      await koajwt({ secret: "shhhh" })(ctx, () => {});
    } catch (err) {
      assert.equal(err.code, "invalid_token");
    }
  });

  it("should throw if jwt is an invalid json", async () => {
    ctx.headers.authorization =
      "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.yJ1c2VybmFtZSI6InNhZ3VpYXIiLCJpYXQiOjE0NzEwMTg2MzUsImV4cCI6MTQ3MzYxMDYzNX0.foo";

    try {
      await koajwt({ secret: "shhhh" })(ctx, () => {});
    } catch (err) {
      assert.equal(err.code, "invalid_token");
    }
  });

  it("should throw if authorization header is not valid jwt", async () => {
    const secret = "shhhhhh";
    const token = jwt.sign({ foo: "bar" }, secret);
    ctx.headers.authorization = "Bearer " + token;

    try {
      await koajwt({ secret: "different-shhhh" })(ctx, () => {});
    } catch (err) {
      assert.ok(err);
      assert.equal(err.code, "invalid_token");
      assert.equal(err.message, "invalid signature");
    }
  });

  it("should throw if audience is not expected", async () => {
    const secret = "shhhhhh";
    const token = jwt.sign({ foo: "bar", aud: "expected-audience" }, secret);

    ctx.headers.authorization = "Bearer " + token;
    try {
      await koajwt({ secret: "shhhhhh", audience: "not-expected-audience" })(
        ctx,
        () => {}
      );
    } catch (err) {
      assert.ok(err);
      assert.equal(err.code, "invalid_token");
      assert.equal(
        err.message,
        "jwt audience invalid. expected: not-expected-audience"
      );
    }
  });

  it("should throw if token is expired", async () => {
    const secret = "shhhhhh";
    const token = jwt.sign({ foo: "bar", exp: 1382412921 }, secret);

    ctx.headers.authorization = "Bearer " + token;
    try {
      await koajwt({ secret: "shhhhhh" })(ctx, () => {});
    } catch (err) {
      assert.ok(err);
      assert.equal(err.code, "invalid_token");
      assert.equal(err.inner.name, "TokenExpiredError");
      assert.equal(err.message, "jwt expired");
    }
  });

  it("should throw if token issuer is wrong", async () => {
    const secret = "shhhhhh";
    const token = jwt.sign({ foo: "bar", iss: "http://foo" }, secret);

    ctx.headers.authorization = "Bearer " + token;
    try {
      await koajwt({ secret: "shhhhhh", issuer: "http://wrong" })(
        ctx,
        () => {}
      );
    } catch (err) {
      assert.ok(err);
      assert.equal(err.code, "invalid_token");
      assert.equal(err.message, "jwt issuer invalid. expected: http://wrong");
    }
  });

  it("should use errors thrown from custom getToken function", async () => {
    const secret = "shhhhhh";
    const token = jwt.sign({ foo: "bar" }, secret);

    function getTokenThatThrowsError() {
      throw new UnauthorizedError("invalid_token", {
        message: "Invalid token!"
      });
    }

    try {
      await koajwt({
        secret: "shhhhhh",
        getToken: getTokenThatThrowsError
      })(ctx, () => {});
    } catch (err) {
      assert.ok(err);
      assert.equal(err.code, "invalid_token");
      assert.equal(err.message, "Invalid token!");
    }
  });

  it("should throw error when signature is wrong", async () => {
    const secret = "shhh";
    const token = jwt.sign({ foo: "bar", iss: "http://www" }, secret);
    // manipulate the token
    const newContent = new Buffer("{foo: 'bar', edg: 'ar'}").toString("base64");
    const splitetToken = token.split(".");
    splitetToken[1] = newContent;
    const newToken = splitetToken.join(".");

    // build request
    ctx.headers = [];
    ctx.headers.authorization = "Bearer " + newToken;

    try {
      await koajwt({ secret: secret })(ctx, () => {});
    } catch (err) {
      assert.ok(err);
      assert.equal(err.code, "invalid_token");
      assert.equal(err.message, "invalid token");
    }
  });

  it("should throw error if token is expired even with when credentials are not required", async () => {
    const secret = "shhhhhh";
    const token = jwt.sign({ foo: "bar", exp: 1382412921 }, secret);

    ctx.headers.authorization = "Bearer " + token;
    try {
      await koajwt({ secret: secret, credentialsRequired: false })(
        ctx,
        () => {}
      );
    } catch (err) {
      assert.ok(err);
      assert.equal(err.code, "invalid_token");
      assert.equal(err.message, "jwt expired");
    }
  });

  it("should throw error if token is invalid even with when credentials are not required", async () => {
    const secret = "shhhhhh";
    const token = jwt.sign({ foo: "bar", exp: 1382412921 }, secret);

    ctx.headers.authorization = "Bearer " + token;
    try {
      await koajwt({ secret: "not the secret", credentialsRequired: false })(
        ctx,
        () => {}
      );
    } catch (err) {
      assert.ok(err);
      assert.equal(err.code, "invalid_token");
      assert.equal(err.message, "invalid signature");
    }
  });
});

describe("work tests", function() {
  let ctx;

  beforeEach(() => {
    ctx = mockContext();
  });

  it("should work if authorization header is valid jwt", async () => {
    const secret = "shhhhhh";
    const token = jwt.sign({ foo: "bar" }, secret);

    ctx.headers.authorization = "Bearer " + token;
    await koajwt({ secret })(ctx, () => {});

    assert.equal("bar", ctx.state.user.foo);
  });

  it("should work with nested properties", async () => {
    const secret = "shhhhhh";
    const token = jwt.sign({ foo: "bar" }, secret);

    ctx.headers.authorization = "Bearer " + token;
    await koajwt({ secret, property: "auth.token" })(ctx, () => {});
    assert.equal("bar", ctx.state.auth.token.foo);
  });

  it("should work if authorization header is valid with a buffer secret", async () => {
    const secret = new Buffer(
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "base64"
    );
    const token = jwt.sign({ foo: "bar" }, secret);

    ctx.headers.authorization = "Bearer " + token;
    await koajwt({ secret })(ctx, () => {});
    assert.equal("bar", ctx.state.user.foo);
  });

  it("should set property if option provided", async () => {
    const secret = "shhhhhh";
    const token = jwt.sign({ foo: "bar" }, secret);

    ctx.headers.authorization = "Bearer " + token;
    await koajwt({ secret, property: "auth" })(ctx, () => {});
    assert.equal("bar", ctx.state.auth.foo);
  });

  it("should work if no authorization header and credentials are not required", async () => {
    await koajwt({ secret: "shhhh", credentialsRequired: false })(
      ctx,
      () => {}
    );
    assert.ok(true);
  });

  it("should not work if no authorization header", async () => {
    try {
      await koajwt({ secret: "shhhh" })(ctx, () => {});
    } catch (err) {
      assert(typeof err !== "undefined");
    }
  });

  it("should produce a stack trace that includes the failure reason", async () => {
    const token = jwt.sign({ foo: "bar" }, "secretA");
    ctx.headers.authorization = "Bearer " + token;

    try {
      await koajwt({ secret: "secretB" })(ctx, () => {});
    } catch (err) {
      const index = err.stack.indexOf("UnauthorizedError: invalid signature");
      assert.equal(
        index,
        0,
        "Stack trace didn't include 'invalid signature' message."
      );
    }
  });

  it("should work with a custom getToken function", async () => {
    const secret = "shhhhhh";
    const token = jwt.sign({ foo: "bar" }, secret);
    ctx.query = {
      token
    };

    function getTokenFromQuery(ctx) {
      return ctx.query.token;
    }

    await koajwt({
      secret,
      getToken: getTokenFromQuery
    })(ctx, () => {
      assert.equal("bar", ctx.state.user.foo);
    });
  });

  it("should work with a secret async function that accepts header argument", async () => {
    const secret = "shhhhhh";
    const secretAsync = async function(ctx, headers, payload, cb) {
      assert.equal(headers.alg, "HS256");
      assert.equal(payload.foo, "bar");

      return new Promise(resolve => {
        process.nextTick(function() {
          resolve(secret);
        });
      });
    };
    const token = jwt.sign({ foo: "bar" }, secret);

    ctx.headers.authorization = "Bearer " + token;
    await koajwt({ secret: secretAsync })(ctx, () => {});
    assert.equal("bar", ctx.state.user.foo);
  });
});

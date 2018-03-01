const jwt = require("jsonwebtoken");
const assert = require("assert");

const koajwt = require("../lib");
const UnauthorizedError = require("../lib/errors/UnauthorizedError");
const mockContext = require("./context");

describe("string tokens", function() {
  let ctx;

  beforeEach(() => {
    ctx = mockContext();
  });

  it("should work with a valid string token", async () => {
    const secret = "shhhhhh";
    const token = jwt.sign("foo", secret);

    ctx.headers.authorization = "Bearer " + token;
    await koajwt({ secret })(ctx, function() {
      assert.equal("foo", ctx.state.user);
    });
  });
});

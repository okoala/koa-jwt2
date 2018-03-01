const Stream = require("stream");
const Koa = require("koa");

const mockContext = (req, res, app) => {
  const socket = new Stream.Duplex();
  req = Object.assign({ headers: {}, socket }, Stream.Readable.prototype, req);
  res = Object.assign({ _headers: {}, socket }, Stream.Writable.prototype, res);
  req.socket.remoteAddress = req.socket.remoteAddress || "127.0.0.1";
  req.url = "";
  app = app || new Koa();
  res.getHeader = k => res._headers[k.toLowerCase()];
  res.setHeader = (k, v) => {
    res._headers[k.toLowerCase()] = v;
    return v;
  };
  res.removeHeader = k => delete res._headers[k.toLowerCase()];
  return app.createContext(req, res);
};
mockContext.request = (req, res, app) => mockContext(req, res, app).request;
mockContext.response = (req, res, app) => mockContext(req, res, app).response;

module.exports = mockContext;

const http = require("node:http");

function price(cents, quantity) {
  if (!Number.isInteger(cents) || !Number.isInteger(quantity) || cents < 0 || quantity < 1) {
    throw new Error("cents must be a non-negative integer and quantity a positive integer");
  }
  return cents * quantity;
}

function handler(req, res) {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname === "/total") {
    try {
      const total = price(Number(url.searchParams.get("cents")), Number(url.searchParams.get("qty")));
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ total }));
    } catch (e) {
      res.writeHead(400, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: e.message }));
    }
  }
  res.writeHead(404);
  res.end();
}

if (require.main === module) {
  http.createServer(handler).listen(3000, () => console.log("listening on http://localhost:3000"));
}

module.exports = { price, handler };

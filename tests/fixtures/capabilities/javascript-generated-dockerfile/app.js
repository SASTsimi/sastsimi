const http = require("node:http");

http.createServer((_request, response) => {
  response.writeHead(200, { "Content-Type": "text/plain" });
  response.end("ok");
}).listen(8080, "127.0.0.1");

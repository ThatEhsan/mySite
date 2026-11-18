import http from 'http';
const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ ok: true, path: req.url }));
});
server.listen(3000, '127.0.0.1', () => {
  console.log('TEST server OK on http://127.0.0.1:3000');
});
server.on('error', (e) => {
  console.error('ERROR', e.code, e.message);
});

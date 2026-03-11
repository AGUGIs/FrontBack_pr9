function loggerMiddleware(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
      console.log('Body:', JSON.stringify(req.body));
    }
  });
  next();
}

module.exports = loggerMiddleware;
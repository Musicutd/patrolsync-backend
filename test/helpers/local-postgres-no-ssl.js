'use strict';

// CI-only preload. The application normally requests TLS, while its disposable
// PostgreSQL service is loopback-only and has TLS disabled.
const pg = require('pg');
const OriginalPool = pg.Pool;
pg.Pool = class LocalTestPool extends OriginalPool {
  constructor(config) {
    const url = new URL(config.connectionString);
    const allowedUrls = [process.env.VISION_TEST_DATABASE_URL, process.env.VISION_TEST_TENANT_DATABASE_URL];
    if (process.env.NODE_ENV !== 'test' ||
        !allowedUrls.includes(config.connectionString) ||
        !['127.0.0.1', 'localhost'].includes(url.hostname) ||
        url.pathname !== '/vision_startup_ci') {
      throw new Error('Refusing non-disposable database in startup test');
    }
    super({ ...config, ssl: false });
  }
};


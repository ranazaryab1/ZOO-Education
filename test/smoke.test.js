const assert = require('node:assert/strict');
const test = require('node:test');
process.env.NODE_ENV = 'test';
process.env.ADMIN_USERNAME = 'test-admin';
process.env.ADMIN_PASSWORD = 'test-only-password';
delete process.env.ADMIN_PASSWORD_HASH;
const { app } = require('../index');

async function withServer(callback) {
    const server = app.listen(0);
    try {
        return await callback(`http://127.0.0.1:${server.address().port}`);
    } finally {
        await new Promise((resolve) => server.close(resolve));
    }
}

test('health endpoint reports an unavailable database as degraded', async () => {
    await withServer(async (baseUrl) => {
        const response = await fetch(`${baseUrl}/health`);
        assert.equal(response.status, 503);
        assert.deepEqual(await response.json(), {
            status: 'degraded',
            database: 'disconnected'
        });
    });
});

test('admin endpoints require authentication', async () => {
    await withServer(async (baseUrl) => {
        const response = await fetch(`${baseUrl}/api/admin/content`);
        assert.equal(response.status, 401);
    });

    test('admin page redirects anonymous visitors before serving the panel', async () => {
        await withServer(async (baseUrl) => {
            const response = await fetch(`${baseUrl}/admin.html`, { redirect: 'manual' });
            assert.equal(response.status, 302);
            assert.equal(response.headers.get('location'), '/login.html');
        });
    });
});

test('login rejects invalid credentials and accepts valid credentials', async () => {
    await withServer(async (baseUrl) => {
        const invalid = await fetch(`${baseUrl}/api/auth/login`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ username: 'not-the-admin', password: 'wrong-password' })
        });
        assert.equal(invalid.status, 401);
        assert.deepEqual(await invalid.json(), { error: 'Invalid username or password' });

        const valid = await fetch(`${baseUrl}/api/auth/login`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
                username: process.env.ADMIN_USERNAME,
                password: process.env.ADMIN_PASSWORD
            })
        });
        assert.equal(valid.status, 200);
        assert.deepEqual(await valid.json(), { message: 'Signed in successfully' });
        assert.match(valid.headers.get('set-cookie') || '', /zoo_session=[^;]+/);
    });
});

test('CSRF protection rejects an authenticated state-changing request without an origin', async () => {
    await withServer(async (baseUrl) => {
        const login = await fetch(`${baseUrl}/api/auth/login`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
                username: process.env.ADMIN_USERNAME,
                password: process.env.ADMIN_PASSWORD
            })
        });
        const cookie = (login.headers.get('set-cookie') || '').split(';', 1)[0];
        assert.match(cookie, /^zoo_session=/);

        const response = await fetch(`${baseUrl}/api/auth/logout`, {
            method: 'POST',
            headers: { cookie }
        });
        assert.equal(response.status, 403);
        assert.deepEqual(await response.json(), { error: 'CSRF validation failed' });
    });
});

test('download and media routes reject path traversal filenames', async () => {
    await withServer(async (baseUrl) => {
        for (const route of [
            '/download/book',
            '/download/assignment',
            '/media/blog',
            '/download/entry-test',
            '/download/past-paper'
        ]) {
            const response = await fetch(`${baseUrl}${route}/..%2Findex.html`);
            assert.equal(response.status, 400, route);
        }
    });
});

test('all upload routes require admin authentication', async () => {
    await withServer(async (baseUrl) => {
        for (const route of [
            '/upload/blog',
            '/upload/assignment',
            '/upload/book',
            '/upload/material',
            '/upload/past-paper'
        ]) {
            const response = await fetch(`${baseUrl}${route}`, { method: 'POST' });
            assert.equal(response.status, 401, route);
        }
    });
});

const request = require('supertest');
const app = require('./app'); // Your express app

describe('SafeVault Security Audit', () => {
    // Test SQL Injection resistance
    it('should block SQL injection attempts in the email field', async () => {
        const res = await request(app)
            .post('/api/vault/login')
            .send({ email: "' OR 1=1 --", password: "password123" });
        
        expect(res.statusCode).toBe(400); // Should fail validation
    });

    // Test RBAC
    it('should deny a "user" access to "admin" routes', async () => {
        const res = await request(app)
            .get('/api/vault/admin-data')
            .set('x-user-role', 'user');
        
        expect(res.statusCode).toBe(403);
    });
});

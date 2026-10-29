import { describe, expect, it } from 'vitest';
import { handleBranding } from '../src/routes/branding';
import { MemoryAdminStore } from './doubles';

describe('GET /branding', () => {
  it('answers without a session before and after the claim', async () => {
    const adminStore = new MemoryAdminStore();
    adminStore.config = {
      issuer: 'https://auth.example.com',
      rpId: 'auth.example.com',
      brandName: 'Example Auth',
      brandBackgroundImage: 'https://cdn.example.com/login.jpg',
      adminUserId: null,
    };

    const anonymous = await handleBranding(new Request('https://auth.example.com/branding'), { adminStore });
    expect(anonymous.status).toBe(200);
    expect(await anonymous.json()).toEqual({
      issuer: 'https://auth.example.com',
      rp_id: 'auth.example.com',
      brand_name: 'Example Auth',
      brand_background_image: 'https://cdn.example.com/login.jpg',
    });

    // The point of the route: a renamed instance keeps its name after the root user is claimed,
    // when `/admin/setup` starts answering 403.
    await adminStore.claimRootUser('root-user', { issuer: 'https://auth.example.com', rpId: 'auth.example.com' });
    const afterClaim = await handleBranding(new Request('https://auth.example.com/branding'), { adminStore });
    expect(afterClaim.status).toBe(200);
    expect(((await afterClaim.json()) as { brand_name: string }).brand_name).toBe('Example Auth');
  });
});

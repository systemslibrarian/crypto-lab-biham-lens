import { defineConfig, devices } from '@playwright/test';

/**
 * Accessibility gate. Tests run against the production build served by
 * `vite preview`, so what passes here is what actually ships to Pages.
 */
export default defineConfig({
  testDir: './e2e',
  timeout: 120_000,
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  webServer: {
    // Build before serving. `preview` only serves whatever is already in dist/,
    // so a failed build would leave the last good bundle on disk and the suite
    // would pass green against source that no longer compiles.
    command: 'npm run build && npm run preview -- --port 4224 --strictPort',
    port: 4224,
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
  use: {
    baseURL: 'http://localhost:4224/crypto-lab-biham-lens/',
    ...devices['Desktop Chrome'],
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
});

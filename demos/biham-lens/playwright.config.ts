import { defineConfig, devices } from '@playwright/test';

/**
 * Accessibility gate. Tests run against the production build served by
 * `vite preview`, so what passes here is what actually ships to Pages.
 */
// One place, not three. This lab sat on 4224, which crypto-lab-hybrid-guide
// also claims; with `reuseExistingServer` on (every local run), whichever suite
// started second would silently attach to the OTHER lab's preview and audit a
// page from a different repo. That is not hypothetical in this fleet — bb84
// once reported kdf-chain's violations. 4680 is unused across the 170+ labs.
// Overridable so a busy port on a dev box does not block the gate.
const PORT = process.env.PREVIEW_PORT ?? '4680';
const BASE = `http://localhost:${PORT}/crypto-lab-biham-lens/`;

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
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    // `url`, not `port`. A bare `port` only asks whether SOMETHING is listening,
    // so any squatter on the number satisfies the wait and the suite proceeds to
    // scan it. Waiting on the full base path requires the server to be serving
    // THIS lab's base before the run starts.
    url: BASE,
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
  use: {
    baseURL: BASE,
    ...devices['Desktop Chrome'],
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
});

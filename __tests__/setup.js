// Test setup file - runs before all tests

// Suppress console.log during tests (optional)
// global.console = {
//   ...console,
//   log: jest.fn(),
//   warn: jest.fn(),
//   error: jest.fn()
// };

// Set test environment variables
// process.env.NODE_ENV = 'test';
// process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/triggers/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';

// Mock fetch for Slack notifications
global.fetch = jest.fn(() =>
  Promise.resolve({
    ok: true,
    status: 200,
    statusText: 'OK',
    json: () => Promise.resolve({ success: true })
  })
);

// Clean up after each test
afterEach(() => {
  jest.clearAllMocks();
});

// Global test utilities
global.testUtils = {
  // Create mock Express request
  createMockReq: (overrides = {}) => ({
    method: 'GET',
    path: '/test',
    originalUrl: '/test',
    ip: '127.0.0.1',
    headers: {},
    query: {},
    body: {},
    connection: { remoteAddress: '127.0.0.1' },
    get: jest.fn((header) => {
      const headers = {
        'user-agent': 'Mozilla/5.0 (Test Browser)',
        'content-type': 'application/json',
        ...overrides.headers
      };
      return headers[header.toLowerCase()];
    }),
    ...overrides
  }),

  // Create mock Express response
  createMockRes: () => ({
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    setHeader: jest.fn().mockReturnThis(),
    removeHeader: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis()
  }),

  // Create mock Express next function
  createMockNext: () => jest.fn(),

  // Wait for async operations
  wait: (ms = 10) => new Promise(resolve => setTimeout(resolve, ms))
};
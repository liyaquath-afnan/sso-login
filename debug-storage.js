const axios = require('axios');
const userService = require('./services/userService');

async function debugStorage() {
  console.log('🔍 Debugging refresh token storage...\n');
  
  // First, do a login to generate tokens
  console.log('1. Performing login to generate tokens...');
  const loginResponse = await axios.post('http://localhost:3000/api/auth/login', {
    email: 'admin@example.com',
    password: 'admin123'
  });
  
  const { tokens } = loginResponse.data;
  console.log('✅ Login successful, tokens generated');
  
  // Wait a moment for storage to be updated
  await new Promise(resolve => setTimeout(resolve, 100));
  
  // Check the current state of refresh tokens storage
  console.log('\n2. Checking refresh token storage:');
  console.log('Storage size:', userService.refreshTokens.size);
  
  // List all stored tokens
  for (const [userId, tokens] of userService.refreshTokens.entries()) {
    console.log(`User ${userId}:`);
    console.log(`  Number of tokens: ${tokens.size}`);
    for (const [jti, tokenData] of tokens.entries()) {
      console.log(`    JTI: ${jti}`);
      console.log(`    Created: ${tokenData.createdAt}`);
    }
  }
  
  // Now try the refresh
  console.log('\n3. Testing refresh with stored token...');
  try {
    const refreshResponse = await axios.post('http://localhost:3000/api/auth/refresh', {
      refreshToken: tokens.refreshToken
    });
    console.log('✅ Refresh successful!');
  } catch (error) {
    console.log('❌ Refresh failed:', error.response?.data);
  }
}

debugStorage().catch(console.error);

const axios = require('axios');

const BASE_URL = 'http://localhost:3000/api';

async function debugRefresh() {
  try {
    console.log('🔍 Debugging refresh token issue...\n');

    // Step 1: Login
    console.log('1. Logging in...');
    const loginResponse = await axios.post(`${BASE_URL}/auth/login`, {
      email: 'admin@example.com',
      password: 'admin123'
    });
    
    const { tokens, user } = loginResponse.data;
    const { accessToken, refreshToken } = tokens;
    
    console.log('✅ Login successful');
    console.log('   User ID:', user.id);
    console.log('   User active status:', user.active);
    console.log('   Refresh Token:', refreshToken.substring(0, 100) + '...');

    // Step 2: Decode the refresh token to see what's in it
    const jwt = require('jsonwebtoken');
    const decoded = jwt.decode(refreshToken);
    console.log('\n2. Decoded refresh token:');
    console.log('   User ID in token:', decoded.userId);
    console.log('   JTI:', decoded.jti);
    console.log('   Type:', decoded.type);

    // Step 3: Try to refresh
    console.log('\n3. Attempting refresh...');
    try {
      const refreshResponse = await axios.post(`${BASE_URL}/auth/refresh`, {
        refreshToken
      });
      console.log('✅ Refresh successful');
      console.log('   New tokens received');
    } catch (error) {
      console.log('❌ Refresh failed:', error.response?.data);
      
      // Step 4: Check if user exists by calling /me endpoint
      console.log('\n4. Checking if user exists via /me endpoint...');
      try {
        const meResponse = await axios.get(`${BASE_URL}/auth/me`, {
          headers: {
            'Authorization': `Bearer ${accessToken}`
          }
        });
        console.log('✅ User exists and is accessible via /me');
        console.log('   User data:', JSON.stringify(meResponse.data.user, null, 2));
      } catch (meError) {
        console.log('❌ User not accessible via /me:', meError.response?.data);
      }
    }

  } catch (error) {
    console.error('❌ Debug failed:', error.response?.data || error.message);
  }
}

debugRefresh();

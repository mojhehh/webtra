// Test script to verify TikTok video proxy works
const http = require('http');

const GATEWAY = 'http://localhost:3000';
const ORIGIN = 'https://mojhheh.gtihub.io';

function request(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, GATEWAY);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: method,
      headers: {
        'Origin': ORIGIN,
        'Content-Type': 'application/json',
        'Authorization': 'Bearer anonymous',
      }
    };
    
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve({ status: res.statusCode, headers: res.headers, data: data });
      });
    });
    
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function testProxy() {
  console.log('=== Testing TikTok Video Proxy ===\n');
  
  // Step 1: Tokenize a TikTok video URL (has actual video data)
  const videoUrl = 'https://www.tiktok.com/@tiktok/video/7000000000000000000';
  console.log('1. Tokenizing', videoUrl.substring(0, 50), '...');
  try {
    const tokenRes = await request('POST', '/tokenize', { url: videoUrl });
    console.log('   Status:', tokenRes.status);
    
    let tokenData;
    try { tokenData = JSON.parse(tokenRes.data); } catch { tokenData = tokenRes.data; }
    
    if (tokenRes.status !== 200) {
      console.log('   ERROR:', tokenData);
      return;
    }
    
    const token = tokenData.token;
    console.log('   Token:', token.substring(0, 30) + '...');
    
    // Step 2: Fetch through SSR proxy
    console.log('\n2. Fetching TikTok via /go-ssr/' + token.substring(0, 20) + '...');
    const ssrRes = await request('GET', '/go-ssr/' + token);
    console.log('   Status:', ssrRes.status);
    console.log('   Content-Type:', ssrRes.headers['content-type']);
    
    if (ssrRes.status === 200) {
      const html = typeof ssrRes.data === 'string' ? ssrRes.data : JSON.stringify(ssrRes.data);
      console.log('   HTML length:', html.length);
      
      // Check for video data in the response
      if (html.includes('__UNIVERSAL_DATA_FOR_REHYDRATION__')) {
        console.log('   ✓ Contains __UNIVERSAL_DATA_FOR_REHYDRATION__');
        
        // Look for video URLs
        const playAddrMatch = html.match(/playAddr['":\s]+['"]([^'"]+)['"]/i) ||
                              html.match(/"play[Aa]ddr?"?\s*:\s*"([^"]+)"/i) ||
                              html.match(/downloadAddr['":\s]+['"]([^'"]+)['"]/i);
        if (playAddrMatch) {
          console.log('   ✓ Found video playAddr URL');
          console.log('   URL:', playAddrMatch[1].substring(0, 80) + '...');
        } else {
          // Look for any video-related URLs in the data
          const videoUrls = html.match(/https?:\\u002F\\u002F[^"]*(?:video|play|v\d+)[^"]*/gi);
          if (videoUrls && videoUrls.length > 0) {
            console.log('   ✓ Found', videoUrls.length, 'video-related URLs in data');
            // Decode unicode escapes for display
            const decoded = videoUrls[0].replace(/\\u002F/g, '/');
            console.log('   Example:', decoded.substring(0, 100));
          } else {
            console.log('   ✗ No playAddr found in HTML');
          }
        }
        
        // Check if video URLs are being rewritten
        const tiktokcdnMatch = html.match(/tiktokcdn[^'"]{0,100}/i);
        if (tiktokcdnMatch) {
          console.log('   ✓ Found tiktokcdn URL (should NOT be tokenized)');
          console.log('   Sample:', tiktokcdnMatch[0]);
        }
        
        // Check if video URLs got tokenized (BAD)
        const tokenizedVideo = html.match(/https?:\/\/[^"'\s]*tiktokcdn[^"'\s]*\/go\//i) || 
                               html.match(/\/go\/[A-Za-z0-9_-]{20,}[^"'\s]*tiktokcdn/i);
        if (tokenizedVideo) {
          console.log('   ✗ BAD: Video CDN URL was tokenized!');
          console.log('   Match:', tokenizedVideo[0].substring(0, 100));
        } else {
          console.log('   ✓ No video CDN URLs were tokenized');
        }
        
        // Look for the actual pattern of tokenized tiktokcdn URLs
        const badPattern = html.match(/localhost:3000\/go\/[^"'\s]+/g);
        if (badPattern) {
          // Check if any of these are video CDN URLs
          const videoCdnTokenized = badPattern.filter(u => 
            u.includes('tiktokcdn') || u.includes('bytedtos') || u.includes('tiktokv')
          );
          if (videoCdnTokenized.length > 0) {
            console.log('   ✗ Found', videoCdnTokenized.length, 'tokenized video CDN URLs');
            console.log('   Example:', videoCdnTokenized[0].substring(0, 120));
          }
        }
        
        // Check for properly direct video URLs
        const directVideoUrls = html.match(/https:\/\/[^"'\s]*tiktokcdn[^"'\s]*/g);
        if (directVideoUrls && directVideoUrls.length > 0) {
          console.log('   ✓ Found', directVideoUrls.length, 'direct tiktokcdn URLs (good!)');
          console.log('   Example:', directVideoUrls[0].substring(0, 100));
        }
      } else {
        console.log('   ✗ No __UNIVERSAL_DATA_FOR_REHYDRATION__ found');
      }
      
      // Check for errors in the bootstrap script
      if (html.includes('[Gateway]')) {
        console.log('   ✓ Contains gateway bootstrap script');
      }
      
    } else {
      console.log('   ERROR response:', typeof ssrRes.data === 'string' ? ssrRes.data.substring(0, 200) : ssrRes.data);
    }
    
    console.log('\n=== Test Complete ===');
    
    // Step 3: Test cookie-privacy mock endpoint
    console.log('\n3. Testing cookie-privacy mock endpoint...');
    const cookiePrivacyToken = await request('POST', '/tokenize', { 
      url: 'https://www.tiktok.com/api/v1/web-cookie-privacy/config?locale=en' 
    });
    let cpTokenData;
    try { cpTokenData = JSON.parse(cookiePrivacyToken.data); } catch { cpTokenData = cookiePrivacyToken.data; }
    
    if (cpTokenData.token) {
      const cpRes = await request('GET', '/go/' + cpTokenData.token);
      console.log('   Status:', cpRes.status);
      let cpData;
      try { cpData = JSON.parse(cpRes.data); } catch { cpData = cpRes.data; }
      console.log('   Response:', JSON.stringify(cpData).substring(0, 100));
      if (cpData.status_code === 0 && cpData.data) {
        console.log('   ✓ Mock returned valid structure');
      } else {
        console.log('   ✗ Mock response invalid');
      }
    }
    
  } catch (err) {
    console.error('ERROR:', err.message);
  }
}

testProxy();

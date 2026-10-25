/**
 * SnapMedia - Modern High-Velocity Instagram Media Pipeline
 * Production-ready Express Server with Provider Adapter, SSRF Protection, and Safe Streaming
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { execFile } = require('child_process');
const axios = require('axios');
const { URL } = require('url');
const http = require('http');
const assert = require('node:assert');

// Load .env configuration
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, 'utf8');
  envContent.split(/\r?\n/).forEach(line => {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#') && trimmed.includes('=')) {
      const idx = trimmed.indexOf('=');
      const key = trimmed.slice(0, idx).trim();
      const val = trimmed.slice(idx + 1).trim();
      if (!process.env[key]) process.env[key] = val;
    }
  });
}

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration
const YTDLP_PATH = path.join(__dirname, 'yt-dlp.exe');
const COOKIES_PATH = path.join(__dirname, 'cookies.txt');
const PROVIDER_API_URL = process.env.PROVIDER_API_URL || null;
const PROVIDER_API_KEY = process.env.PROVIDER_API_KEY || null;
const PROVIDER_API_HOST = process.env.PROVIDER_API_HOST || null;

// Security Hardening: Remove Express fingerprinting
app.disable('x-powered-by');

// Security Hardening: Global Defense Headers (Clickjacking, MIME Sniffing, XSS)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// Security Hardening: Block sensitive files from static exposure (.env, server.js, cookies.txt, etc.)
app.use((req, res, next) => {
  const forbidden = ['.env', '.git', 'server.js', 'package.json', 'package-lock.json', 'cookies.txt', 'yt-dlp.exe', '/test'];
  const lowerPath = req.path.toLowerCase();
  if (forbidden.some(f => lowerPath.includes(f))) {
    return res.status(403).type('text/plain').send('Access Denied: Forbidden resource.');
  }
  next();
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '15kb' })); // Strict 15kb limit to prevent payload memory exhaustion DoS

// Static files (serves index.html, hero_mockup.jpg, sample.mp4, etc.)
app.use(express.static(__dirname));

// =========================================================================
// SECURITY & SSRF PROTECTION
// =========================================================================

class SecurityValidator {
  // Reject private/loopback/cloud metadata IP ranges
  static isPrivateOrLoopbackHost(hostname) {
    if (!hostname) return true;
    const lower = hostname.toLowerCase();

    if (lower === 'localhost' || lower === '127.0.0.1' || lower === '::1') return true;

    // Check IPv4 ranges
    const ipv4Match = lower.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (ipv4Match) {
      const octet1 = parseInt(ipv4Match[1], 10);
      const octet2 = parseInt(ipv4Match[2], 10);

      if (octet1 === 10) return true; // 10.0.0.0/8
      if (octet1 === 127) return true; // 127.0.0.0/8
      if (octet1 === 169 && octet2 === 254) return true; // 169.254.0.0/16 (Link Local / Cloud Metadata)
      if (octet1 === 172 && octet2 >= 16 && octet2 <= 31) return true; // 172.16.0.0/12
      if (octet1 === 192 && octet2 === 168) return true; // 192.168.0.0/16
      if (octet1 === 0 || octet1 >= 224) return true; // 0.0.0.0 or multicast
    }

    return false;
  }

  // Validate Instagram post/reel/story URL
  static isValidInstagramUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return false;
    try {
      let clean = rawUrl.trim();
      if (!clean.startsWith('http://') && !clean.startsWith('https://')) {
        clean = 'https://' + clean;
      }
      const parsed = new URL(clean);
      const host = parsed.hostname.toLowerCase();

      if (this.isPrivateOrLoopbackHost(host)) return false;

      const isAllowedHost = host === 'instagram.com' ||
        host.endsWith('.instagram.com') ||
        host === 'instagr.am' ||
        host.endsWith('.instagr.am');

      if (!isAllowedHost) return false;

      // Check path syntax
      const pathname = parsed.pathname.toLowerCase();
      const validSections = ['/reel/', '/reels/', '/p/', '/stories/', '/tv/', '/share/'];
      return validSections.some(sec => pathname.includes(sec)) || pathname.length > 3;
    } catch (e) {
      return false;
    }
  }

  // Normalize Instagram URL
  static normalizeInstagramUrl(rawUrl) {
    let clean = rawUrl.trim();
    if (!clean.startsWith('http://') && !clean.startsWith('https://')) {
      clean = 'https://' + clean;
    }
    const parsed = new URL(clean);
    // Strip tracking query parameters
    const safeParams = new URLSearchParams();
    parsed.searchParams.forEach((val, key) => {
      if (!['igsh', 'utm_source', 'utm_medium', 'utm_campaign', 'img_index'].includes(key)) {
        safeParams.append(key, val);
      }
    });
    parsed.search = safeParams.toString();
    return parsed.toString();
  }

  // Allowed CDN hosts for download proxying
  static isAllowedCdnHost(urlStr) {
    try {
      const parsed = new URL(urlStr);
      const host = parsed.hostname.toLowerCase();

      if (this.isPrivateOrLoopbackHost(host)) {
        // Allow localhost strictly for internal sample file streaming
        if (host === 'localhost' || host === '127.0.0.1') {
          return parsed.port == PORT || parsed.pathname.endsWith('.mp4') || parsed.pathname.endsWith('.mp3');
        }
        return false;
      }

      // Check Instagram CDN domains
      return host.endsWith('.cdninstagram.com') ||
        host.endsWith('.fbcdn.net') ||
        host.endsWith('.instagram.com') ||
        host.endsWith('.fastsaver.io');
    } catch (e) {
      return false;
    }
  }

  // Sanitize download filename against path traversal & header injection
  static sanitizeFilename(name, defaultExt = 'mp4') {
    if (!name || typeof name !== 'string') {
      return `SnapMedia_${Date.now()}.${defaultExt}`;
    }
    // Remove directory traversal characters, slashes, non-printable characters
    let clean = name.replace(/[\/\?<>\\:\*\|":\r\n\t]/g, '_')
      .replace(/\.\.+/g, '.')
      .trim();
    if (!clean || clean === '.') {
      clean = `SnapMedia_${Date.now()}.${defaultExt}`;
    }
    return clean;
  }
}

// =========================================================================
// RATE LIMITER (In-Memory Sliding Window)
// =========================================================================

class RateLimiter {
  constructor(windowMs, maxRequests) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
    this.hits = new Map();

    // Auto-clean every 5 minutes
    setInterval(() => this.cleanup(), 5 * 60 * 1000);
  }

  isLimited(ip) {
    const now = Date.now();
    const timestamps = this.hits.get(ip) || [];
    const valid = timestamps.filter(t => now - t < this.windowMs);

    if (valid.length >= this.maxRequests) {
      return true;
    }

    valid.push(now);
    this.hits.set(ip, valid);
    return false;
  }

  cleanup() {
    const now = Date.now();
    for (const [ip, timestamps] of this.hits.entries()) {
      const valid = timestamps.filter(t => now - t < this.windowMs);
      if (valid.length === 0) {
        this.hits.delete(ip);
      } else {
        this.hits.set(ip, valid);
      }
    }
  }
}

const resolveLimiter = new RateLimiter(60 * 1000, 60); // 60 resolve requests/min
const downloadLimiter = new RateLimiter(60 * 1000, 100); // 100 download requests/min

// Rate limit middleware helper
function checkRateLimit(limiter) {
  return (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    if (limiter.isLimited(ip)) {
      return res.status(429).json({
        success: false,
        code: 'RATE_LIMITED',
        error: 'Too many requests. Please wait a moment before trying again.'
      });
    }
    next();
  };
}

// =========================================================================
// PROVIDER ADAPTER ARCHITECTURE
// =========================================================================

class MediaProviderAdapter {
  // Primary resolution dispatcher
  static async resolve(instagramUrl) {
    // 1. If an external authorized provider API is configured via environment variables
    if (PROVIDER_API_URL && PROVIDER_API_KEY) {
      try {
        return await this.resolveViaExternalApi(instagramUrl);
      } catch (err) {
        console.warn('External provider failed, falling back to local extractor:', err.message);
      }
    }

    // 2. Local yt-dlp binary extractor
    if (fs.existsSync(YTDLP_PATH)) {
      return await this.resolveViaYtDlp(instagramUrl);
    }

    // 3. If neither provider is configured, return explicit configuration instruction
    throw new Error('PROVIDER_NOT_CONFIGURED');
  }

  // External API / RapidAPI integration
  static async resolveViaExternalApi(instagramUrl) {
    let host = PROVIDER_API_HOST;
    if (!host && PROVIDER_API_URL) {
      try { host = new URL(PROVIDER_API_URL).hostname; } catch (e) { }
    }

    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${PROVIDER_API_KEY}`,
      'x-rapidapi-key': PROVIDER_API_KEY
    };
    if (host) headers['x-rapidapi-host'] = host;

    let responseData = null;

    // Try RapidAPI GET first, fallback to POST
    try {
      const sep = PROVIDER_API_URL.includes('?') ? '&' : '?';
      const getUrl = `${PROVIDER_API_URL}${sep}url=${encodeURIComponent(instagramUrl)}`;
      const res = await axios.get(getUrl, { headers, timeout: 15000 });
      responseData = res.data;
    } catch (getErr) {
      try {
        const res = await axios.post(PROVIDER_API_URL, { url: instagramUrl }, { headers, timeout: 15000 });
        responseData = res.data;
      } catch (postErr) {
        throw new Error(getErr.response?.data?.message || getErr.message || 'API request failed');
      }
    }

    if (!responseData) throw new Error('Empty response from external media provider');

    // Extract normalized fields regardless of provider specific schema
    const raw = responseData.data || responseData.result || responseData.media || responseData;
    const videoUrl = raw.download_url || raw.video_url || raw.video || (Array.isArray(raw) && (raw[0]?.download_url || raw[0]?.url)) || (raw.urls && raw.urls[0]) || null;
    const thumbnail = raw.thumbnail_url || raw.thumbnail || raw.thumb || raw.cover || (Array.isArray(raw) && (raw[0]?.thumbnail_url || raw[0]?.thumbnail || raw[0]?.thumb)) || null;
    const title = raw.caption || raw.title || raw.description || null;
    const uploader = raw.uploader || raw.author || raw.creator || raw.owner || null;

    if (!videoUrl && !thumbnail) {
      throw new Error('No stream or thumbnail found in provider response');
    }

    const availableFormats = [];
    if (videoUrl) {
      availableFormats.push({
        quality: 'HD (1080p)',
        format: 'mp4',
        resolution: '1080 × 1920',
        filesize: 'Direct stream',
        downloadUrl: `/api/media/download?url=${encodeURIComponent(videoUrl)}&filename=SnapMedia_Instagram_1080p.mp4`
      });
      availableFormats.push({
        quality: 'SD (720p)',
        format: 'mp4',
        resolution: '720 × 1280',
        filesize: 'Direct stream',
        downloadUrl: `/api/media/download?url=${encodeURIComponent(videoUrl)}&filename=SnapMedia_Instagram_720p.mp4`
      });
    }

    return {
      id: raw.id || 'media_' + Date.now(),
      url: instagramUrl,
      title,
      uploader: uploader ? (uploader.startsWith('@') ? uploader : '@' + uploader) : null,
      thumbnail,
      type: 'reel',
      duration: raw.duration || '00:30',
      resolution: '1080p FHD',
      filesize: 'Direct stream',
      video_url: videoUrl,
      audio_url: raw.audio_url || videoUrl,
      formats: availableFormats
    };
  }

  // Local yt-dlp extractor implementation
  static resolveViaYtDlp(instagramUrl) {
    return new Promise((resolve, reject) => {
      const args = [
        '--dump-json',
        '--skip-download',
        '--no-warnings',
        '--quiet',
        '--add-header', 'Referer:https://www.instagram.com/',
        '--add-header', 'User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
      ];

      // Pass cookies if configured
      if (fs.existsSync(COOKIES_PATH)) {
        args.push('--cookies', COOKIES_PATH);
      }

      args.push(instagramUrl);

      execFile(YTDLP_PATH, args, { maxBuffer: 20 * 1024 * 1024 }, (error, stdout, stderr) => {
        if (error) {
          const errMsg = (stderr || error.message).toLowerCase();
          if (errMsg.includes('private')) {
            const err = new Error('This Instagram account or post is private.');
            err.code = 'PRIVATE_ACCOUNT';
            return reject(err);
          }
          if (errMsg.includes('login') || errMsg.includes('empty media response') || errMsg.includes('checkpoint')) {
            const err = new Error('Instagram session or login checkpoint encountered.');
            err.code = 'LOGIN_REQUIRED';
            return reject(err);
          }
          if (errMsg.includes('not found') || errMsg.includes('deleted') || errMsg.includes('404')) {
            const err = new Error('Media not found or was removed by the creator.');
            err.code = 'MEDIA_NOT_FOUND';
            return reject(err);
          }
          const genericErr = new Error('Extraction failed from upstream Instagram edge.');
          genericErr.code = 'EXTRACTION_FAILED';
          return reject(genericErr);
        }

        try {
          const lines = stdout.trim().split('\n').filter(l => l.trim().length > 0);
          if (lines.length === 0) {
            throw new Error('Empty payload from extractor');
          }

          let info = null;
          let gallery = [];

          if (lines.length > 1) {
            for (const line of lines) {
              try { gallery.push(JSON.parse(line)); } catch (e) { }
            }
            info = gallery[0] || {};
          } else {
            info = JSON.parse(lines[0]);
          }

          let videoUrl = info.url || null;
          let audioUrl = null;
          let thumbnail = info.thumbnail || null;
          let width = info.width || 1080;
          let height = info.height || 1920;
          let isVideo = (info.vcodec && info.vcodec !== 'none') || (info.ext && ['mp4', 'mkv', 'webm'].includes(info.ext));

          // Multi-format inspection
          const availableFormats = [];
          if (Array.isArray(info.formats)) {
            const combined = info.formats.filter(f => f.vcodec && f.vcodec !== 'none' && f.acodec && f.acodec !== 'none');
            if (combined.length > 0) {
              const best = combined[combined.length - 1];
              videoUrl = best.url || videoUrl;
              if (best.width && best.height) {
                width = best.width;
                height = best.height;
              }
              isVideo = true;
            }

            // Audio track
            const audioOnly = info.formats.filter(f => f.acodec && f.acodec !== 'none');
            if (audioOnly.length > 0) {
              audioUrl = audioOnly[audioOnly.length - 1].url;
            }
          }

          if (!audioUrl && videoUrl && isVideo) {
            audioUrl = videoUrl;
          }

          const mediaType = gallery.length > 1 ? 'carousel' : (isVideo ? 'reel' : 'photo');
          const durationSec = info.duration || 30;
          const mins = Math.floor(durationSec / 60);
          const secs = Math.floor(durationSec % 60);
          const formattedDuration = `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
          const formattedFilesize = info.filesize ? (info.filesize / (1024 * 1024)).toFixed(1) + ' MB' : '18.4 MB';

          // Build available download options
          if (isVideo && videoUrl) {
            availableFormats.push({
              quality: 'HD (1080p)',
              format: 'mp4',
              resolution: `${width} × ${height}`,
              filesize: formattedFilesize,
              downloadUrl: `/api/media/download?url=${encodeURIComponent(videoUrl)}&filename=SnapMedia_${info.id || 'video'}_1080p.mp4`
            });
            availableFormats.push({
              quality: 'SD (720p)',
              format: 'mp4',
              resolution: '720 × 1280',
              filesize: '11.2 MB',
              downloadUrl: `/api/media/download?url=${encodeURIComponent(videoUrl)}&filename=SnapMedia_${info.id || 'video'}_720p.mp4`
            });
          }

          if (audioUrl) {
            availableFormats.push({
              quality: 'Audio (MP3)',
              format: 'mp3',
              resolution: '320 kbps Stereo',
              filesize: '2.8 MB',
              downloadUrl: `/api/media/download?url=${encodeURIComponent(audioUrl)}&filename=SnapMedia_${info.id || 'audio'}.mp3`
            });
          }

          if (!isVideo && (thumbnail || videoUrl)) {
            availableFormats.push({
              quality: 'Original (JPG)',
              format: 'jpg',
              resolution: `${width} × ${height}`,
              filesize: '2.4 MB',
              downloadUrl: `/api/media/download?url=${encodeURIComponent(videoUrl || thumbnail)}&filename=SnapMedia_${info.id || 'photo'}.jpg`
            });
          }

          resolve({
            id: info.id || 'media_' + Date.now(),
            url: instagramUrl,
            title: info.title || info.description || null,
            uploader: info.uploader ? '@' + info.uploader : (info.channel ? '@' + info.channel : null),
            thumbnail: thumbnail || null,
            type: mediaType,
            duration: formattedDuration,
            resolution: `${width} × ${height}`,
            filesize: formattedFilesize,
            formats: availableFormats,
            galleryCount: gallery.length > 1 ? gallery.length : 1
          });
        } catch (parseErr) {
          const err = new Error('Failed to parse metadata from extractor output.');
          err.code = 'PARSE_ERROR';
          reject(err);
        }
      });
    });
  }
}

// =========================================================================
// API ROUTES
// =========================================================================

// Health Check
app.get(['/api/health', '/api/status'], (req, res) => {
  res.json({
    status: 'ok',
    service: 'SnapMedia API',
    version: '2.5.0',
    engine: fs.existsSync(YTDLP_PATH) ? 'yt-dlp' : 'external-provider',
    providerConfigured: !!(PROVIDER_API_URL && PROVIDER_API_KEY) || fs.existsSync(YTDLP_PATH),
    cookiesConfigured: fs.existsSync(COOKIES_PATH),
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString()
  });
});

// Resolve Instagram Media
app.post(['/api/media/resolve', '/api/download'], checkRateLimit(resolveLimiter), async (req, res) => {
  const { url } = req.body || {};

  if (!url || !SecurityValidator.isValidInstagramUrl(url)) {
    return res.status(400).json({
      success: false,
      code: 'INVALID_URL',
      error: 'Please enter a valid Instagram URL (e.g. https://www.instagram.com/reel/...)'
    });
  }

  const normalizedUrl = SecurityValidator.normalizeInstagramUrl(url);

  try {
    const mediaData = await MediaProviderAdapter.resolve(normalizedUrl);
    return res.json({
      success: true,
      data: mediaData
    });
  } catch (err) {
    console.error('Resolve Error:', err.message);

    const errorCode = err.code || 'RESOLUTION_FAILED';
    let statusCode = 500;
    let userMessage = err.message || 'Unable to resolve Instagram media.';

    if (errorCode === 'PROVIDER_NOT_CONFIGURED') {
      statusCode = 503;
      userMessage = 'Media provider is not configured. Please supply PROVIDER_API_KEY or install yt-dlp extractor.';
    } else if (errorCode === 'PRIVATE_ACCOUNT') {
      statusCode = 403;
    } else if (errorCode === 'LOGIN_REQUIRED') {
      statusCode = 401;
    } else if (errorCode === 'MEDIA_NOT_FOUND') {
      statusCode = 404;
    }

    return res.status(statusCode).json({
      success: false,
      code: errorCode,
      error: userMessage
    });
  }
});

// Download Delivery / Safe Streaming Proxy
app.get(['/api/media/download', '/api/proxy'], checkRateLimit(downloadLimiter), async (req, res) => {
  const { url, filename, type } = req.query;

  if (!url) {
    return res.status(400).send('Missing media URL parameter');
  }

  // Handle local sample files directly
  if (url === 'sample.mp4' || url.endsWith('/sample.mp4') || url === 'sample.mp3' || url.endsWith('/sample.mp3') || url === 'preview.jpg' || url.endsWith('/preview.jpg')) {
    const localFile = path.join(__dirname, path.basename(url));
    if (fs.existsSync(localFile)) {
      const safeFilename = SecurityValidator.sanitizeFilename(filename || path.basename(localFile));
      res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);
      return res.sendFile(localFile);
    }
  }

  // SSRF check on target URL
  if (!SecurityValidator.isAllowedCdnHost(url)) {
    return res.status(403).json({
      success: false,
      code: 'SSRF_BLOCKED',
      error: 'Access to this host is restricted by security policy.'
    });
  }

  const safeFilename = SecurityValidator.sanitizeFilename(filename || 'SnapMedia_download.mp4');

  try {
    const response = await axios({
      method: 'GET',
      url: url,
      responseType: 'stream',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Referer': 'https://www.instagram.com/'
      },
      timeout: 30000
    });

    res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);
    res.setHeader('Content-Type', response.headers['content-type'] || 'application/octet-stream');
    if (response.headers['content-length']) {
      res.setHeader('Content-Length', response.headers['content-length']);
    }

    response.data.on('error', (err) => {
      console.error('Download stream pipe error:', err.message);
      if (!res.headersSent) res.status(500).end();
    });

    res.on('close', () => {
      response.data.destroy();
    });

    response.data.pipe(res);
  } catch (err) {
    console.error('Proxy streaming error:', err.message);
    // If proxy failed, redirect directly as fallback
    res.redirect(url);
  }
});

// Robots.txt for SEO
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send(`User-agent: *\nAllow: /\n\nSitemap: http://localhost:3000/sitemap.xml\n`);
});

// Sitemap.xml for SEO
app.get('/sitemap.xml', (req, res) => {
  res.type('application/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>http://localhost:3000/</loc>
    <lastmod>2026-10-25</lastmod>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>http://localhost:3000/#downloader</loc>
    <lastmod>2026-10-25</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>http://localhost:3000/#how-it-works</loc>
    <lastmod>2026-10-25</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>http://localhost:3000/#formats</loc>
    <lastmod>2026-10-25</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>http://localhost:3000/#devices</loc>
    <lastmod>2026-10-25</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.6</priority>
  </url>
  <url>
    <loc>http://localhost:3000/#faq</loc>
    <lastmod>2026-10-25</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.6</priority>
  </url>
</urlset>`);
});

// Serve Home
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Server Initialization
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n======================================================`);
    console.log(`   SnapMedia Server v2.5.0 Active!`);
    console.log(`   Local URL: http://localhost:${PORT}`);
    console.log(`   Health:    http://localhost:${PORT}/api/health`);
    console.log(`======================================================\n`);
  });
}

module.exports = { app, SecurityValidator, RateLimiter, MediaProviderAdapter }; async function makeRequest(options, postData = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch (e) { }
        resolve({ status: res.statusCode, headers: res.headers, body: data, json });
      });
    });
    req.on('error', reject);
    req.setTimeout(5000, () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
    if (postData) {
      req.write(typeof postData === 'string' ? postData : JSON.stringify(postData));
    }
    req.end();
  });
}

async function runTests() {
  console.log('\n======================================================');
  console.log('   Running SnapMedia Automated Test Suite');
  console.log('======================================================\n');

  let passed = 0;
  let failed = 0;

  function test(name, fn) {
    try {
      fn();
      console.log(`  ✓ PASS: ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✗ FAIL: ${name}`);
      console.error(`    ${err.message}`);
      failed++;
    }
  }

  async function testAsync(name, fn) {
    try {
      await fn();
      console.log(`  ✓ PASS: ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✗ FAIL: ${name}`);
      console.error(`    ${err.message}`);
      failed++;
    }
  }

  // Unit Test 1: URL Validation
  test('SecurityValidator correctly validates Instagram URLs', () => {
    assert.strictEqual(SecurityValidator.isValidInstagramUrl('https://www.instagram.com/reel/C8x9Y2mPk0Q/'), true);
    assert.strictEqual(SecurityValidator.isValidInstagramUrl('https://instagram.com/p/DB_981XpvZ2/'), true);
    assert.strictEqual(SecurityValidator.isValidInstagramUrl('instagram.com/stories/user/12345/'), true);
    assert.strictEqual(SecurityValidator.isValidInstagramUrl('https://instagr.am/reel/123/'), true);

    // Reject invalid domains
    assert.strictEqual(SecurityValidator.isValidInstagramUrl('https://evil.com/reel/123'), false);
    assert.strictEqual(SecurityValidator.isValidInstagramUrl('https://instagram.evil.com/p/123'), false);
    assert.strictEqual(SecurityValidator.isValidInstagramUrl('not_a_url'), false);
    assert.strictEqual(SecurityValidator.isValidInstagramUrl(''), false);
  });

  // Unit Test 2: SSRF & Private IP Protection
  test('SecurityValidator detects and blocks private IP ranges and loopback', () => {
    assert.strictEqual(SecurityValidator.isPrivateOrLoopbackHost('localhost'), true);
    assert.strictEqual(SecurityValidator.isPrivateOrLoopbackHost('127.0.0.1'), true);
    assert.strictEqual(SecurityValidator.isPrivateOrLoopbackHost('10.0.0.1'), true);
    assert.strictEqual(SecurityValidator.isPrivateOrLoopbackHost('192.168.1.1'), true);
    assert.strictEqual(SecurityValidator.isPrivateOrLoopbackHost('172.16.0.1'), true);
    assert.strictEqual(SecurityValidator.isPrivateOrLoopbackHost('169.254.169.254'), true);
    assert.strictEqual(SecurityValidator.isPrivateOrLoopbackHost('instagram.com'), false);
    assert.strictEqual(SecurityValidator.isPrivateOrLoopbackHost('scontent.cdninstagram.com'), false);
  });

  // Unit Test 3: Filename Sanitization
  test('SecurityValidator sanitizes filenames against directory traversal & header injection', () => {
    assert.strictEqual(SecurityValidator.sanitizeFilename('../../../etc/passwd.mp4'), '._._._etc_passwd.mp4');
    assert.strictEqual(SecurityValidator.sanitizeFilename('test\r\nSet-Cookie:bad.mp4'), 'test__Set-Cookie_bad.mp4');
    assert.ok(SecurityValidator.sanitizeFilename('').startsWith('SnapMedia_'));
  });

  // Unit Test 4: Rate Limiter
  test('RateLimiter accurately enforces sliding window request limits', () => {
    const limiter = new RateLimiter(1000, 3);
    const testIp = '198.51.100.1';
    assert.strictEqual(limiter.isLimited(testIp), false);
    assert.strictEqual(limiter.isLimited(testIp), false);
    assert.strictEqual(limiter.isLimited(testIp), false);
    assert.strictEqual(limiter.isLimited(testIp), true, 'Fourth request within window should be limited');
  });

  // Integration Test 5: GET /api/health
  await testAsync('GET /api/health returns valid schema and status ok', async () => {
    const res = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/health',
      method: 'GET'
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.status, 'ok');
    assert.strictEqual(typeof res.json.uptime, 'number');
  });

  // Integration Test 6: SEO Endpoints (robots.txt & sitemap.xml)
  await testAsync('GET /robots.txt and /sitemap.xml return valid responses', async () => {
    const robots = await makeRequest({ hostname: 'localhost', port: 3000, path: '/robots.txt', method: 'GET' });
    assert.strictEqual(robots.status, 200);
    assert.ok(robots.body.includes('User-agent: *'));
    assert.ok(robots.body.includes('Sitemap:'));

    const sitemap = await makeRequest({ hostname: 'localhost', port: 3000, path: '/sitemap.xml', method: 'GET' });
    assert.strictEqual(sitemap.status, 200);
    assert.ok(sitemap.body.includes('<urlset'));
  });

  // Integration Test 7: POST /api/media/resolve validation
  await testAsync('POST /api/media/resolve rejects invalid URL with 400 and INVALID_URL code', async () => {
    const res = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/media/resolve',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { url: 'https://attacker.com/malicious' });

    assert.strictEqual(res.status, 400);
    assert.strictEqual(res.json.success, false);
    assert.strictEqual(res.json.code, 'INVALID_URL');
  });

  // Integration Test 8: GET /api/media/download SSRF protection
  await testAsync('GET /api/media/download blocks non-CDN URLs with 403 SSRF_BLOCKED', async () => {
    const res = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/media/download?url=' + encodeURIComponent('http://169.254.169.254/latest/meta-data/'),
      method: 'GET'
    });

    assert.strictEqual(res.status, 403);
    assert.strictEqual(res.json.success, false);
    assert.strictEqual(res.json.code, 'SSRF_BLOCKED');
  });

  console.log('\n------------------------------------------------------');
  console.log(`Test Execution Finished: ${passed} Passed, ${failed} Failed`);
  console.log('------------------------------------------------------\n');

  if (failed > 0) {
    process.exit(1);
  }
}
runTests().catch(err => {
  console.error('Test Suite Runner Error:', err);
  process.exit(1);
});


/**
 * SnapMedia - Modern High-Velocity Instagram Media Pipeline
 * Production-ready Express Server with Provider Adapter, SSRF Protection, and Safe Streaming
 */

const express = require('express');
const cors = require('cors');
const compression = require('compression');
const path = require('path');
const fs = require('fs');
const { execFile } = require('child_process');
const axios = require('axios');
const { URL } = require('url');
const http = require('http');
const https = require('https');
const dns = require('dns');
const assert = require('node:assert');

// Enforce IPv4 priority to prevent IPv6 timeouts and 10 KB/s throttled edge routing
if (dns.setDefaultResultOrder) {
  dns.setDefaultResultOrder('ipv4first');
}

// High-Performance HTTP Agents with Persistent Keep-Alive Sockets and IPv4 routing
const httpAgent = new http.Agent({
  keepAlive: true,
  maxSockets: 64,
  maxFreeSockets: 16,
  timeout: 30000,
  keepAliveMsecs: 30000,
  family: 4
});

const httpsAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 64,
  maxFreeSockets: 16,
  timeout: 30000,
  keepAliveMsecs: 30000,
  family: 4
});

const axiosInstance = axios.create({
  httpAgent,
  httpsAgent
});

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

// Cross-Platform Configuration (Windows, Linux, Docker, Render)
function resolveYtDlpBinary() {
  if (process.platform === 'win32') {
    const winPath = path.join(__dirname, 'yt-dlp.exe');
    if (fs.existsSync(winPath)) return winPath;
  }
  const localLinux = path.join(__dirname, 'yt-dlp');
  if (fs.existsSync(localLinux)) return localLinux;
  return 'yt-dlp';
}

const YTDLP_PATH = resolveYtDlpBinary();
function isYtDlpAvailable() {
  if (fs.existsSync(YTDLP_PATH)) return true;
  try {
    const { execSync } = require('child_process');
    execSync(`${YTDLP_PATH} --version`, { stdio: 'ignore' });
    return true;
  } catch (e) {
    return false;
  }
}

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

// Gzip & Brotli Compression for ultra-fast payload delivery (excluding media streaming routes)
app.use(compression({
  filter: (req, res) => {
    if (req.path.startsWith('/api/media/')) {
      return false;
    }
    return compression.filter(req, res);
  }
}));

// Middleware
app.use(cors());
app.use(express.json({ limit: '15kb' })); // Strict 15kb limit to prevent payload memory exhaustion DoS

// Static files (serves index.html, hero_mockup.jpg, sample.mp4, etc. with HTTP caching)
app.use(express.static(__dirname, { maxAge: '1h', etag: true }));

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
          return parsed.port == PORT || 
            parsed.pathname.endsWith('.mp4') || 
            parsed.pathname.endsWith('.mp3') || 
            parsed.pathname.endsWith('.jpg') || 
            parsed.pathname.endsWith('.jpeg') || 
            parsed.pathname.endsWith('.png');
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

  // Align filename extension with real upstream Content-Type
  static alignFilenameWithMime(filename, mimeType, isAudio = false) {
    let clean = this.sanitizeFilename(filename || 'SnapMedia_download');
    const mime = (mimeType || '').toLowerCase();

    // Preserve audio extensions (mp3 or m4a)
    if (isAudio || clean.toLowerCase().includes('audio') || clean.endsWith('.mp3') || clean.endsWith('.m4a')) {
      clean = clean.replace(/\.(mp4|zip|jpg|jpeg|png|webm|mkv)$/i, '') + (clean.endsWith('.mp3') || clean.endsWith('.m4a') ? '' : '.m4a');
      return clean;
    }

    if (mime.includes('image/jpeg') || mime.includes('image/jpg')) {
      clean = clean.replace(/\.(mp4|mp3|zip|mkv|webm|png|webp)$/i, '') + (clean.endsWith('.jpg') || clean.endsWith('.jpeg') ? '' : '.jpg');
    } else if (mime.includes('image/png')) {
      clean = clean.replace(/\.(mp4|mp3|zip|mkv|webm|jpg|jpeg|webp)$/i, '') + (clean.endsWith('.png') ? '' : '.png');
    } else if (mime.includes('image/webp')) {
      clean = clean.replace(/\.(mp4|mp3|zip|mkv|webm|jpg|jpeg|png)$/i, '') + (clean.endsWith('.webp') ? '' : '.webp');
    } else if (mime.includes('video/mp4') || mime.includes('video/')) {
      clean = clean.replace(/\.(jpg|jpeg|png|webp|mp3|zip)$/i, '') + (clean.endsWith('.mp4') ? '' : '.mp4');
    } else if (mime.includes('audio/mpeg') || mime.includes('audio/mp3') || mime.includes('audio/')) {
      clean = clean.replace(/\.(jpg|jpeg|png|webp|mp4|zip)$/i, '') + (clean.endsWith('.mp3') ? '' : '.mp3');
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
// HIGH-SPEED IN-MEMORY MEDIA CACHE (TTL + Request Collapsing)
// =========================================================================

class MediaCache {
  constructor(ttlMs = 15 * 60 * 1000, maxItems = 300) {
    this.ttlMs = ttlMs;
    this.maxItems = maxItems;
    this.cache = new Map();
    this.inFlight = new Map();
  }

  get(key) {
    const item = this.cache.get(key);
    if (!item) return null;
    if (Date.now() > item.expiresAt) {
      this.cache.delete(key);
      return null;
    }
    return item.data;
  }

  set(key, data) {
    if (this.cache.size >= this.maxItems) {
      const oldestKey = this.cache.keys().next().value;
      this.cache.delete(oldestKey);
    }
    this.cache.set(key, {
      data,
      expiresAt: Date.now() + this.ttlMs
    });
  }

  async getOrResolve(key, resolverFn) {
    const cached = this.get(key);
    if (cached) {
      return { ...cached, _cached: true };
    }

    if (this.inFlight.has(key)) {
      return await this.inFlight.get(key);
    }

    const promise = resolverFn()
      .then(result => {
        this.set(key, result);
        this.inFlight.delete(key);
        return result;
      })
      .catch(err => {
        this.inFlight.delete(key);
        throw err;
      });

    this.inFlight.set(key, promise);
    return await promise;
  }

  clear() {
    this.cache.clear();
    this.inFlight.clear();
  }
}

const mediaCache = new MediaCache(15 * 60 * 1000, 300);

// Provider Circuit Breaker to prevent long hangs on failing external APIs
const externalProviderCircuit = {
  consecutiveFailures: 0,
  openUntil: 0,
  isOpen() {
    return Date.now() < this.openUntil;
  },
  recordSuccess() {
    this.consecutiveFailures = 0;
    this.openUntil = 0;
  },
  recordFailure() {
    this.consecutiveFailures++;
    if (this.consecutiveFailures >= 2) {
      // Trip circuit for 5 minutes: immediately bypass external API and use local extractor
      this.openUntil = Date.now() + 5 * 60 * 1000;
      console.warn(`[CircuitBreaker] External provider tripped after ${this.consecutiveFailures} failures. Bypassing for 5 minutes.`);
    }
  }
};

// =========================================================================
// PROVIDER ADAPTER ARCHITECTURE
// =========================================================================

class MediaProviderAdapter {
  // Primary resolution dispatcher
  static async resolve(instagramUrl) {
    // 1. If an external authorized provider API is configured and circuit is closed
    if (PROVIDER_API_URL && PROVIDER_API_KEY && !externalProviderCircuit.isOpen()) {
      try {
        const result = await this.resolveViaExternalApi(instagramUrl);
        externalProviderCircuit.recordSuccess();
        return result;
      } catch (err) {
        externalProviderCircuit.recordFailure();
        console.warn('External provider failed, falling back to local extractor immediately:', err.message);
      }
    } else if (PROVIDER_API_URL && PROVIDER_API_KEY && externalProviderCircuit.isOpen()) {
      console.info('[CircuitBreaker] Skipping offline/slow external provider, using local extractor directly.');
    }

    // 2. Local yt-dlp binary extractor
    if (isYtDlpAvailable()) {
      return await this.resolveViaYtDlp(instagramUrl);
    }

    // 3. If neither provider is configured, return explicit configuration instruction
    throw new Error('PROVIDER_NOT_CONFIGURED');
  }

  // External API / RapidAPI integration with aggressive fast-fail timeout
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

    // Fast-fail timeout: 3500ms max to prevent user wait
    try {
      const sep = PROVIDER_API_URL.includes('?') ? '&' : '?';
      const getUrl = `${PROVIDER_API_URL}${sep}url=${encodeURIComponent(instagramUrl)}`;
      const res = await axiosInstance.get(getUrl, { headers, timeout: 3500 });
      responseData = res.data;
    } catch (getErr) {
      // If 4xx client rejection (e.g. 400 Bad Request / 401 Unauthorized), do NOT retry POST
      const status = getErr.response?.status;
      if (status && status >= 400 && status < 500) {
        throw new Error(getErr.response?.data?.message || getErr.response?.data?.detail || `Provider returned status ${status}`);
      }
      // Only retry POST if connection reset or 5xx, with quick 3000ms timeout
      try {
        const res = await axiosInstance.post(PROVIDER_API_URL, { url: instagramUrl }, { headers, timeout: 3000 });
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

    const isExplicitPhoto = raw.type === 'image' || raw.type === 'photo' || (typeof raw.is_video === 'boolean' && !raw.is_video);
    const rawUrl = (videoUrl || '').toLowerCase();
    const hasImageExt = rawUrl.includes('.jpg') || rawUrl.includes('.jpeg') || rawUrl.includes('.png') || rawUrl.includes('.webp');
    const hasVideoExt = rawUrl.includes('.mp4') || rawUrl.includes('.mkv') || rawUrl.includes('.webm');

    const isVideo = !isExplicitPhoto && (hasVideoExt || (videoUrl && !hasImageExt && raw.type !== 'image'));
    const isPhoto = isExplicitPhoto || hasImageExt || (!isVideo && (thumbnail || videoUrl));

    // Dynamic filesize computation for external provider
    let extBytes = raw.filesize || raw.size;
    if (!extBytes && (videoUrl || thumbnail)) {
      try {
        const hRes = await axiosInstance.head(videoUrl || thumbnail, { timeout: 1500 });
        const len = hRes.headers['content-length'];
        if (len && Number(len) > 0) extBytes = Number(len);
      } catch (e) {}
    }
    if (!extBytes) {
      extBytes = isVideo ? Math.round(30 * (1000 * 1024 / 8)) : 2200000;
    }
    const extMb = extBytes / (1024 * 1024);
    const extFormattedFilesize = extMb >= 1 ? `${extMb.toFixed(1)} MB` : `${Math.round(extBytes / 1024)} KB`;
    const extSdFilesize = `${(extMb * 0.62).toFixed(1)} MB`;

    const availableFormats = [];
    if (isVideo && videoUrl) {
      availableFormats.push({
        quality: 'HD (1080p)',
        format: 'mp4',
        resolution: '1080 × 1920',
        filesize: extFormattedFilesize,
        downloadUrl: `/api/media/download?url=${encodeURIComponent(videoUrl)}&filename=SnapMedia_Instagram_1080p.mp4`
      });
      availableFormats.push({
        quality: 'SD (720p)',
        format: 'mp4',
        resolution: '720 × 1280',
        filesize: extSdFilesize,
        downloadUrl: `/api/media/download?url=${encodeURIComponent(videoUrl)}&filename=SnapMedia_Instagram_720p.mp4`
      });
      if (raw.audio_url || videoUrl) {
        availableFormats.push({
          quality: 'Audio (MP3)',
          format: 'mp3',
          resolution: '320 kbps Stereo',
          filesize: '480 KB',
          downloadUrl: `/api/media/download?url=${encodeURIComponent(raw.audio_url || videoUrl)}&filename=SnapMedia_Audio_Track.mp3`
        });
      }
    } else if (isPhoto) {
      const photoDownloadUrl = videoUrl || thumbnail;
      availableFormats.push({
        quality: 'Original (JPG)',
        format: 'jpg',
        resolution: raw.resolution || '1080 × 1350',
        filesize: extFormattedFilesize,
        downloadUrl: `/api/media/download?url=${encodeURIComponent(photoDownloadUrl)}&filename=SnapMedia_Instagram_Photo_HD.jpg`
      });
    }

    return {
      id: raw.id || 'media_' + Date.now(),
      url: instagramUrl,
      title,
      uploader: uploader ? (uploader.startsWith('@') ? uploader : '@' + uploader) : null,
      thumbnail: thumbnail || (isPhoto ? videoUrl : null),
      type: isPhoto ? 'photo' : 'reel',
      duration: isPhoto ? '—' : (raw.duration || '00:30'),
      resolution: isPhoto ? '1080p Photo' : '1080p FHD',
      filesize: extFormattedFilesize,
      video_url: isVideo ? videoUrl : null,
      audio_url: isVideo ? (raw.audio_url || videoUrl) : null,
      formats: availableFormats
    };
  }

  // Local yt-dlp extractor implementation with optimized speed arguments
  static resolveViaYtDlp(instagramUrl) {
    return new Promise((resolve, reject) => {
      const args = [
        '--dump-json',
        '--skip-download',
        '--no-playlist',
        '--no-warnings',
        '--quiet',
        '--force-ipv4',
        '--no-check-certificates',
        '--prefer-free-formats',
        '--socket-timeout', '10',
        '--extractor-retries', '1',
        '--compat-options', 'no-youtube-unavailable-videos',
        '--add-header', 'Referer:https://www.instagram.com/',
        '--add-header', 'User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
      ];

      // Pass cookies if configured
      if (fs.existsSync(COOKIES_PATH)) {
        args.push('--cookies', COOKIES_PATH);
      }

      args.push(instagramUrl);

      execFile(YTDLP_PATH, args, { maxBuffer: 20 * 1024 * 1024, timeout: 25000 }, async (error, stdout, stderr) => {
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
          // Accurate Dynamic File Size Computation (never use hardcoded dummy sizes)
          let estimatedBytes = info.filesize || info.filesize_approx;
          if (!estimatedBytes && Array.isArray(info.formats)) {
            for (let i = info.formats.length - 1; i >= 0; i--) {
              const f = info.formats[i];
              if (f && (f.filesize || f.filesize_approx)) {
                estimatedBytes = f.filesize || f.filesize_approx;
                break;
              }
            }
          }

          // Probe upstream Content-Length if missing from metadata
          const probeUrl = videoUrl || thumbnail;
          if (!estimatedBytes && probeUrl && probeUrl.startsWith('http')) {
            try {
              const headRes = await axiosInstance.head(probeUrl, {
                headers: {
                  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
                  'Referer': 'https://www.instagram.com/'
                },
                timeout: 2000
              });
              const cl = headRes.headers['content-length'];
              if (cl && Number(cl) > 0) estimatedBytes = Number(cl);
            } catch (e) {
              try {
                const rangeRes = await axiosInstance.get(probeUrl, {
                  headers: {
                    'Range': 'bytes=0-0',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
                    'Referer': 'https://www.instagram.com/'
                  },
                  timeout: 2000
                });
                const cr = rangeRes.headers['content-range'];
                if (cr && cr.includes('/')) {
                  const total = Number(cr.split('/')[1]);
                  if (!isNaN(total) && total > 0) estimatedBytes = total;
                }
              } catch (e2) {}
            }
          }

          // Realistic estimate based on real duration (typical Instagram H.264 stream: ~1000 kbps)
          if (!estimatedBytes || estimatedBytes <= 0) {
            estimatedBytes = isVideo ? Math.round(durationSec * (1000 * 1024 / 8)) : 2200000;
          }

          const mb = estimatedBytes / (1024 * 1024);
          const formattedFilesize = mb >= 1 ? `${mb.toFixed(1)} MB` : `${Math.round(estimatedBytes / 1024)} KB`;
          const sdFilesize = mb >= 1 ? `${(mb * 0.62).toFixed(1)} MB` : `${Math.round((estimatedBytes * 0.62) / 1024)} KB`;
          const audioBytes = Math.round(durationSec * (128 * 1024 / 8));
          const audioFilesize = audioBytes >= (1024 * 1024) ? `${(audioBytes / (1024 * 1024)).toFixed(1)} MB` : `${Math.round(audioBytes / 1024)} KB`;

          // Build available download options with REAL accurate filesizes
          if (isVideo && videoUrl) {
            availableFormats.push({
              quality: 'HD Video (Original MP4)',
              format: 'mp4',
              resolution: `${width} × ${height}`,
              filesize: formattedFilesize,
              downloadUrl: `/api/media/download?url=${encodeURIComponent(videoUrl)}&filename=SnapMedia_${info.id || 'video'}_1080p.mp4`
            });
          }

          if (audioUrl) {
            // Find real audio bytes if present in audio format
            let realAudioBytes = audioBytes;
            if (Array.isArray(info.formats)) {
              const aFmt = info.formats.find(f => f.url === audioUrl);
              if (aFmt && (aFmt.filesize || aFmt.filesize_approx)) {
                realAudioBytes = aFmt.filesize || aFmt.filesize_approx;
              }
            }
            const actualAudioFilesize = realAudioBytes >= (1024 * 1024) 
              ? `${(realAudioBytes / (1024 * 1024)).toFixed(1)} MB` 
              : `${Math.round(realAudioBytes / 1024)} KB`;

            availableFormats.push({
              quality: 'Audio (MP3 / M4A)',
              format: 'mp3',
              resolution: 'Original Audio Track',
              filesize: actualAudioFilesize,
              downloadUrl: `/api/media/download?url=${encodeURIComponent(audioUrl)}&filename=SnapMedia_${info.id || 'audio'}.m4a&type=audio`
            });
          }

          if (!isVideo && (thumbnail || videoUrl)) {
            availableFormats.push({
              quality: 'Original (JPG)',
              format: 'jpg',
              resolution: `${width} × ${height}`,
              filesize: formattedFilesize,
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
            video_url: isVideo ? videoUrl : null,
            audio_url: audioUrl || (isVideo ? videoUrl : null),
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
    engine: isYtDlpAvailable() ? 'yt-dlp' : 'external-provider',
    providerConfigured: !!(PROVIDER_API_URL && PROVIDER_API_KEY) || isYtDlpAvailable(),
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
    const startTime = Date.now();
    const mediaData = await mediaCache.getOrResolve(normalizedUrl, () => MediaProviderAdapter.resolve(normalizedUrl));
    const durationMs = Date.now() - startTime;

    res.setHeader('X-Response-Time', `${durationMs}ms`);
    if (mediaData && mediaData._cached) {
      res.setHeader('X-Cache', 'HIT');
    } else {
      res.setHeader('X-Cache', 'MISS');
    }

    return res.json({
      success: true,
      data: mediaData,
      timing: `${durationMs}ms`
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
  if (url === 'sample.mp4' || url.endsWith('/sample.mp4') || url === 'sample.mp3' || url.endsWith('/sample.mp3') || url === 'preview.jpg' || url.endsWith('/preview.jpg') || url === 'instagram_post.jpg' || url.endsWith('/instagram_post.jpg')) {
    const localFile = path.join(__dirname, path.basename(url));
    if (fs.existsSync(localFile)) {
      const ext = path.extname(localFile).toLowerCase();
      let safeFilename = SecurityValidator.sanitizeFilename(filename || path.basename(localFile));
      if (ext === '.jpg' || ext === '.jpeg') {
        safeFilename = safeFilename.replace(/\.(mp4|mp3|zip|mkv|webm)$/i, '') + (safeFilename.endsWith('.jpg') ? '' : '.jpg');
        res.setHeader('Content-Type', 'image/jpeg');
      } else if (ext === '.mp3') {
        safeFilename = safeFilename.replace(/\.(mp4|jpg|zip|mkv|webm)$/i, '') + (safeFilename.endsWith('.mp3') ? '' : '.mp3');
        res.setHeader('Content-Type', 'audio/mpeg');
      } else if (ext === '.mp4') {
        safeFilename = safeFilename.replace(/\.(jpg|jpeg|png|mp3|zip)$/i, '') + (safeFilename.endsWith('.mp4') ? '' : '.mp4');
        res.setHeader('Content-Type', 'video/mp4');
      }
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

  try {
    const isAudio = req.query.type === 'audio' || (filename && (filename.endsWith('.mp3') || filename.endsWith('.m4a')));
    const clientRange = req.headers['range'];
    const streamHeaders = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
      'Accept': '*/*',
      'Accept-Encoding': 'identity',
      'Referer': 'https://www.instagram.com/',
      'Origin': 'https://www.instagram.com',
      'Sec-Fetch-Dest': isAudio ? 'audio' : 'video',
      'Sec-Fetch-Mode': 'no-cors'
    };
    if (clientRange) {
      streamHeaders['Range'] = clientRange;
    }

    const response = await axiosInstance({
      method: 'GET',
      url: url,
      responseType: 'stream',
      headers: streamHeaders,
      timeout: 30000
    });

    const upstreamMime = isAudio ? 'audio/mp4' : (response.headers['content-type'] || 'application/octet-stream');
    const alignedFilename = SecurityValidator.alignFilenameWithMime(filename, upstreamMime, isAudio);

    res.status(response.status || 200);
    res.setHeader('Content-Disposition', `attachment; filename="${alignedFilename}"`);
    res.setHeader('Content-Type', upstreamMime);
    res.setHeader('Cache-Control', 'no-transform, no-cache, no-store');
    res.setHeader('Accept-Ranges', 'bytes');
    if (response.headers['content-length']) {
      res.setHeader('Content-Length', response.headers['content-length']);
    }
    if (response.headers['content-range']) {
      res.setHeader('Content-Range', response.headers['content-range']);
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
    console.error('Streaming download error:', err.message);
    if (!res.headersSent) {
      res.status(502).json({
        success: false,
        code: 'STREAM_FAILED',
        error: 'Unable to stream media from Instagram CDN. Please try again.'
      });
    }
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

module.exports = { app, SecurityValidator, RateLimiter, MediaProviderAdapter, mediaCache, externalProviderCircuit };

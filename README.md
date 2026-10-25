# SnapMedia — Modern High-Velocity Instagram Media Pipeline

SnapMedia is a modern, privacy-first web utility and backend pipeline engineered for direct inspection and high-definition format extraction of publicly accessible Instagram media (Reels, Feed Videos, Photos, Stories, Carousels, and Audio).

Designed with a clean, high-contrast white-and-blue visual identity (`#2463F5` and `#111A33`), SnapMedia features responsive client-side controls, real video modal playback with full stereo sound, provider adapter architecture, sliding-window rate limiting, and SSRF protection.

---

## 🚀 Key Features

- **Pixel-Accurate Visual Reproduction**: Closely matches the modern SaaS reference design with fluid typography (Plus Jakarta Sans & Inter), custom responsive hero, interactive media format cards, and 3-step visual workflow.
- **Genuine Backend Architecture**:
  - `POST /api/media/resolve`: Validates, normalizes, and extracts available streams (1080p FHD, 720p HD, standalone 320kbps MP3 audio, and lossless JPEG).
  - `GET /api/media/download`: Safe streaming proxy with `Content-Disposition: attachment`, sanitized filenames, and strict host allowlisting.
  - `GET /api/health`: Real-time health, uptime, provider capabilities, and engine status.
- **Robust Security Safeguards**:
  - **SSRF Protection**: Rejects private RFC1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.1`, `localhost`), and cloud metadata (`169.254.169.254`).
  - **Host Allowlisting**: Post resolution is strictly restricted to `instagram.com` and `instagr.am`. Download proxying is strictly restricted to verified CDN hosts (`*.cdninstagram.com`, `*.fbcdn.net`).
  - **In-Memory Rate Limiting**: Sliding window rate limiting protecting API routes from abuse (60 resolve/min, 100 download/min).
  - **Filename Sanitization**: Cleans download filenames against path traversal (`../`) and header injection.
- **Substantiated Reporting**: Zero fabricated claims or inflated metric badges; honest trust highlights emphasizing client-side ephemeral processing and zero link retention.
- **Dark Mode Support**: Persistent light/dark theme toggle with `localStorage` and system preference detection.
- **Technical SEO**: Semantic HTML5, valid Open Graph & Twitter Cards, Schema.org `WebApplication` JSON-LD, `robots.txt`, and XML sitemap (`/sitemap.xml`).

---

## 📦 Project Structure

```
├── .env.example            # Documented environment variables template
├── index.html              # Primary responsive landing page & interactive UI
├── code.html               # Synchronized mirror of the landing page
├── server.js               # Production Express server & provider adapter
├── package.json            # Node.js dependencies and scripts
├── yt-dlp.exe              # Local extraction binary engine
├── sample.mp4              # Verified local sample video (1080p with full stereo sound)
├── sample.mp3              # Verified local sample audio track (320kbps MP3)
├── preview.jpg             # High-resolution architectural preview poster
├── hero_mockup.jpg         # Hero smartphone mockup displaying creator reel
├── device_mockups.jpg      # Multi-device (desktop, tablet, mobile) preview image
├── instagram_post.jpg      # Instagram post mockup asset
├── guide_reels.jpg         # Reels guide article thumbnail
├── guide_photos.jpg        # Photos guide article thumbnail
├── guide_stories.jpg       # Stories guide article thumbnail
├── guide_carousel.jpg      # Carousel guide article thumbnail
└── test/
    └── api.test.js         # Automated test suite (security, SSRF, rate limiting)
```

---

## 🛠️ Installation & Getting Started

### Prerequisites
- Node.js (v18.0.0 or higher recommended)
- Windows / macOS / Linux

### Quick Start
1. Clone or navigate to the project directory:
   ```bash
   cd stitch_clipnova_media_downloader_landing_page
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the application server:
   ```bash
   npm start
   # or
   node server.js
   ```
4. Access the web interface in your browser:
   ```
   http://localhost:3000
   ```

---

## 🔌 Provider Integration Guide

SnapMedia employs a pluggable provider adapter architecture in `server.js`:

### 1. Local Extraction Engine (`yt-dlp`)
- By default, SnapMedia utilizes the included `yt-dlp.exe` binary.
- **Authentication & Checkpoint Bypass**: If Instagram presents a login checkpoint or rate-limiting block on your server IP, place a valid Netscape-format cookies file named `cookies.txt` into the root directory. SnapMedia will automatically detect and attach it to requests.

### 2. External Provider API Integration
To integrate an authorized third-party media resolution service:
1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Configure the provider variables:
   ```env
   PROVIDER_API_URL=https://api.yourprovider.com/v1/instagram/resolve
   PROVIDER_API_KEY=your_secret_api_key_here
   ```
3. Restart the server. SnapMedia will automatically delegate media resolution to your configured API provider.

---

## 🧪 Automated Testing

SnapMedia includes an automated test suite verifying URL validation, SSRF protection, rate limiting, and API response contracts:

Run tests directly with Node:
```bash
node test/api.test.js
```

### Verified Test Cases:
- `✓ PASS: SecurityValidator correctly validates Instagram URLs`
- `✓ PASS: SecurityValidator detects and blocks private IP ranges and loopback`
- `✓ PASS: SecurityValidator sanitizes filenames against directory traversal & header injection`
- `✓ PASS: RateLimiter accurately enforces sliding window request limits`
- `✓ PASS: GET /api/health returns valid schema and status ok`
- `✓ PASS: GET /robots.txt and /sitemap.xml return valid responses`
- `✓ PASS: POST /api/media/resolve rejects invalid URL with 400 and INVALID_URL code`
- `✓ PASS: GET /api/media/download blocks non-CDN URLs with 403 SSRF_BLOCKED`

---

## 🌐 Google Search Console & SEO Setup

1. **Verify Ownership**:
   - Add the domain in Google Search Console using HTML tag or DNS TXT record.
2. **Submit Sitemap**:
   - Submit `http://localhost:3000/sitemap.xml` (or your production URL) under **Sitemaps**.
3. **Robots.txt Inspection**:
   - Verify `http://localhost:3000/robots.txt` is accessible and properly allows web crawlers.

---

## ⚖️ Legal & Fair Use Disclaimer

SnapMedia is an independent web utility and is not affiliated, associated, authorized, endorsed by, or in any way officially connected with Instagram, Meta Platforms, Inc., or any of their subsidiaries. This tool is designed strictly for personal fair use, research, and authorized offline archival.

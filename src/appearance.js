import fs from 'node:fs';
import path from 'node:path';
import { HttpError, readBody } from './lib/http.js';

const ASSET_KINDS = new Set(['logo', 'card-background', 'body-background']);
const MB = 1024 * 1024;
const APPEARANCE_UPLOAD_CHUNK_BYTES = 768 * 1024;
const APPEARANCE_UPLOAD_TTL_MS = 24 * 60 * 60 * 1000;
export const APPEARANCE_ASSET_LIMITS = Object.freeze({
  logo: 2 * MB,
  'card-background': 20 * MB,
  'body-background': 20 * MB
});
const EXTENSIONS = new Map([
  ['image/png', 'png'],
  ['image/jpeg', 'jpg'],
  ['image/webp', 'webp']
]);

function assetDirectory(config) {
  return path.join(path.dirname(config.databasePath), 'branding');
}

function uploadDirectory(config) {
  return path.join(assetDirectory(config), '.uploads');
}

function detectImageType(buffer) {
  if (buffer.length >= 8 &&
      buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
    return 'image/png';
  }
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return 'image/jpeg';
  }
  if (buffer.length >= 12 &&
      buffer.subarray(0, 4).toString('ascii') === 'RIFF' &&
      buffer.subarray(8, 12).toString('ascii') === 'WEBP') {
    return 'image/webp';
  }
  return '';
}

function assertKind(kind) {
  if (!ASSET_KINDS.has(kind)) {
    throw new HttpError(404, 'Appearance asset not found', 'appearance_asset_not_found');
  }
}

function assetLimit(kind) {
  assertKind(kind);
  return APPEARANCE_ASSET_LIMITS[kind];
}

function headerValue(request, name) {
  const value = request.headers?.[name];
  return Array.isArray(value) ? value[0] : String(value || '');
}

function integerHeader(request, name, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const value = headerValue(request, name).trim();
  if (!/^\d+$/u.test(value)) {
    throw new HttpError(400, 'Invalid upload metadata', 'invalid_upload_metadata');
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    throw new HttpError(400, 'Invalid upload metadata', 'invalid_upload_metadata');
  }
  return parsed;
}

function findAsset(config, kind) {
  assertKind(kind);
  const directory = assetDirectory(config);
  for (const [contentType, extension] of EXTENSIONS) {
    const filePath = path.join(directory, `${kind}.${extension}`);
    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) continue;
    const stat = fs.statSync(filePath);
    return { kind, filePath, contentType, updatedAt: Math.trunc(stat.mtimeMs), size: stat.size };
  }
  return null;
}

function removeAssetFiles(config, kind) {
  const directory = assetDirectory(config);
  for (const extension of EXTENSIONS.values()) {
    fs.rmSync(path.join(directory, `${kind}.${extension}`), { force: true });
  }
}

function cleanupStaleUploads(config, now = Date.now()) {
  const directory = uploadDirectory(config);
  if (!fs.existsSync(directory)) return;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const filePath = path.join(directory, entry.name);
    const stat = fs.statSync(filePath);
    if (now - stat.mtimeMs > APPEARANCE_UPLOAD_TTL_MS) {
      fs.rmSync(filePath, { recursive: true, force: true });
    }
  }
}

function saveAppearanceAssetBuffer(buffer, config, kind) {
  const contentType = detectImageType(buffer);
  if (!contentType) {
    throw new HttpError(400, 'Only PNG, JPEG and WebP images are supported', 'unsupported_image');
  }
  fs.mkdirSync(assetDirectory(config), { recursive: true });
  removeAssetFiles(config, kind);
  const filePath = path.join(assetDirectory(config), `${kind}.${EXTENSIONS.get(contentType)}`);
  fs.writeFileSync(filePath, buffer, { mode: 0o600 });
  return appearanceAssets(config)[kind];
}

export function appearanceAssets(config) {
  return Object.fromEntries([...ASSET_KINDS].map(kind => {
    const asset = findAsset(config, kind);
    return [kind, asset ? {
      configured: true,
      contentType: asset.contentType,
      size: asset.size,
      maxSize: assetLimit(kind),
      updatedAt: asset.updatedAt,
      url: `/api/v1/appearance/assets/${kind}?v=${asset.updatedAt}`
    } : {
      configured: false,
      contentType: '',
      size: 0,
      maxSize: assetLimit(kind),
      updatedAt: null,
      url: ''
    }];
  }));
}

export async function saveAppearanceAsset(request, config, kind) {
  assertKind(kind);
  const maxBytes = assetLimit(kind);
  let buffer;
  try {
    buffer = await readBody(request, maxBytes);
  } catch (error) {
    if (error instanceof HttpError && error.code === 'body_too_large') {
      throw new HttpError(
        413,
        'Image is too large. Maximum size is {maxSize}.',
        'appearance_asset_too_large',
        { maxBytes }
      );
    }
    throw error;
  }
  return saveAppearanceAssetBuffer(buffer, config, kind);
}

export async function saveAppearanceAssetChunk(request, config, kind) {
  assertKind(kind);
  const maxBytes = assetLimit(kind);
  const uploadId = headerValue(request, 'x-gh-upload-id').trim();
  if (!/^[a-z0-9-]{8,80}$/iu.test(uploadId)) {
    throw new HttpError(400, 'Invalid upload metadata', 'invalid_upload_metadata');
  }
  const total = integerHeader(request, 'x-gh-upload-total', { min: 1, max: 256 });
  const index = integerHeader(request, 'x-gh-upload-index', { min: 0, max: total - 1 });
  const totalSize = integerHeader(request, 'x-gh-upload-size', { min: 1, max: maxBytes });
  const buffer = await readBody(request, APPEARANCE_UPLOAD_CHUNK_BYTES);
  if (!buffer.length) {
    throw new HttpError(400, 'Invalid upload metadata', 'invalid_upload_metadata');
  }

  cleanupStaleUploads(config);
  const root = uploadDirectory(config);
  const directory = path.join(root, `${kind}-${uploadId}`);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const metaPath = path.join(directory, 'meta.json');
  const meta = fs.existsSync(metaPath)
    ? JSON.parse(fs.readFileSync(metaPath, 'utf8'))
    : { kind, uploadId, total, totalSize };
  if (meta.kind !== kind || meta.uploadId !== uploadId || meta.total !== total || meta.totalSize !== totalSize) {
    throw new HttpError(409, 'Upload metadata changed', 'upload_metadata_changed');
  }
  fs.writeFileSync(metaPath, JSON.stringify(meta), { mode: 0o600 });
  fs.writeFileSync(path.join(directory, `${index}.part`), buffer, { mode: 0o600 });

  const chunks = [];
  let actualSize = 0;
  for (let chunkIndex = 0; chunkIndex < total; chunkIndex += 1) {
    const chunkPath = path.join(directory, `${chunkIndex}.part`);
    if (!fs.existsSync(chunkPath)) {
      return { complete: false, received: fs.readdirSync(directory).filter(name => name.endsWith('.part')).length };
    }
    const chunk = fs.readFileSync(chunkPath);
    chunks.push(chunk);
    actualSize += chunk.length;
    if (actualSize > maxBytes) {
      fs.rmSync(directory, { recursive: true, force: true });
      throw new HttpError(
        413,
        'Image is too large. Maximum size is {maxSize}.',
        'appearance_asset_too_large',
        { maxBytes }
      );
    }
  }
  if (actualSize !== totalSize) {
    fs.rmSync(directory, { recursive: true, force: true });
    throw new HttpError(400, 'Invalid upload metadata', 'invalid_upload_metadata');
  }
  const asset = saveAppearanceAssetBuffer(Buffer.concat(chunks, actualSize), config, kind);
  fs.rmSync(directory, { recursive: true, force: true });
  return { complete: true, asset };
}

export function deleteAppearanceAsset(config, kind) {
  assertKind(kind);
  removeAssetFiles(config, kind);
  return appearanceAssets(config)[kind];
}

export function serveAppearanceAsset(response, config, kind) {
  const asset = findAsset(config, kind);
  if (!asset) throw new HttpError(404, 'Appearance asset not found', 'appearance_asset_not_found');
  const body = fs.readFileSync(asset.filePath);
  response.writeHead(200, {
    'content-type': asset.contentType,
    'content-length': body.length,
    'cache-control': 'public, max-age=31536000, immutable',
    'content-security-policy': "default-src 'none'; img-src 'self'",
    'x-content-type-options': 'nosniff'
  });
  response.end(body);
}

function cssUrl(value) {
  return value ? `url("${value.replaceAll('"', '%22')}")` : 'none';
}

function hexToRgba(value, opacityPercent) {
  const hex = /^#?([0-9a-f]{6})$/iu.exec(String(value || ''))?.[1] || '000000';
  const opacity = Math.max(0, Math.min(1, Number(opacityPercent || 0) / 100));
  const red = Number.parseInt(hex.slice(0, 2), 16);
  const green = Number.parseInt(hex.slice(2, 4), 16);
  const blue = Number.parseInt(hex.slice(4, 6), 16);
  return `rgba(${red},${green},${blue},${opacity})`;
}

export function portalThemeCss(config) {
  const assets = appearanceAssets(config);
  const theme = config.appearance;
  const cardBorder = `${theme.cardBorderWidth}px solid ${hexToRgba(theme.cardBorderColor, theme.cardBorderOpacity)}`;
  const cardShadow = [
    `${theme.cardShadowOffsetX}px`,
    `${theme.cardShadowOffsetY}px`,
    `${theme.cardShadowBlur}px`,
    `${theme.cardShadowSpread}px`,
    hexToRgba(theme.cardShadowColor, theme.cardShadowOpacity)
  ].join(' ');
  return `:root {
  --portal-primary: ${theme.primaryColor};
  --portal-primary-hover: ${theme.primaryHoverColor};
  --portal-heading: ${theme.headingColor};
  --portal-text: ${theme.textColor};
  --portal-muted: ${theme.mutedColor};
  --portal-button-text: ${theme.buttonTextColor};
  --portal-input-background: ${theme.inputBackgroundColor};
  --portal-input-border: ${theme.inputBorderColor};
  --portal-input-text: ${theme.inputTextColor};
  --portal-body-color: ${theme.bodyBackgroundColor};
  --portal-body-color-opacity: ${theme.bodyBackgroundOpacity / 100};
  --portal-body-image: ${cssUrl(assets['body-background'].url)};
  --portal-body-image-opacity: ${theme.bodyImageOpacity / 100};
  --portal-body-image-blur: ${theme.bodyImageBlur}px;
  --portal-card-color: ${theme.cardBackgroundColor};
  --portal-card-color-opacity: ${theme.cardBackgroundOpacity / 100};
  --portal-card-border: ${cardBorder};
  --portal-card-radius: ${theme.cardBorderRadius}px;
  --portal-card-shadow: ${cardShadow};
  --portal-card-image: ${cssUrl(assets['card-background'].url)};
  --portal-card-image-opacity: ${theme.cardImageOpacity / 100};
  --portal-card-image-blur: ${theme.cardImageBlur}px;
  --portal-card-backdrop-blur: ${theme.cardBackdropBlur}px;
}
`;
}

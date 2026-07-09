import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import {
  APPEARANCE_ASSET_LIMITS, appearanceAssets, deleteAppearanceAsset, portalThemeCss, saveAppearanceAsset,
  saveAppearanceAssetChunk
} from '../src/appearance.js';

function uploadChunk(buffer, { uploadId, index, total, totalSize }) {
  const request = Readable.from([buffer]);
  request.headers = {
    'x-gh-upload-id': uploadId,
    'x-gh-upload-index': String(index),
    'x-gh-upload-total': String(total),
    'x-gh-upload-size': String(totalSize)
  };
  return request;
}

test('appearance assets accept supported images and generate CSP-safe theme CSS', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-appearance-'));
  const config = {
    databasePath: path.join(directory, 'hotspot.db'),
    appearance: {
      primaryColor: '#112233',
      primaryHoverColor: '#223344',
      headingColor: '#334455',
      textColor: '#445566',
      mutedColor: '#556677',
      buttonTextColor: '#FFFFFF',
      inputBackgroundColor: '#FAFAFA',
      inputBorderColor: '#CCCCCC',
      inputTextColor: '#111111',
      bodyBackgroundColor: '#EEEEEE',
      bodyBackgroundOpacity: 80,
      bodyImageOpacity: 70,
      bodyImageBlur: 4,
      bodyImageAnimationEnabled: true,
      cardBackgroundColor: '#FFFFFF',
      cardBackgroundOpacity: 90,
      cardImageOpacity: 60,
      cardImageBlur: 2,
      cardBackdropBlur: 8
    }
  };
  try {
    const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00]);
    const asset = await saveAppearanceAsset(Readable.from([png]), config, 'logo');
    await saveAppearanceAsset(Readable.from([png]), config, 'body-background');
    assert.equal(asset.configured, true);
    assert.equal(asset.contentType, 'image/png');
    assert.equal(asset.maxSize, APPEARANCE_ASSET_LIMITS.logo);
    assert.match(asset.url, /^\/api\/v1\/appearance\/assets\/logo\?v=\d+$/u);

    const css = portalThemeCss(config);
    assert.match(css, /--portal-primary: #112233/u);
    assert.match(css, /--portal-card-backdrop-blur: 8px/u);
    assert.match(css, /--portal-body-image-animation: portal-backdrop-cinematic 34s ease-in-out infinite alternate/u);
    assert.match(css, /url\("\/api\/v1\/appearance\/assets\/body-background\?v=/u);

    deleteAppearanceAsset(config, 'logo');
    assert.equal(appearanceAssets(config).logo.configured, false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('background appearance assets allow 20 MB and reject larger uploads', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-appearance-'));
  const config = { databasePath: path.join(directory, 'hotspot.db') };
  const maxBytes = APPEARANCE_ASSET_LIMITS['body-background'];
  const png = Buffer.alloc(maxBytes);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(png);
  try {
    const asset = await saveAppearanceAsset(Readable.from([png]), config, 'body-background');
    assert.equal(asset.configured, true);
    assert.equal(asset.size, maxBytes);
    assert.equal(asset.maxSize, maxBytes);

    await assert.rejects(
      saveAppearanceAsset(Readable.from([png, Buffer.from([0])]), config, 'body-background'),
      error => {
        assert.equal(error.statusCode, 413);
        assert.equal(error.code, 'appearance_asset_too_large');
        assert.equal(error.details.maxBytes, maxBytes);
        return true;
      }
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('appearance assets can be uploaded in chunks below proxy body limits', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-appearance-'));
  const config = { databasePath: path.join(directory, 'hotspot.db') };
  const totalSize = 1200 * 1024;
  const firstSize = 700 * 1024;
  const png = Buffer.alloc(totalSize);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(png);
  const uploadId = 'chunk-upload-1';
  try {
    const pending = await saveAppearanceAssetChunk(
      uploadChunk(png.subarray(0, firstSize), { uploadId, index: 0, total: 2, totalSize }),
      config,
      'body-background'
    );
    assert.equal(pending.complete, false);
    assert.equal(pending.received, 1);

    const complete = await saveAppearanceAssetChunk(
      uploadChunk(png.subarray(firstSize), { uploadId, index: 1, total: 2, totalSize }),
      config,
      'body-background'
    );
    assert.equal(complete.complete, true);
    assert.equal(complete.asset.configured, true);
    assert.equal(complete.asset.size, totalSize);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('appearance assets reject unsupported file contents', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-appearance-'));
  const config = { databasePath: path.join(directory, 'hotspot.db') };
  try {
    await assert.rejects(
      saveAppearanceAsset(Readable.from([Buffer.from('<svg></svg>')]), config, 'logo'),
      /Only PNG, JPEG and WebP/u
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

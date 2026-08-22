import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

const NO_FOLLOW = fs.constants.O_NOFOLLOW || 0;

function notRegularFileError(filePath) {
  const error = new Error(`Expected a regular file: ${filePath}`);
  error.code = 'EINVAL';
  return error;
}

export function openRegularFileSync(filePath) {
  const descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | NO_FOLLOW);
  try {
    if (!fs.fstatSync(descriptor).isFile()) throw notRegularFileError(filePath);
    return descriptor;
  } catch (error) {
    fs.closeSync(descriptor);
    throw error;
  }
}

export function readRegularFileSync(filePath, encoding = null) {
  const descriptor = openRegularFileSync(filePath);
  try {
    const stat = fs.fstatSync(descriptor);
    const data = encoding == null
      ? fs.readFileSync(descriptor)
      : fs.readFileSync(descriptor, encoding);
    return { data, stat };
  } finally {
    fs.closeSync(descriptor);
  }
}

export function readRegularFileIfExistsSync(filePath, encoding = null) {
  try {
    return readRegularFileSync(filePath, encoding);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

export function statRegularFileIfExistsSync(filePath) {
  let descriptor;
  try {
    descriptor = openRegularFileSync(filePath);
    return fs.fstatSync(descriptor);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
  }
}

export function chmodRegularFilePrivateIfExistsSync(filePath) {
  let descriptor;
  try {
    descriptor = openRegularFileSync(filePath);
    fs.fchmodSync(descriptor, 0o600);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
  }
}

function syncParentDirectory(filePath) {
  let descriptor;
  try {
    descriptor = fs.openSync(path.dirname(filePath), fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0));
    fs.fsyncSync(descriptor);
  } catch (error) {
    if (!['EINVAL', 'ENOTSUP', 'EISDIR'].includes(error?.code)) throw error;
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
  }
}

export function atomicWriteFileSync(filePath, data, { mode = 0o600 } = {}) {
  const directory = path.dirname(filePath);
  const temporary = path.join(directory, `.${path.basename(filePath)}.${randomUUID()}.tmp`);
  let descriptor;
  try {
    descriptor = fs.openSync(
      temporary,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | NO_FOLLOW,
      mode
    );
    fs.writeFileSync(descriptor, data);
    fs.fchmodSync(descriptor, mode);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = null;
    fs.renameSync(temporary, filePath);
    syncParentDirectory(filePath);
  } catch (error) {
    if (descriptor != null) {
      try { fs.closeSync(descriptor); } catch {}
    }
    try { fs.unlinkSync(temporary); } catch {}
    throw error;
  }
}

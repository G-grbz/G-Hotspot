import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';

export const ANDROID_APPLICATION_ID = 'com.ghotspot.admin';
export const GOOGLE_SERVICES_MAX_BYTES = 128 * 1024;
const BUILD_LOG_LIMIT = 32 * 1024;
const buildJobs = new Map();

function buildError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

export function androidProjectPaths(projectRoot = process.cwd()) {
  const root = path.resolve(projectRoot);
  const androidRoot = path.join(root, 'android');
  return {
    projectRoot: root,
    androidRoot,
    androidUserHome: path.join(androidRoot, 'app', '.android'),
    googleServicesFile: path.join(androidRoot, 'app', 'google-services.json'),
    settingsFile: path.join(androidRoot, 'settings.gradle'),
    apkFile: path.join(androidRoot, 'app', 'build', 'outputs', 'apk', 'debug', 'g-hotspot.apk')
  };
}

function objectValue(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

export function validateGoogleServicesConfig(input) {
  let config;
  try {
    config = typeof input === 'string' || Buffer.isBuffer(input)
      ? JSON.parse(Buffer.from(input).toString('utf8'))
      : input;
  } catch {
    throw buildError('google-services.json is not valid JSON', 'android_google_services_invalid_json');
  }
  if (!objectValue(config)) {
    throw buildError('google-services.json must contain a JSON object', 'android_google_services_invalid');
  }
  if (config.type === 'service_account' || config.private_key) {
    throw buildError(
      'Upload google-services.json from the Firebase Android app, not the private service account file',
      'android_google_services_service_account'
    );
  }
  const projectInfo = objectValue(config.project_info);
  const clients = Array.isArray(config.client) ? config.client : [];
  const client = clients.find(item =>
    item?.client_info?.android_client_info?.package_name === ANDROID_APPLICATION_ID
  );
  const appId = String(client?.client_info?.mobilesdk_app_id || '').trim();
  const apiKey = String(client?.api_key?.find(item => item?.current_key)?.current_key || '').trim();
  const projectId = String(projectInfo?.project_id || '').trim();
  const projectNumber = String(projectInfo?.project_number || '').trim();
  if (!projectId || !projectNumber || !client || !appId || !apiKey) {
    throw buildError(
      `Firebase configuration must contain an Android app with package name ${ANDROID_APPLICATION_ID}`,
      'android_google_services_package_mismatch'
    );
  }
  return {
    config,
    summary: {
      projectId,
      projectNumber,
      appId,
      packageName: ANDROID_APPLICATION_ID
    }
  };
}

function configurationStatus(paths) {
  if (!fs.existsSync(paths.googleServicesFile)) {
    return { configured: false, valid: false, error: '' };
  }
  try {
    const stat = fs.statSync(paths.googleServicesFile);
    const { summary } = validateGoogleServicesConfig(fs.readFileSync(paths.googleServicesFile));
    return {
      configured: true,
      valid: true,
      ...summary,
      updatedAt: stat.mtimeMs,
      size: stat.size
    };
  } catch (error) {
    return {
      configured: true,
      valid: false,
      error: error.message,
      errorCode: error.code || 'android_google_services_invalid'
    };
  }
}

export function saveGoogleServicesConfig(input, { projectRoot = process.cwd() } = {}) {
  const raw = Buffer.isBuffer(input) ? input : Buffer.from(String(input || ''), 'utf8');
  if (!raw.length) throw buildError('Select a google-services.json file', 'android_google_services_required');
  if (raw.length > GOOGLE_SERVICES_MAX_BYTES) {
    throw buildError('google-services.json is too large', 'android_google_services_too_large');
  }
  const paths = androidProjectPaths(projectRoot);
  if (!fs.existsSync(path.dirname(paths.googleServicesFile))) {
    throw buildError('Android application source directory was not found', 'android_project_not_found');
  }
  const { config, summary } = validateGoogleServicesConfig(raw);
  const temporary = `${paths.googleServicesFile}.${randomUUID()}.tmp`;
  try {
    fs.writeFileSync(temporary, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(temporary, paths.googleServicesFile);
  } finally {
    try {
      if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
    } catch {
    }
  }
  return { ...summary, file: paths.googleServicesFile };
}

function jobFor(paths) {
  return buildJobs.get(paths.projectRoot) || {
    id: '',
    state: 'idle',
    startedAt: null,
    finishedAt: null,
    error: '',
    log: ''
  };
}

function appendBuildLog(job, chunk) {
  job.log = `${job.log}${String(chunk || '')}`.slice(-BUILD_LOG_LIMIT);
}

function createBuildWorkspace(paths) {
  const workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-android-build-'));
  const androidRoot = path.join(workspaceRoot, 'android');
  try {
    fs.cpSync(paths.androidRoot, androidRoot, {
      recursive: true,
      filter(source) {
        const relative = path.relative(paths.androidRoot, source);
        if (!relative) return true;
        const parts = relative.split(path.sep);
        if (parts[0] === '.gradle' || parts[0] === 'build') return false;
        return !(parts[0] === 'app' && (parts[1] === 'build' || parts[1] === '.android'));
      }
    });
    return { workspaceRoot, androidRoot };
  } catch (error) {
    fs.rmSync(workspaceRoot, { recursive: true, force: true });
    throw error;
  }
}

function publishApk(source, destination) {
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  const temporary = `${destination}.${randomUUID()}.tmp`;
  try {
    fs.copyFileSync(source, temporary);
    fs.renameSync(temporary, destination);
  } finally {
    try {
      if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
    } catch {
    }
  }
}

function copySigningKey(source, destination) {
  if (!fs.existsSync(source)) return false;
  fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
  const temporary = `${destination}.${randomUUID()}.tmp`;
  try {
    fs.copyFileSync(source, temporary);
    fs.chmodSync(temporary, 0o600);
    fs.renameSync(temporary, destination);
    return true;
  } finally {
    try {
      if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
    } catch {
    }
  }
}

function androidSdkCandidates(paths, environment) {
  const home = String(environment.HOME || os.homedir() || '').trim();
  const candidates = [
    environment.ANDROID_HOME,
    environment.ANDROID_SDK_ROOT,
    home && path.join(home, 'Android', 'Sdk'),
    home && path.join(home, 'Library', 'Android', 'sdk'),
    '/opt/android-sdk',
    '/usr/lib/android-sdk',
    '/usr/local/lib/android/sdk'
  ];
  const containerRoot = path.dirname(paths.projectRoot);
  try {
    for (const entry of fs.readdirSync(containerRoot, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      candidates.push(path.join(containerRoot, entry.name, '.tooling', 'android-sdk'));
    }
  } catch {
  }
  return candidates
    .map(candidate => String(candidate || '').trim())
    .filter((candidate, index, all) => candidate && all.indexOf(candidate) === index);
}

function resolveAndroidSdk(paths, environment) {
  return androidSdkCandidates(paths, environment).find(candidate =>
    fs.existsSync(path.join(candidate, 'platforms')) &&
    fs.existsSync(path.join(candidate, 'build-tools'))
  ) || '';
}

export function androidBuildStatus({ projectRoot = process.cwd() } = {}) {
  const paths = androidProjectPaths(projectRoot);
  const config = configurationStatus(paths);
  const job = jobFor(paths);
  let apk = { ready: false, size: 0, builtAt: null, filename: 'g-hotspot.apk' };
  if (fs.existsSync(paths.apkFile)) {
    const stat = fs.statSync(paths.apkFile);
    apk = {
      ready: Boolean(config.valid && stat.mtimeMs >= Number(config.updatedAt || 0) && job.state !== 'running'),
      size: stat.size,
      builtAt: stat.mtimeMs,
      filename: path.basename(paths.apkFile)
    };
  }
  return {
    id: job.id,
    state: job.state,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    error: job.error,
    log: job.state === 'failed' ? job.log.slice(-8000) : '',
    config,
    apk
  };
}

export function startAndroidBuild({
  projectRoot = process.cwd(),
  spawnProcess = spawn,
  environment = process.env
} = {}) {
  const paths = androidProjectPaths(projectRoot);
  const current = jobFor(paths);
  if (current.state === 'running') throw buildError('An Android APK build is already running', 'android_build_running');
  const config = configurationStatus(paths);
  if (!config.valid) {
    throw buildError(config.error || 'Upload a valid google-services.json before building', 'android_google_services_required');
  }
  if (!fs.existsSync(paths.settingsFile)) {
    throw buildError('Android Gradle project was not found', 'android_project_not_found');
  }

  let workspace;
  try {
    workspace = createBuildWorkspace(paths);
  } catch (error) {
    throw buildError(`Could not prepare the Android build workspace: ${error.message}`, 'android_build_workspace_failed');
  }
  const androidSdk = resolveAndroidSdk(paths, environment);
  if (!androidSdk) {
    fs.rmSync(workspace.workspaceRoot, { recursive: true, force: true });
    throw buildError(
      'Android SDK was not found on the server. Set ANDROID_HOME or ANDROID_SDK_ROOT for the G-Hotspot service',
      'android_sdk_not_found'
    );
  }

  const job = {
    id: randomUUID(),
    state: 'running',
    startedAt: Date.now(),
    finishedAt: null,
    error: '',
    log: ''
  };
  buildJobs.set(paths.projectRoot, job);

  const workspaceApk = path.join(
    workspace.androidRoot,
    'app',
    'build',
    'outputs',
    'apk',
    'debug',
    'g-hotspot.apk'
  );
  const cleanupWorkspace = () => {
    try {
      fs.rmSync(workspace.workspaceRoot, { recursive: true, force: true });
    } catch {
    }
  };
  const androidUserHome = path.join(workspace.workspaceRoot, '.android');
  fs.mkdirSync(androidUserHome, { recursive: true, mode: 0o700 });
  const persistentDebugKey = path.join(paths.androidUserHome, 'debug.keystore');
  const workspaceDebugKey = path.join(androidUserHome, 'debug.keystore');
  copySigningKey(persistentDebugKey, workspaceDebugKey);

  const javaHome = String(environment.JAVA_HOME || '').trim() ||
    (fs.existsSync('/usr/lib/jvm/java-17-openjdk') ? '/usr/lib/jvm/java-17-openjdk' : '');
  const child = spawnProcess(
    String(environment.GRADLE_COMMAND || 'gradle'),
    ['--no-daemon', ':app:assembleDebug'],
    {
      cwd: workspace.androidRoot,
      env: {
        ...environment,
        ...(javaHome ? { JAVA_HOME: javaHome } : {}),
        ANDROID_HOME: androidSdk,
        ANDROID_SDK_ROOT: androidSdk,
        ANDROID_USER_HOME: androidUserHome,
        ANDROID_SDK_HOME: workspace.workspaceRoot,
        GRADLE_USER_HOME: String(environment.GRADLE_USER_HOME || '').trim() ||
          path.join(os.tmpdir(), 'g-hotspot-gradle')
      },
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: false
    }
  );
  child.stdout?.on('data', chunk => appendBuildLog(job, chunk));
  child.stderr?.on('data', chunk => appendBuildLog(job, chunk));
  child.on('error', error => {
    job.state = 'failed';
    job.finishedAt = Date.now();
    job.error = error.code === 'ENOENT'
      ? 'Gradle command was not found on the server'
      : error.message;
    appendBuildLog(job, error.stack || error.message);
    cleanupWorkspace();
  });
  child.on('close', code => {
    if (job.state === 'failed') return;
    job.finishedAt = Date.now();
    if (code === 0 && fs.existsSync(workspaceApk)) {
      try {
        if (!copySigningKey(workspaceDebugKey, persistentDebugKey)) {
          throw new Error('Gradle did not produce a persistent debug signing key');
        }
        publishApk(workspaceApk, paths.apkFile);
        job.state = 'succeeded';
      } catch (error) {
        job.state = 'failed';
        job.error = `Could not publish the generated APK: ${error.message}`;
        appendBuildLog(job, error.stack || error.message);
      } finally {
        cleanupWorkspace();
      }
      return;
    }
    job.state = 'failed';
    job.error = code === 0
      ? 'Gradle completed but the APK output was not found'
      : `Gradle build failed with exit code ${code}`;
    cleanupWorkspace();
  });
  return androidBuildStatus({ projectRoot: paths.projectRoot });
}

export function resetAndroidBuildState(projectRoot = process.cwd()) {
  buildJobs.delete(path.resolve(projectRoot));
}

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import {
  ANDROID_APPLICATION_ID,
  androidBuildStatus,
  androidProjectPaths,
  resetAndroidBuildState,
  saveGoogleServicesConfig,
  startAndroidBuild,
  validateGoogleServicesConfig
} from '../src/services/androidBuild.js';

function firebaseConfig(packageName = ANDROID_APPLICATION_ID) {
  return {
    project_info: {
      project_number: '1234567890',
      project_id: 'g-hotspot-test',
      storage_bucket: 'g-hotspot-test.firebasestorage.app'
    },
    client: [{
      client_info: {
        mobilesdk_app_id: '1:1234567890:android:abcdef',
        android_client_info: { package_name: packageName }
      },
      api_key: [{ current_key: 'test-api-key' }]
    }],
    configuration_version: '1'
  };
}

function temporaryAndroidProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-android-build-'));
  fs.mkdirSync(path.join(root, 'android', 'app'), { recursive: true });
  fs.writeFileSync(path.join(root, 'android', 'settings.gradle'), 'rootProject.name = "test"\n');
  return root;
}

test('google-services validation accepts only the G-Hotspot Android package', () => {
  const valid = validateGoogleServicesConfig(JSON.stringify(firebaseConfig()));
  assert.equal(valid.summary.packageName, ANDROID_APPLICATION_ID);
  assert.equal(valid.summary.projectId, 'g-hotspot-test');

  assert.throws(
    () => validateGoogleServicesConfig(firebaseConfig('com.example.wrong')),
    error => error.code === 'android_google_services_package_mismatch'
  );
  assert.throws(
    () => validateGoogleServicesConfig({ type: 'service_account', private_key: 'secret' }),
    error => error.code === 'android_google_services_service_account'
  );
});

test('google-services upload is stored atomically and invalidates an older APK', () => {
  const root = temporaryAndroidProject();
  try {
    const paths = androidProjectPaths(root);
    fs.mkdirSync(path.dirname(paths.apkFile), { recursive: true });
    fs.writeFileSync(paths.apkFile, 'old-apk');
    fs.utimesSync(paths.apkFile, new Date(1000), new Date(1000));

    const saved = saveGoogleServicesConfig(JSON.stringify(firebaseConfig()), { projectRoot: root });
    assert.equal(saved.projectId, 'g-hotspot-test');
    assert.equal(JSON.parse(fs.readFileSync(paths.googleServicesFile, 'utf8')).configuration_version, '1');

    const status = androidBuildStatus({ projectRoot: root });
    assert.equal(status.config.valid, true);
    assert.equal(status.apk.ready, false);
  } finally {
    resetAndroidBuildState(root);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('Android build runs Gradle without a shell and exposes the generated APK', async () => {
  const root = temporaryAndroidProject();
  try {
    const paths = androidProjectPaths(root);
    const androidSdk = path.join(root, 'android-sdk');
    fs.mkdirSync(path.join(androidSdk, 'platforms'), { recursive: true });
    fs.mkdirSync(path.join(androidSdk, 'build-tools'), { recursive: true });
    fs.mkdirSync(paths.androidUserHome, { recursive: true });
    fs.writeFileSync(path.join(paths.androidUserHome, 'debug.keystore'), 'persistent-key');
    saveGoogleServicesConfig(JSON.stringify(firebaseConfig()), { projectRoot: root });
    let invocation = null;
    let workspaceSigningKey = '';
    const spawnProcess = (command, args, options) => {
      invocation = { command, args, options };
      workspaceSigningKey = fs.readFileSync(
        path.join(options.env.ANDROID_USER_HOME, 'debug.keystore'),
        'utf8'
      );
      const child = new EventEmitter();
      child.stdout = new EventEmitter();
      child.stderr = new EventEmitter();
      process.nextTick(() => {
        const workspaceApk = path.join(
          options.cwd,
          'app',
          'build',
          'outputs',
          'apk',
          'debug',
          'g-hotspot.apk'
        );
        fs.mkdirSync(path.dirname(workspaceApk), { recursive: true });
        fs.writeFileSync(workspaceApk, 'new-apk');
        child.stdout.emit('data', 'BUILD SUCCESSFUL');
        child.emit('close', 0);
      });
      return child;
    };

    const started = startAndroidBuild({
      projectRoot: root,
      spawnProcess,
      environment: { PATH: process.env.PATH || '', ANDROID_HOME: androidSdk }
    });
    assert.equal(started.state, 'running');
    await new Promise(resolve => setImmediate(resolve));

    const finished = androidBuildStatus({ projectRoot: root });
    assert.equal(finished.state, 'succeeded');
    assert.equal(finished.apk.ready, true);
    assert.equal(invocation.command, 'gradle');
    assert.deepEqual(invocation.args, ['--no-daemon', ':app:assembleDebug']);
    assert.match(invocation.options.cwd, /g-hotspot-android-build-.+\/android$/u);
    assert.notEqual(invocation.options.cwd, paths.androidRoot);
    assert.equal(invocation.options.shell, false);
    assert.equal(invocation.options.env.ANDROID_HOME, androidSdk);
    assert.equal(invocation.options.env.ANDROID_SDK_ROOT, androidSdk);
    assert.match(invocation.options.env.ANDROID_USER_HOME, /g-hotspot-android-build-.+\/\.android$/u);
    assert.equal(fs.existsSync(path.join(invocation.options.cwd, 'app', '.android', 'debug.keystore')), false);
    assert.equal(workspaceSigningKey, 'persistent-key');
    assert.equal(fs.readFileSync(path.join(paths.androidUserHome, 'debug.keystore'), 'utf8'), 'persistent-key');
    assert.equal(fs.readFileSync(paths.apkFile, 'utf8'), 'new-apk');
  } finally {
    resetAndroidBuildState(root);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

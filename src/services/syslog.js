import {
  createLaw5651AutoExporter,
  createLaw5651ExportArchive,
  createLaw5651HealthGuard,
  createLaw5651SyslogServer,
  assertLaw5651PortalWritable,
  law5651Csv,
  law5651FileDate,
  law5651IsoDate,
  law5651RecordFromSession,
  law5651RecordsFromSyslog,
  law5651StorageStatus
} from './law5651.js';

function compatibleConfig(config = {}) {
  if (config.law5651) return config;
  return { ...config, law5651: config.syslog || {} };
}

export const syslogCsv = law5651Csv;
export const syslogFileDate = law5651FileDate;
export const syslogIsoDate = law5651IsoDate;
export const syslogRecordFromSession = law5651RecordFromSession;
export const syslogRecordsFromMessage = law5651RecordsFromSyslog;
export const syslogStorageStatus = law5651StorageStatus;
export const assertSyslogPortalWritable = assertLaw5651PortalWritable;

export function createSyslogServer(options = {}) {
  return createLaw5651SyslogServer({
    ...options,
    config: compatibleConfig(options.config)
  });
}

export async function createSyslogExportArchive(options = {}) {
  return createLaw5651ExportArchive({
    ...options,
    config: compatibleConfig(options.config)
  });
}

export function createSyslogAutoExporter(options = {}) {
  return createLaw5651AutoExporter({
    ...options,
    config: compatibleConfig(options.config)
  });
}

export function createSyslogHealthGuard(options = {}) {
  return createLaw5651HealthGuard({
    ...options,
    config: compatibleConfig(options.config)
  });
}

export type Severity = "critical" | "high" | "medium" | "low" | "safe";

export interface Flag {
  type:
    | "new_dep"
    | "package_age"
    | "osv_malicious"
    | "osv_vuln"
    | "typosquat"
    | "install_script"
    | "phantom_dep";
  severity: Severity;
  message: string;
  detail?: string;
}

export interface CheckEntry {
  name: string;
  source: string;
  passed: boolean;
  detail: string;
  durationMs: number;
}

export interface CheckResult {
  flags: Flag[];
  checks: CheckEntry[];
}

export interface PackageResult {
  name: string;
  version: string;
  resolvedVersion: string;
  flags: Flag[];
  checks: CheckEntry[];
  score: number;
  severity: Severity;
  safe: boolean;
}

export interface Config {
  blockOn: Severity;
  allowList: string[];
  denyList: string[];
  maxAgeHours: number;
  offline: boolean;
  communityRulesUrl?: string;
}

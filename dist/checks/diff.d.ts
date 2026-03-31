import { CheckResult } from "../types";
export declare function diffDeps(packageName: string, newVersion: string, maxAgeHours: number): Promise<CheckResult>;

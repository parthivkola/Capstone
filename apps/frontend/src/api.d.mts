export declare const API_BASE: string;
export declare class ApiError extends Error {
  status: number;
  constructor(status: number, message: string);
}
export declare function get(path: string): Promise<any>;
export declare function post(path: string, payload?: Record<string, unknown>): Promise<any>;

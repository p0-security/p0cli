export const DONE_STATUSES = ["DONE", "DONE_NOTIFIED"] as const;
export const DENIED_STATUSES = ["DENIED", "DENIED_NOTIFIED"] as const;
export const ERROR_STATUSES = [
  "ERRORED",
  "ERRORED",
  "ERRORED_NOTIFIED",
] as const;

export type Request<T = object> = {
  status: string;
  generatedRoles: {
    role: string;
  }[];
  generated: {
    documentName: string;
  };
  permission: T;
  principal: string;
};

export type RequestResponse = {
  ok: true;
  message: string;
  id: string;
  isPreexisting: boolean;
  isPersistent: boolean;
};

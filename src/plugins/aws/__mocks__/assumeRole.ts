import { AwsCredentials } from "../types";

export const assumeRoleWithSaml = async (): Promise<AwsCredentials> => ({
  AWS_ACCESS_KEY_ID: "test-access-key-id",
  AWS_SECRET_ACCESS_KEY: "test-secret-access-key",
  AWS_SESSION_TOKEN: "test-session-token",
});

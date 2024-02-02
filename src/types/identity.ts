export type Identity = {
  credential: TokenResponse & { expires_at: number };
  org: OrgData;
};

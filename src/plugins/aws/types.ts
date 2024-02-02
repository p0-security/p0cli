export type AwsOktaSamlUidLocation = {
  id: "okta_saml_sso";
  samlProviderName: string;
  appId: string;
};

type AwsUidLocation =
  | { id: "idc"; parentId: string }
  | AwsOktaSamlUidLocation
  | { id: "user_tag"; tagName: string }
  | { id: "username" };

export type AwsItemConfig = {
  account: {
    id: string;
    alias?: string;
  };
  state: string;
  uidLocation?: AwsUidLocation;
};

export type AwsConfig = {
  workflows?: {
    items: AwsItemConfig[];
  };
};

export type AwsCredentials = {
  AWS_ACCESS_KEY_ID: string;
  AWS_SECRET_ACCESS_KEY: string;
  AWS_SESSION_TOKEN: string;
};

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
    description?: string;
  };
  state: string;
  uidLocation?: AwsUidLocation;
};

export type AwsConfig = {
  workflows?: {
    items: AwsItemConfig[];
  };
};

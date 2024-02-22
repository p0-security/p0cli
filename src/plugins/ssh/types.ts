type SshItemConfig = {
  alias?: string;
  identifier: string;
  state: string;
  type: "aws" | "gcloud";
};

export type SshConfig = {
  workflows?: {
    items: SshItemConfig[];
  };
};

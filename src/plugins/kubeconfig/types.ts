/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { PermissionSpec } from "../../types/request";

export type K8sConfig = {
  workflows: {
    items: K8sClusterConfig[];
  };
};

export type BaseK8sClusterConfig = {
  clusterId: string;
  clusterServer: string;
  clusterCertificate: string;
  state: string;
} & (KubernetesProxyComponentConfig | KubernetesPublicComponentConfig);

// k8s clusters that are not EKS clusters will not have these set...
export type K8sClusterConfig = BaseK8sClusterConfig & {
  awsAccountId?: string;
  awsClusterArn?: string;
};

// ...But all EKS clusters must have both set
export type EksClusterConfig = BaseK8sClusterConfig & {
  awsAccountId: string;
  awsClusterArn: string;
};

type KubernetesProxyComponentConfig = {
  isProxy: true;
  publicJwk: string;
};

export type KubernetesPublicComponentConfig = {
  isProxy: false;
};

export type K8sPermissionSpec = PermissionSpec<
  "k8s",
  K8sResourcePermission,
  K8sGenerated
>;

export type K8sResourcePermission = {
  resource: {
    name: string;
    namespace: string;
    kind: string;
  };
  role: string;
  clusterId: string;
  type: "resource";
};

export type K8sGenerated = {
  eksGenerated: {
    // For IDC, the name of the permission set. For Federated, the name of the assumed role
    name: string;

    // Only present for IDC; the ID and region of the IDC installation
    idc?: { id: string; region: string };
  };
  role: string; // The name of the generated role in k8s itself
};

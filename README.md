<div align="center">
    <a href="https://github.com/p0-security/p0cli">
        <img width="200" height="200" src="https://p0.dev/images/logo.png" alt="P0 Security logo">
    </a>
</div>

# P0 Security CLI

The offical Command-Line Interface (CLI) for P0.

Supports creating access requests for cloud resources, assuming AWS roles, and connecting to AWS instances.

## Table of Contents

- [About](#about)
- [Quickstart](#quickstart)
  - [Installation](#installation)
  - [Configuration](#configuration)
- [Command Reference](#command-reference)
- [Example Usage](#example-usage)
- [Support](#support)
- [Contributing](#contributing)
- [Copyright](#copyright)

## About

P0 manages just-in-time access to your cloud resources. The P0 CLI enables developers to seamlessly integrate P0 into their normal workflows by supporting the following use cases:

- Assume an AWS role or SSH into an AWS instance: P0 will request access, wait for access to be approved and provisioned, and then execute the relevant `aws` command
- Create P0 access requests for any cloud resource

To learn more about P0, see our [docs](https://docs.p0.dev/).

## Quickstart

### Installation

To install the P0 CLI, run:

```
npm install -g @p0security/p0cli
```

You can now invoke the CLI by running `p0`.

### Configuration

Before you can make requests using the P0 CLI, you will need to authenticate with your P0 organization. If you don't have a P0 organization account yet, follow our [Quick Start guide](https://docs.p0.dev/getting-started/quick-start) to create an account and install a resource for access requests.

Once you have a P0 organization account, run

```
p0 login <P0_ORGANIZATION_ID>
```

then follow the prompts in your browser to complete authentication.

You can now request access via

```
p0 request
```

## CLI Reference

### Usage

Interact with the `p0` CLI via:

```
p0 <command> <options>
```

To view help, use the `--help` option with any command.

### Available commands

```
  p0 aws                    Execute AWS commands
  p0 login <org>            Log in to p0 using a web browser
  p0 ls [arguments..]       List request-command arguments
  p0 request [arguments..]  Manually request permissions on a resource
  p0 ssh <instance>         SSH into a virtual machine
```

## Example Usage

### Create an access request

To view the resources available for access requests, run:

```
p0 request --help
```

Sample output:

```
Request access to a resource using P0

Commands:
  p0 request aws                Amazon Web Services
  p0 request azure-ad           Entra ID
  p0 request gcloud             Google Cloud
  p0 request okta               Okta
  p0 request ssh <destination>  Secure Shell (SSH) session
  p0 request workspace          Google Workspace

Options:
      --help    Show help                                              [boolean]
      --reason  Reason access is needed                                 [string]
  -w, --wait    Block until the request is completed                   [boolean]
```

Run `--help` on any of these commands for information on requesting that resource. For example, to request a Google Cloud role, run

```
p0 request gcloud --help
```

```
Google Cloud

Commands:
  p0 request gcloud resource <accesses..>  GCP resource
  p0 request gcloud role <names..>         Custom or predefined role
  p0 request gcloud permission <names..>   GCP permissions

Options:
      --help    Show help                                              [boolean]
      --reason  Reason access is needed                                 [string]
  -w, --wait    Block until the request is completed                   [boolean]
```

If you don't know the name of the role you need, you can use the `p0 ls` command. `p0 ls` accepts the same arguments that you provide to `p0 request` and lists the available options for access within your selected resource. For example, to view the available Google Cloud roles, run

```
 p0 ls gcloud role names --like bigquery
```

Now, to request `bigquery.admin`, run:

```
p0 request gcloud role bigquery.admin
```

### Assume an AWS IAM Role

### SSH into an AWS Instance

## Support

If you encounter any issues with the P0 CLI, you can open a GitHub issue on this repo, email `support@p0.dev`, or reach out to us on our [community slack](https://join.slack.com/t/p0securitycommunity/shared_invite/zt-1zouzlovp-1kuym9RfuzkJ17ZlvAf6mQ).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## Copyright

Copyright © 2024-present P0 Security.

The P0 Security CLI is licensed under the terms of the GNU General Public License version 3. See [LICENSE.md](LICENSE.md) for details.

```

```

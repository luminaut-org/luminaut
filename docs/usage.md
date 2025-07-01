---
title: Usage
layout: single
toc: true
---

# Command line usage

## Cloud provider configuration

Luminaut supports AWS and GCP cloud environments. The commands in this documentation assumes that your shell is already configured with the necessary AWS and GCP credentials.

You can confirm your AWS credential configuration by running `aws sts get-caller-identity`. For additional information on configuring AWS credentials, see the [AWS CLI documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html).

You can confirm your GCP credential configuration by running `gcloud auth list`. For additional information on configuring GCP credentials, see the [GCP SDK documentation](https://cloud.google.com/sdk/docs/install).

## Command line interface

No arguments are required to run luminaut. The default is to look for a `luminaut.toml` file in the same directory and run available tools to start detecting resources.

The default configuration options are shown in the Configuration section.

Luminaut help is available with the argument `--help`.

```bash
$ luminaut --help                       
usage: luminaut [-h] [--config CONFIG] [--log LOG] [--verbose]

Luminaut: Casting light on shadow cloud deployments. 

options:
  -h, --help       show this help message and exit
  --config CONFIG  Configuration file. (default: luminaut.toml)
  --log LOG        Log file. (default: luminaut.log)
  --verbose        Verbose output in the log file. (default: False)
```

## Examples

By default, Luminaut will run all available tools. It requires your AWS profile to be configured with the necessary permissions, otherwise the first step of public IP detection on ENIs will fail.

```bash
luminaut
```

The AWS Config scanner takes at least 50 seconds to run per resource type. If you would like to disable this, you can do so as shown in the provided `configs/disable_aws_config.toml` configuration file. You can provide this configuration with `-c configs/disable_aws_config.toml`.

```bash
luminaut -c configs/disable_aws_config.toml
```

Similarly, if you'd like to enable Shodan, you will need to specify a configuration file that includes the Shodan API key. See the Configuration section for more information on the configuration file specification.

# Usage with docker

When running with docker, we need to supply a few arguments:
1. `-it` to run the container interactively and display the output in the terminal.
2. `-v ~/.aws:/home/app/.aws` to mount the AWS credentials from your host machine to the container, if you are using AWS.
3. `-e AWS_PROFILE=aws-profile-name` to set the AWS profile to use in the container. Replace `aws-profile-name` with the name of your AWS profile.
4. `-v ~/.config/gcloud:/home/app/.config/gcloud` to mount the GCP credentials from your host machine to the container, if you are using GCP.
5. `-v $(pwd)/configs:/app/configs` to mount the configuration file from your host machine to the container.
6. `luminaut` to select the luminaut container.
7. `--help` to display the help message, though replace this with your desired arguments (ie `-c disable_aws_config.toml`).

Note that saved files, such as the log file and JSON reports, will be saved within the container. You may want to mount another volume to save the report files. If you would like to run other commands within the container, you can override the default entrypoint by adding `--entrypoint /bin/bash`.

## Examples

Bash, zsh, and similar terminals:
```bash
docker run -it \
  -v ~/.aws:/home/app/.aws \
  -e AWS_PROFILE=aws-profile-name \
  -v ~/.config/gcloud:/home/app/.config/gcloud \
  -v $(pwd)/configs:/app/configs \
  luminaut --help
```

Powershell:
```powershell
docker run -it `
  -v $env:USERPROFILE\.aws:/home/app/.aws `
  -e AWS_PROFILE=aws-profile-name `
  -v $env:APPDATA\gcloud:/home/app/.config/gcloud `
  -v ${PWD}\configs:/app/configs `
  luminaut --help
```

# Library usage

Luminaut is also designed for use as a Python library. For example usage, see the `examples/` directory within the root of the repository for scripts that showcase how to leverage Luminaut functionality as a Python library.

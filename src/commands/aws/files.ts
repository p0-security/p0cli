/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { AwsCredentials } from "../../plugins/aws/types";
import * as ini from "ini";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import path from "node:path";
import tmp from "tmp-promise";

const AWS_CONFIG_PATH = path.join(os.homedir(), ".aws");
export const AWS_CONFIG_FILE = path.join(AWS_CONFIG_PATH, "config");
export const AWS_CREDENTIALS_FILE = path.join(AWS_CONFIG_PATH, "credentials");

// Reference documentation: https://docs.aws.amazon.com/sdkref/latest/guide/file-format.html

/**
 * Reads in an AWS CLI configuration file, which is formatted as INI text, and
 * returns an arbitrary object representing the contents.
 *
 * @param path Path of the file to read
 * @returns Arbitrary object representing the contents of the file, or an empty
 * object if the file is empty or does not exist
 */
export const readIniFile = async (
  path: string
): Promise<{ [key: string]: any }> => {
  try {
    const data = await fs.readFile(path, { encoding: "utf-8" });
    return data ? ini.parse(data) : {};
  } catch (err: any) {
    if (err.code === "ENOENT") {
      return {};
    }

    throw err;
  }
};

/**
 * This function writes an arbitrary object as INI-formatted text to a file
 * atomically by first writing the data to a temporary file then moving the
 * temporary file on top of the target file. This minimizes the chance that an
 * exception, system crash, or other similar event will leave the file in a
 * corrupted state; this is important since we're mucking around with the AWS
 * CLI's configuration files.
 *
 * @param path Path of the (permanent) file to write to
 * @param obj Arbitrary object to convert to INI-formatted text and write to the
 * file
 * @param iniEncodeOptions Options to pass to the INI encoding library
 */
export const atomicWriteIniFile = async (
  path: string,
  obj: any,
  iniEncodeOptions?: ini.EncodeOptions
): Promise<void> => {
  const data = ini.stringify(obj, iniEncodeOptions);

  // Permissions will be moved along with the file
  const { path: tmpPath } = await tmp.file({ mode: 0o600, prefix: "p0cli-" });

  await fs.writeFile(tmpPath, data, { encoding: "utf-8" });
  await fs.rename(tmpPath, path);
};

export const writeAwsTempCredentials = async (
  profileName: string,
  awsCredentials: AwsCredentials
) => {
  const credentials = await readIniFile(AWS_CREDENTIALS_FILE);

  credentials[profileName] = {
    aws_access_key_id: awsCredentials.AWS_ACCESS_KEY_ID,
    aws_secret_access_key: awsCredentials.AWS_SECRET_ACCESS_KEY,
    aws_session_token: awsCredentials.AWS_SESSION_TOKEN,
  };

  // The credentials file is formatted with whitespace before and after the `=`
  await atomicWriteIniFile(AWS_CREDENTIALS_FILE, credentials, {
    whitespace: true,
  });
};

export const writeAwsConfigProfile = async (
  profileName: string,
  profileConfig: any
) => {
  const config = await readIniFile(AWS_CONFIG_FILE);

  config[`profile ${profileName}`] = profileConfig;

  await atomicWriteIniFile(AWS_CONFIG_FILE, config);
};

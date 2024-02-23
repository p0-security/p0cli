/** Copyright © 2024 P0 Security 

This file is part of @p0security/p0cli

@p0security/p0cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/p0cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/p0cli. If not, see <https://www.gnu.org/licenses/>.
**/

export const stsResponse = `<AssumeRoleWithSAMLResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
<AssumeRoleWithSAMLResult>
  <Audience>https://signin.aws.amazon.com/saml</Audience>
  <AssumedRoleUser>
    <AssumedRoleId>ABCDEFGHIJLMNOPQRST:test-user@test.com</AssumedRoleId>
    <Arn>arn:aws:sts::1:assumed-role/Role1/test-user@test.com</Arn>
  </AssumedRoleUser>
  <Credentials>
    <AccessKeyId>test-access-key</AccessKeyId>
    <SecretAccessKey>secret-access-key</SecretAccessKey>
    <SessionToken>session-token</SessionToken>
    <Expiration>2024-02-22T00:18:21Z</Expiration>
  </Credentials>
  <Subject>test-user@test.com</Subject>
  <NameQualifier>abcdefghijklmnop</NameQualifier>
  <SourceIdentity>test-user@test.com</SourceIdentity>
  <PackedPolicySize>2</PackedPolicySize>
  <SubjectType>unspecified</SubjectType>
  <Issuer>http://www.okta.com/abc</Issuer>
</AssumeRoleWithSAMLResult>
<ResponseMetadata>
  <RequestId>f5b94ad4-f322-4d7b-b568-84f2ec184cd7</RequestId>
</ResponseMetadata>
</AssumeRoleWithSAMLResponse>`;

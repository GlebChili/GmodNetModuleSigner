# GmodNetModuleSigner
Code signing utility for [GmodDotNet](https://github.com/GlebChili/GmodDotNet) powered by [NSec](https://nsec.rocks/) and [libsodium](https://libsodium.org).

## About
GmodNetModuleSigner (or just `gms` for short) is command line tool for code signing of Garry's Mod .NET modules. `gms` signs code with [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) digital signature algorithm based on [Twisted Edwards curves cryptography](https://en.wikipedia.org/wiki/EdDSA).

In general, `gms` creates a module signature by private key from module's SHA-512 checksum and version. Resulting signature can be verified by public key to ensure that module was compiled by original author and wasn't modified.

## Usage
1. Get the latest `gms` build from the [releases page](https://github.com/GlebChili/GmodNetModuleSigner/releases).

2. If you are using Linux or Mac Os, ensure that `gms` executable has execution privileges (by running `chmod +x gms`).

3. If you don't have a public-private key pair, generate one by running `gms` with `--generate-key` flag:
```shell
$ ./gms --generate-key
```
`gms` will write a key pair to `private.modulekey` fail, which is just a JSON document of form
```json
{
  "PrivateKey": "FE958AACDE44A0F90AE2D8F1595EB61DA060A5E09D9D5EB72DA86CD5801AE420",
  "PublicKey": "3E94D3C8823B20DF9FF63DC0D82DC8C1201ACF72F065167553C12A54E1262188"
}
```
It is a good practice to have an individual private key for each project you develop. __NEVER__ publish your `*.modulekey` file with `PrivateKey` field in it. Keep this pair secret.

4. Let's say you want to sign a `SimpleModule.dll` module with `gms`. Then you should run `gms` as following:
```shell
$ ./gms --sign=[full_or_relative_path_to_SimpleModule.dll] --key=[path_to_your_pruvate_public_key_pair_file] --version=[string_version_of_your_module]
```
Version can be any string, but it is an good idea for it to be of the form `X.Y.Z`, since GmodDotNet works only with versions of such format. `gms` will generate a `signature.modulekey` JSON file of the following form:
```json
{
  "Version": "1.2.0",
  "Signature": "F00200AF95CFED2CD5FD0F2959FB352BEF22609E2C24F76474B24A56627CEFDEFC4D8ACCF8B76F7B326357D428575EB02DF321D9694056AD64A443E30B66C400"
}
```
This file does not contain any secret data and designed to be distributed publicly.

5. Rename `signature.modulesign` to `[your_module_name].modulesign` (like `SimpleModule.modulesign`).

6. Copy `private.modulekey`, rename it to `[your_module_name].modulekey`, and __DELETE__ `PrivateKey` field from it. `*.modulekey` files without `PrivateKey` field are safe to publish.

7. Place `[your_module_name].modulesign` and `[your_module_name].modulekey` with your module distribution. GmodDotNet will use this files to verify that client has valid version of module.

8. You can verify signatures with `gms`:
```shell
$ ./gms --verify=[path_to_file_to_verify] --key=[path_to_modulekey_file] --signature=[path_to_modulesign_file]
```
In case of verification `*modulekey` file can contain only `PublicKey` field.

9. You can always get usage help from `gms` by running
```shell
$ ./gms --help
```

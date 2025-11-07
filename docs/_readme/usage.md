## Usage

```shell
gpg --list-keys | jgpg
```

**Sample Output**

```
{
  "/home/USERNAME/.gnupg/pubring.kbx": [
    {
      "key_type": "rsa3072",
      "created": "2025-08-13",
      "can_sign": true,
      "can_certify": true,
      "can_encrypt": false,
      "can_authenticate": false,
      "expires": "2027-08-13",
      "id": "A6C4C64CCC8E8D4A278660B0A78A721FDBC087D9",
      "fingerprint": null,
      "trust_level": "ultimate",
      "real_name": "testing",
      "email": "testing@local",
      "sub_keys": [
        {
          "key_type": "rsa3072",
          "created": "2025-08-13",
          "can_sign": false,
          "can_certify": false,
          "can_encrypt": true,
          "can_authenticate": false,
          "expires": "2027-08-13"
        }
      ]
    }
  ]
}
```

**Get an array of key names stored in `/etc/apt/trusted.gpg` using `jgpg` and `jq`.**

```shell
apt-key list | cargo run | jq '."/etc/apt/trusted.gpg" | map(.real_name)''
```

**Sample Output**

```
[
  "Launchpad PPA for Ubuntu Git Maintainers",
  "Launchpad PPA for Janek Bevendorff",
  "Launchpad PPA for wereturtle"
]
```

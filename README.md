# acme-ksh v1

  This script is an **Automatic Certificate Management Environment** (ACME) tool
  which can be used to go through all steps required to register ACME accounts,
  obtain, update, revoke SSL certificates and unregister ACME accounts on
  demand using the [Let’s Encrypt](https://letsencrypt.org/docs/) Certificate Authority (CA) servers and
  possibly others following the Let’s Encrypt [API version 1](https://tools.ietf.org/html/draft-ietf-acme-acme-07). It supports the challenge-response
  mechanism [http-01](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-8.3) and is intended to be used for mass deployment and
  maintenance of Let’s Encrypt certificates. It can be even used as a
  supporting library. See [./docs/](./docs/) for more information.

  Note that Let’s Encrypt probably supports this API until the end of 2019, only
  because finally [RFC 8555](https://tools.ietf.org/html/rfc8555) got released
  and the servers have been adjusted to follow it more strictly. So you should
  use acme-ksh v2 from the master branch instead of this version.

## Build acme.ksh

  make

## Latest release

  To just get the latest released version of this script, simply get
  http://iks.cs.ovgu.de/~elkner/acme/acme.ksh - that's all you need.

## Latest source

  The script sources and supplementing material is hosted on Github under 
  https://github.com/jelmd/acme-ksh/.

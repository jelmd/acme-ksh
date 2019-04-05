# acme-ksh

  This script is an **Automatic Certificate Management Environment** (ACME) tool
  which can be used to go through all steps required to register ACME accounts,
  obtain, update, revoke SSL certificates and unregister ACME accounts on
  demand using the [Let’s Encrypt](https://letsencrypt.org/docs/) Certificate Authority (CA) servers and
  possibly others following [RFC 8555](https://tools.ietf.org/html/rfc8555). It supports the challenge-response
  mechanism [http-01](https://tools.ietf.org/html/rfc8555#section-8.3) and is intended to be used for mass deployment and
  maintenance of Let’s Encrypt certificates. It can be even used as a
  supporting library. See [./docs/](./docs/) for more information.

## Build acme.ksh

  make

## Latest release

  To just get the latest released version of this script, simply get
  http://iks.cs.ovgu.de/~elkner/acme/acme.ksh - that's all you need.

## Latest source

  The script sources and supplementing material is hosted on Github under 
  https://github.com/jelmd/acme-ksh/.

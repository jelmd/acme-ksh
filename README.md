# acme-ksh

  This script is an **Automatic Certificate Management Environment** (ACME) tool
  which can be used to go through all steps required to register ACME accounts,
  obtain, update, revoke SSL certificates and unregister ACME accounts on
  demand using the [Let’s Encrypt](https://letsencrypt.org/docs/) Certificate Authority (CA) servers and
  possibly others following [RFC 8555](https://tools.ietf.org/html/rfc8555). It supports the challenge-response
  mechanism [http-01](https://tools.ietf.org/html/rfc8555#section-8.3) and is intended to be used for mass deployment and
  maintenance of Let’s Encrypt certificates. It can be even used as a
  supporting library.

  acme-ksh is a ksh93 script, which just uses openssl, wget or curl, rarely
  egrep and a GNU compatible version of sed, which supports the -i and -r option.
  If you want acme-ksh to answer authorization challenges directly,
  you need a base installation of python 2.7+ or 3.4+ with its standard library
  installed and possibly something like sudo or pfexec to run the embedded
  simple HTTP server on demand on a privileged port (usually 80), too.

  So basically it should run on every POSIX compatible Linux/Unix based or
  derived OS.

  See [./docs/](./docs/) for more information.

  Note that in contrast to other shell based ACME client implementations this
  one uses a real (also ksh93 based) JSON parser for en- and decoding
  ACME messages and thus is probably more robust and efficient.

## Latest source

  The script sources and supplementing material is hosted on Github under
  https://github.com/jelmd/acme-ksh/.

## Build acme.ksh

  make

## Latest release

  To just get the latest released version of this script, simply get
  http://iks.cs.ovgu.de/~elkner/acme/acme.ksh - that's all you need.

## Getting help

  Just run `acme.ksh -h`

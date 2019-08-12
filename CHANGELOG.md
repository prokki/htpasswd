# Changes in Htpasswd

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/) and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

## [0.0] - 2019-08-12

### Added
- First version supports all five available encoding methods
  - `apr1-md5` (default), thanks to [https://github.com/whitehat101](https://github.com/whitehat101/apr1-md5)
  - `bcrypt` and `crypt`
  - `sha1`
  - plain text
- customizable htpasswd file location
  - **`%kernel.project_dir%/.htpasswd`** by default
  - see config variable `htpasswd.path`)
- customizable user roles
  - **`[USER_ROLE]`** by default 
  - overridable by config variable `htpasswd.roles`
  - overridable by extended htpasswd file structure 
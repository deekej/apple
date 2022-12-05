#!/usr/bin/python

# Copyright: (c) 2022, Dee'Kej <devel@deekej.io>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: app.notatize

short_description: Submits given path for macOS notarization on Apple's servers.

description:
  - This module submits given path for notarization of code signed binary / app.
  - It uses the older M(altool) for the notarization submission.

options:
  path:
    description:
      - Path to M(zip) or M(pkg) file that needs to be notarized.
    required: true
    type: path

  username:
    description:
      - Username of Apple developer account to use when running the notarization process.
    required: true
    type: string

  bundle_ID:
    description:
      - String to uniquely identify the notarized file.
    required: true
    type: string

  password:
    description:
      - Password of Apple developer account to use when running the notarization process.
      - Either one of M(password) or M(API_key) / M(API_issuer) has to be specified.
    required: false
    type: string
    default: None

  API_key:
    description:
      - API_key of Apple developer account to use when running the notarization process.
      - Either one of M(password) or M(API_key) / M(API_issuer) has to be specified.
    required: false
    type: string
    default: None

  API_issuer:
    description:
      - ID of issuer.
      - Necessary when using M(API_key) option.
    required: false
    type: string
    default: None

  ASC_provider:
    description:
      - Needed when the Apple developer account is associated with multiple providers.
    required: false
    type: string
    default: None

  chdir:
    description:
      - Directory to change into before starting the notarization.
    required: false
    type: path
    default: None

  altool_binary:
    description:
      - Path to M(altool) binary which should be used for the notarization.
      - Allows overriding the default lookup process for the M(altool) binary.
    required: false
    type: path
    default: None

  xcrun_binary:
    description:
      - Path to M(xcrun) binary, which is used for lookup of the M(altool) binary location.
      - Allows partial overriding of the default lookup process for the M(altool) binary.
    required: false
    type: path
    default: None

  sdk:
    description:
      - SDK version to use when the automatic lookup of the M(altool) binary happens.
    required: false
    type: string
    default: None

  toolchain:
    description:
      - Toolchain to use when the automatic lookup of the M(altool) binary happens.
    required: false
    type: string
    default: None

  nocache:
    description:
      - Disables the usage of cache when doing the lookup of M(altool) binary location.
    required: false
    type: boolean
    default: False

  checksum_algorithm:
    description:
      - Selects the algorithm to use when computing checksum of the submitted file for notarization.
      - The checksum of the submitted file is provided for logging purposes.
    required: false
    type: string
    default: sha256
    aliases:
      - checksum
      - checksum_algo
    choices:
      - md5
      - sha1
      - sha224
      - sha256
      - sha384
      - sha512

author:
    - Dee'Kej (@deekej)
'''

EXAMPLES = r'''
- name: Notarize the previously signed & archived binaries
  app.notarize:
    path:         "signed-binaries-v{{ version }}.zip"
    chdir:        /Users/deekej/build
    username:     "{{ credentials.username }}"
    password:     "{{ credentials.password }}"
    bundle_ID:    "app-name-v{{ version }}"
    checksum:     sha256
  register:       notarization
  no_log:         true
'''

# =====================================================================

import atexit
import gc
import os
import plistlib
import shutil
import subprocess

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback

cmd = None
API_key = None
password = None

# ---------------------------------------------------------------------

def clear_sensitive_data():
    global cmd, API_key, password
    del cmd, API_key, password
    gc.collect()


def parse_plist(xml_string):
    return plistlib.loads(str.encode(xml_string), fmt=plistlib.FMT_XML)


def run_module():
    global cmd, API_key, password

    # Ansible Module arguments initialization:
    module_args = dict(
        path               = dict(type='path', required=True),
        username           = dict(type='raw',  required=True),
        bundle_ID          = dict(type='raw',  required=True),
        password           = dict(type='raw',  required=False, default=None, no_log=True),
        API_key            = dict(type='raw',  required=False, default=None, no_log=True),
        API_issuer         = dict(type='raw',  required=False, default=None),
        ASC_provider       = dict(type='raw',  required=False, default=None),
        chdir              = dict(type='path', required=False, default=None),
        altool_binary      = dict(type='path', required=False, default=None),
        xcrun_binary       = dict(type='path', required=False, default=None),
        sdk                = dict(type='raw',  required=False, default=None),
        toolchain          = dict(type='raw',  required=False, default=None),
        nocache            = dict(type='bool', required=False, default=False),
        checksum_algorithm = dict(type='str',  required=False, default='sha256',
                                  choices=['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'],
                                  aliases=['checksum', 'checksum_algo'])
    )

    # Parsing of Ansible Module arguments:
    module = AnsibleModule(
        argument_spec       = module_args,
        mutually_exclusive  = [
            ('API_key', 'password')
        ],
        required_one_of     = [
            ('API_key', 'password')
        ],
        required_together   = [
            ('API_key', 'API_issuer')
        ],
        supports_check_mode = False
    )

    # Make sure we clear the sensitive data no matter the result:
    atexit.register(clear_sensitive_data)

    username           = module.params['username']
    bundle_ID          = module.params['bundle_ID']
    password           = module.params['password']
    API_key            = module.params['API_key']
    API_issuer         = module.params['API_issuer']
    ASC_provider       = module.params['ASC_provider']
    chdir              = module.params['chdir']
    altool_binary      = module.params['altool_binary']
    xcrun_binary       = module.params['xcrun_binary']
    sdk                = module.params['sdk']
    toolchain          = module.params['toolchain']
    nocache            = module.params['nocache']
    checksum_algorithm = module.params['checksum_algorithm']

    path = os.path.expanduser(module.params['path'])

    if chdir:
        chdir = os.path.expanduser(chdir)

    if altool_binary:
        altool_binary = os.path.expanduser(altool_binary)

    if xcrun_binary:
        xcrun_binary = os.path.expanduser(xcrun_binary)

    # NOTE: We are not updating the changed state at all, because this
    #       module does not apply any changes to its host or its files...
    result = dict(
        changed            = False,
        path               = path,
        username           = username,
        bundle_ID          = bundle_ID,
        password           = '[REDACTED]',
        API_key            = '[REDACTED]',
        API_issuer         = API_issuer,
        ASC_provider       = ASC_provider,
        chdir              = chdir,
        altool_binary      = altool_binary,
        xcrun_binary       = xcrun_binary,
        toolchain          = toolchain,
        sdk                = sdk,
        nocache            = nocache,
        checksum_algorithm = checksum_algorithm
    )

    # -----------------------------------------------------------------

    if chdir:
        try:
            os.chdir(chdir)
        except Exception as ex:
            module.fail_json(msg=str(ex), **result)

    if not os.path.exists(path):
        module.fail_json(msg="path does not exist: %s" % path, **result)

    # -----------------------------------------------------------------

    if not altool_binary:
        if not xcrun_binary:
            xcrun_binary = shutil.which('xcrun')

            if not xcrun_binary:
                module.fail_json(msg="'xcrun' binary not found on the system", **result)

        cmd = [xcrun_binary, '--find', 'altool']

        if sdk:
            cmd.extend(['--sdk', sdk])

        if toolchain:
            cmd.extend(['--toolchain', toolchain])

        if nocache:
            cmd.append('--no-cache')

        try:
            process = subprocess.run(cmd, capture_output=True, check=True,
                                     text=True, encoding='ascii')
        except subprocess.CalledProcessError as ex:
            module.fail_json(msg=str(ex.stderr), **result)
        except Exception as ex:
            module.fail_json(msg=str(ex), **result)

        altool_binary = process.stdout.rstrip()

    # -----------------------------------------------------------------

    cmd = [
        altool_binary,
        '--notarize-app',
        '--output-format', 'xml',
        '--primary-bundle-id', bundle_ID,
        '-f', path,
        '-u', username
    ]

    if password:
        cmd.extend(['-p', password])
    else:
        cmd.extend(['--apiKey', API_key])
        cmd.extend(['--apiIssuer', API_issuer])

    if ASC_provider:
        cmd.extend(['--asc-provider', ASC_provider])

    # -----------------------------------------------------------------

    result['checksum'] = checksum = module.digest_from_file(path, checksum_algorithm)

    if password:
        result['command'] = (' '.join(cmd)).replace(password, '******')
    else:
        result['command'] = (' '.join(cmd)).replace(API_key,  '******')

    # -----------------------------------------------------------------

    try:
        process = subprocess.run(cmd, capture_output=True, check=True,
                                 text=True, encoding='ascii')
    except subprocess.CalledProcessError as ex:
        result['status'] = 'failed'
        result['rc'] = ex.returncode

        response = parse_plist(ex.stdout)

        error_msg = "submitting %s for notarization failed:\n" % path

        for error in response['product-errors']:
            error_msg += "  - %s [code %s]\n" % (error['message'], error['code'])

        module.fail_json(msg=error_msg, **result)
    except Exception as ex:
        module.fail_json(msg=str(ex), **result)

    # -----------------------------------------------------------------

    response = parse_plist(process.stdout)

    result['msg']     = response['success-message']
    result['UUID']    = response['notarization-upload']['RequestUUID']

    result['status']  = 'success'
    result['rc']      = process.returncode

    module.exit_json(**result)

# =====================================================================

def main():
    run_module()


if __name__ == '__main__':
    main()

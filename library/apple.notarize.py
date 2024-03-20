#!/usr/bin/python

# Copyright: (c) 2022, Dee'Kej <devel@deekej.io>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: apple.notarize

short_description: Submits given path for macOS notarization on Apple's servers.

description:
  - This module submits given path for notarization of code signed binary / app.
  - It uses notarytool from Xcode 13

options:
  path:
    description:
      - Path to M(zip) or M(pkg) file that needs to be notarized.
    required: true
    type: path

  keychain_profile:
    description:
      - Name of keychain profile if account's app password is already stored by notarytool
  
  username:
    description:
      - Username of Apple developer account to use when running the notarization process.
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

  notarytool_binary:
    description:
      - Path to M(notarytool) binary which should be used for the notarization.
      - Allows overriding the default lookup process for the M(notarytool) binary.
    required: false
    type: path
    default: None

  xcrun_binary:
    description:
      - Path to M(xcrun) binary, which is used for lookup of the M(notarytool) binary location.
      - Allows partial overriding of the default lookup process for the M(notarytool) binary.
    required: false
    type: path
    default: None

  sdk:
    description:
      - SDK version to use when the automatic lookup of the M(notarytool) binary happens.
    required: false
    type: string
    default: None

  toolchain:
    description:
      - Toolchain to use when the automatic lookup of the M(notarytool) binary happens.
    required: false
    type: string
    default: None

  nocache:
    description:
      - Disables the usage of cache when doing the lookup of M(notarytool) binary location.
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
import json
import plistlib
import shutil
import subprocess

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback

cmd = None
API_key = None
username = None
password = None
keychain_profile = None
# ---------------------------------------------------------------------

def clear_sensitive_data():
    global cmd, API_key, password
    del cmd, API_key, password
    gc.collect()


def parse_plist(xml_string):
    return plistlib.loads(str.encode(xml_string), fmt=plistlib.FMT_XML)


def run_module():
    global cmd, API_key, password, keychain_profile

    # Ansible Module arguments initialization:
    module_args = dict(
        path               = dict(type='path', required=True),
        keychain_profile   = dict(type='raw', required=False),
        username           = dict(type='raw',  required=False),
        password           = dict(type='raw',  required=False, default=None, no_log=True),
        API_key            = dict(type='raw',  required=False, default=None, no_log=True),
        API_issuer         = dict(type='raw',  required=False, default=None),
        ASC_provider       = dict(type='raw',  required=False, default=None),
        chdir              = dict(type='path', required=False, default=None),
        notarytool_binary  = dict(type='path', required=False, default=None),
        xcrun_binary       = dict(type='path', required=False, default=None),
        sdk                = dict(type='raw',  required=False, default=None),
        toolchain          = dict(type='raw',  required=False, default=None),
        nocache            = dict(type='bool', required=False, default=False),
        wait               = dict(type='bool', required=False, default=False),
        checksum_algorithm = dict(type='str',  required=False, default='sha256',
                                  choices=['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'],
                                  aliases=['checksum', 'checksum_algo'])
    )

    # Parsing of Ansible Module arguments:
    module = AnsibleModule(
        argument_spec       = module_args,
        mutually_exclusive  = [
            ('API_key', 'password'),
            ('keychain_profile', 'username')
        ],
        required_one_of     = [
            ('API_key', 'password', 'keychain_profile')
        ],
        required_together   = [
            ('API_key', 'API_issuer'),
            ('username', 'password')
        ],
        supports_check_mode = False
    )

    # Make sure we clear the sensitive data no matter the result:
    atexit.register(clear_sensitive_data)

    keychain_profile   = module.params['keychain_profile']
    username           = module.params['username']
    password           = module.params['password']
    API_key            = module.params['API_key']
    API_issuer         = module.params['API_issuer']
    ASC_provider       = module.params['ASC_provider']
    chdir              = module.params['chdir']
    notarytool_binary  = module.params['notarytool_binary']
    xcrun_binary       = module.params['xcrun_binary']
    sdk                = module.params['sdk']
    toolchain          = module.params['toolchain']
    nocache            = module.params['nocache']
    checksum_algorithm = module.params['checksum_algorithm']
    wait               = module.params['wait']

    path = os.path.expanduser(module.params['path'])

    if chdir:
        chdir = os.path.expanduser(chdir)

    if notarytool_binary:
        notarytool_binary = os.path.expanduser(notarytool_binary)

    if xcrun_binary:
        xcrun_binary = os.path.expanduser(xcrun_binary)

    # NOTE: We are not updating the changed state at all, because this
    #       module does not apply any changes to its host or its files...
    result = dict(
        changed            = False,
        path               = path,
        keychain_profile   = keychain_profile,
        username           = username,
        password           = '[REDACTED]',
        API_key            = '[REDACTED]',
        API_issuer         = API_issuer,
        ASC_provider       = ASC_provider,
        chdir              = chdir,
        notarytool_binary  = notarytool_binary,
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

    if not notarytool_binary:
        if not xcrun_binary:
            xcrun_binary = shutil.which('xcrun')

            if not xcrun_binary:
                module.fail_json(msg="'xcrun' binary not found on the system", **result)

        cmd = [xcrun_binary, '--find', 'notarytool']

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

        notarytool_binary = process.stdout.rstrip()

    # -----------------------------------------------------------------

    cmd = [
        notarytool_binary,
        'submit',
        path,
        '-f', 'json'
    ]

    if wait:
        cmd.append('--wait')

    if username:
        cmd.extend(['-u', username, '-p', password])
    elif keychain_profile:
        cmd.extend(['--keychain-profile', keychain_profile])
    else:
        cmd.extend(['--apiKey', API_key])
        cmd.extend(['--apiIssuer', API_issuer])

    if ASC_provider:
        cmd.extend(['--asc-provider', ASC_provider])

    # -----------------------------------------------------------------

    result['checksum'] = checksum = module.digest_from_file(path, checksum_algorithm)

    if password:
        result['command'] = (' '.join(cmd)).replace(password, '******')
    elif API_key:
        result['command'] = (' '.join(cmd)).replace(API_key,  '******')
    else:
        result["command"] = (' '.join(cmd))

    # -----------------------------------------------------------------

    try:
        process = subprocess.run(cmd, capture_output=True, check=True,
                                 text=True, encoding='utf-8')
        process_output = json.loads(process.stdout)
    except subprocess.CalledProcessError as ex:
        # TODO: Need to check what the failure actually looks like, this might fail
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

    if process_output.get('status') == 'Accepted':
        result['message'] = process_output.get('message')
        result['id'] = process_output.get('id')
        result['status']  = 'success'
        module.exit_json(**result)
    else:
        submission_id = process_output.get('id')
        log_failure_cmd = [notarytool_binary, 'log','--keychain-profile',keychain_profile, submission_id]
        failure_check = subprocess.run(log_failure_cmd, capture_output=True, check=True,
                                        text=True, encoding='ascii')
        error_msg = failure_check.stdout.get('issues')
        module.fail_json(msg=error_msg, **result)


# =====================================================================

def main():
    run_module()


if __name__ == '__main__':
    main()

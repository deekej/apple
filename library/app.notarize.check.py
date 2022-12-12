#!/usr/bin/python

# Copyright: (c) 2022, Dee'Kej <devel@deekej.io>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: app.notatize.check

short_description: Submits given path for macOS notarization on Apple's servers.

description:

options:
  UUID:
    description:
      - UUID string (version 4) response which has been returned from Apple's servers during previous submission for notarization.
      - This string can be also obtained from the return values of app.notarize module.
    required: true
    type: string

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

author:
    - Dee'Kej (@deekej)
'''

EXAMPLES = r'''
- name: Notarize the previously signed & archived binaries
  app.notarize.check:
    UUID:         "{{ notarization.UUID }}"
    username:     "{{ credentials.username }}"
    password:     "{{ credentials.password }}"
  register:       check
  until:          check.response == 'Package Approved'
  failed_when:    check.status not in ['success', 'in progress']
  retries:        60
  delay:          60
  no_log:         true
'''

# =====================================================================

import atexit
import gc
import os
import plistlib
import re
import shutil
import subprocess

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback

cmd = None
API_key = None
password = None
UUID_regex = r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'

# ---------------------------------------------------------------------

def clear_sensitive_data():
    global cmd, API_key, password
    del cmd, API_key, password
    gc.collect()


def parse_plist(xml_string):
    return plistlib.loads(str.encode(xml_string), fmt=plistlib.FMT_XML)


def run_module():
    global cmd, API_key, password, UUID_regex

    # Ansible Module arguments initialization:
    module_args = dict(
        UUID               = dict(type='str',  required=True),
        username           = dict(type='raw',  required=True),
        password           = dict(type='raw',  required=False, default=None, no_log=True),
        API_key            = dict(type='raw',  required=False, default=None, no_log=True),
        API_issuer         = dict(type='raw',  required=False, default=None),
        altool_binary      = dict(type='path', required=False, default=None),
        xcrun_binary       = dict(type='path', required=False, default=None),
        sdk                = dict(type='raw',  required=False, default=None),
        toolchain          = dict(type='raw',  required=False, default=None),
        nocache            = dict(type='bool', required=False, default=False)
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

    UUID               = module.params['UUID']
    username           = module.params['username']
    password           = module.params['password']
    API_key            = module.params['API_key']
    API_issuer         = module.params['API_issuer']
    altool_binary      = module.params['altool_binary']
    xcrun_binary       = module.params['xcrun_binary']
    sdk                = module.params['sdk']
    toolchain          = module.params['toolchain']
    nocache            = module.params['nocache']

    if altool_binary:
        altool_binary = os.path.expanduser(altool_binary)

    if xcrun_binary:
        xcrun_binary = os.path.expanduser(xcrun_binary)

    # NOTE: We are not updating the changed state at all, because this
    #       module does not apply any changes to its host or its files...
    result = dict(
        changed            = False,
        UUID               = UUID,
        username           = username,
        password           = '[REDACTED]',
        API_key            = '[REDACTED]',
        API_issuer         = API_issuer,
        altool_binary      = altool_binary,
        xcrun_binary       = xcrun_binary,
        toolchain          = toolchain,
        sdk                = sdk,
        nocache            = nocache
    )

    # -----------------------------------------------------------------

    # We need the Version 4 UUID string:
    if re.match(UUID_regex, UUID) is None:
        module.fail_json(msg="invalid UUID string: %s" % UUID, **result)

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
        '--notarization-info', UUID,
        '--output-format', 'xml',
        '-u', username
    ]

    if password:
        cmd.extend(['-p', password])
    else:
        cmd.extend(['--apiKey', API_key])
        cmd.extend(['--apiIssuer', API_issuer])

    # -----------------------------------------------------------------

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
        error_msg = "obtaining notarization info for %s [UUID] failed:\n" % UUID

        for error in response['product-errors']:
            error_msg += "  - %s [code %s]\n" % (error['message'], error['code'])

        module.fail_json(msg=error_msg, **result)
    except Exception as ex:
        module.fail_json(msg=str(ex), **result)

    # -----------------------------------------------------------------

    response = parse_plist(process.stdout)

    notarize_info         = response['notarization-info']
    result['msg']         = response['success-message']

    result['logfile_URL'] = notarize_info['LogFileURL']
    result['timestamp']   = notarize_info['Date'].isoformat()
    result['checksum']    = notarize_info['Hash']
    result['response']    = notarize_info['Status Message']
    result['status']      = notarize_info['Status']

    result['rc']          = process.returncode

    module.exit_json(**result)

# =====================================================================

def main():
    run_module()


if __name__ == '__main__':
    main()

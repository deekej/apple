#!/usr/bin/python

# Copyright: (c) 2022, Dee'Kej <devel@deekej.io>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: apple.unlock_keychain

short_description: Unlocks security keychain on macOS machine

version_added: "1.0.0"

description: This module is used to unlock security keychain on macOS
             machine, so follow up macOS tasks can run...

options:
    password:
        description: Password for unlocking the macOS security keychain.
        required: true
        type: raw

    keychain:
        description:
          - Path to a non-default security keychain to unlock.
          - Default: None (system default is used)
        required: false
        type: str

author:
    - Dee'Kej (@deekej)
'''

EXAMPLES = r'''
- name: Unlock non-default macOS security keychain
  unlock.keychain:
    password:     "{{ keychain_password }}"
    keychain:     /Users/deekej/Library/Keychains/custom-keychain.db
  no_log:         true
'''

# =====================================================================

import atexit
import gc
import subprocess

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback

cmd = None
password = None

# ---------------------------------------------------------------------

def clear_sensitive_data():
    global cmd, password
    del cmd, password
    gc.collect()

def run_module():
    global cmd, password

    # Ansible Module arguments initialization:
    module_args = dict(
        password = dict(type='raw', required=True, no_log=True),
        keychain = dict(type='str', required=False, default=None)
    )

    # Parsing of Ansible Module arguments:
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False
    )

    # Make sure we clear the sensitive data no matter the result:
    atexit.register(clear_sensitive_data)

    password = module.params['password']
    keychain = module.params['keychain']

    result = dict(
        changed  = False,
        password = '[REDACTED]',
        keychain = keychain
    )

    # -----------------------------------------------------------------

    cmd = [
        'security',
        'unlock-keychain',
        '-p',
        password
    ]

    if keychain:
        cmd.append(keychain)

    # Run the actual unlocking of keychain:
    try:
        subprocess.run(cmd, capture_output=True, check=True, text=True, encoding='ascii')
    except subprocess.CalledProcessError as ex:
        if ex.returncode != 51:
            module.fail_json(msg=ex.stderr.rstrip(), **result)

        if keychain:
            error_msg = "incorrect passphrase for keychain: %s" % keychain
        else:
            error_msg = 'incorrect passphrase for default keychain'

        module.fail_json(msg=error_msg, **result)
    except Exception as ex:
        module.fail_json(msg=str(ex), **result)

    result['changed'] = True
    module.exit_json(**result)

# =====================================================================

def main():
    run_module()


if __name__ == '__main__':
    main()
